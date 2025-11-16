"""Server skeleton — plain TCP; no TLS. See assignment spec."""
import socket
import json
import os
import sys
import secrets
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel

# Import custom modules - support both relative and absolute imports
try:
    from app.crypto.aes import aes_encrypt, aes_decrypt
    from app.crypto.dh import DH_G, DH_P, generate_dh_private_key, compute_dh_public_key, compute_dh_shared_secret, derive_aes_key_from_dh
    from app.crypto.pki import (load_certificate_from_file, load_private_key_from_file, 
                                 validate_certificate_chain, get_certificate_fingerprint, certificate_to_pem, CertificateValidationError)
    from app.crypto.sign import rsa_sign, rsa_verify_from_cert
    from app.common.protocol import (HelloMessage, ServerHelloMessage, RegisterMessage, LoginMessage,
                                     DHClientMessage, DHServerMessage, ChatMessage, SessionReceipt, StatusMessage, EncryptedPayload)
    from app.common.utils import now_ms, b64e, b64d, sha256_hex
    from app.storage.db import Database, compute_salted_hash
    from app.storage.transcript import Transcript, compute_message_digest
except ModuleNotFoundError:
    # Fallback to relative imports when running directly
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    from crypto.aes import aes_encrypt, aes_decrypt
    from crypto.dh import DH_G, DH_P, generate_dh_private_key, compute_dh_public_key, compute_dh_shared_secret, derive_aes_key_from_dh
    from crypto.pki import (load_certificate_from_file, load_private_key_from_file, 
                                 validate_certificate_chain, get_certificate_fingerprint, certificate_to_pem, CertificateValidationError)
    from crypto.sign import rsa_sign, rsa_verify_from_cert
    from common.protocol import (HelloMessage, ServerHelloMessage, RegisterMessage, LoginMessage,
                                     DHClientMessage, DHServerMessage, ChatMessage, SessionReceipt, StatusMessage, EncryptedPayload)
    from common.utils import now_ms, b64e, b64d, sha256_hex
    from storage.db import Database, compute_salted_hash
    from storage.transcript import Transcript, compute_message_digest

# Load environment variables
load_dotenv()

console = Console()


class SecureChatServer:
    """Secure Chat Server implementing the protocol."""
    
    def __init__(self):
        """Initialize server."""
        self.host = os.getenv('SERVER_HOST', '127.0.0.1')
        self.port = int(os.getenv('SERVER_PORT', 5555))
        
        # Load server certificate and key
        server_cert_path = os.getenv('SERVER_CERT', 'certs/server-cert.pem')
        server_key_path = os.getenv('SERVER_KEY', 'certs/server-key.pem')
        ca_cert_path = os.getenv('CA_CERT', 'certs/ca-cert.pem')
        
        try:
            self.server_cert = load_certificate_from_file(server_cert_path)
            self.server_key = load_private_key_from_file(server_key_path)
            self.ca_cert = load_certificate_from_file(ca_cert_path)
            console.print("[green][+] Server certificates loaded successfully[/green]")
        except Exception as e:
            console.print(f"[red][!] Failed to load certificates: {e}[/red]")
            sys.exit(1)
        
        # Database
        self.db = Database()
        
        # Session state
        self.client_socket = None
        self.client_cert = None
        self.session_key = None
        self.authenticated_user = None
        self.seqno = 0
        self.client_seqno = 0
        self.transcript = None
        self.session_id = None
    
    def start(self):
        """Start the server."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.host, self.port))
            server_socket.listen(1)
            
            console.print(Panel.fit(
                f"🔒 Secure Chat Server Running\n"
                f"Listening on {self.host}:{self.port}",
                title="Server Started",
                border_style="green"
            ))
            
            while True:
                try:
                    console.print("\n[cyan]Waiting for client connection...[/cyan]")
                    client_socket, client_address = server_socket.accept()
                    console.print(f"[green]Client connected from {client_address}[/green]")
                    
                    self.client_socket = client_socket
                    self.handle_client()
                    
                except KeyboardInterrupt:
                    console.print("\n[yellow]Server shutting down...[/yellow]")
                    break
                except Exception as e:
                    console.print(f"[red]Error: {e}[/red]")
                finally:
                    if self.client_socket:
                        self.client_socket.close()
                    self.reset_session()
    
    def reset_session(self):
        """Reset session state."""
        self.client_cert = None
        self.session_key = None
        self.authenticated_user = None
        self.seqno = 0
        self.client_seqno = 0
        self.transcript = None
        self.session_id = None
    
    def send_message(self, data: dict):
        """Send JSON message to client."""
        message = json.dumps(data).encode()
        self.client_socket.sendall(len(message).to_bytes(4, 'big'))
        self.client_socket.sendall(message)
    
    def receive_message(self) -> dict:
        """Receive JSON message from client."""
        length_bytes = self.client_socket.recv(4)
        if not length_bytes:
            return None
        
        length = int.from_bytes(length_bytes, 'big')
        data = b''
        while len(data) < length:
            chunk = self.client_socket.recv(min(4096, length - len(data)))
            if not chunk:
                return None
            data += chunk
        
        return json.loads(data.decode())
    
    def handle_client(self):
        """Handle client connection through full protocol."""
        try:
            # Phase 1: Certificate Exchange (Control Plane)
            if not self.handle_hello():
                return
            
            # Phase 2: Initial DH for control plane encryption
            if not self.handle_initial_dh():
                return
            
            # Phase 3: Registration or Login
            if not self.handle_authentication():
                return
            
            # Phase 4: Session Key Establishment (DH for data plane)
            if not self.handle_session_dh():
                return
            
            # Phase 5: Encrypted Chat (Data Plane)
            self.handle_chat()
            
        except Exception as e:
            console.print(f"[red][!] Error handling client: {e}[/red]")
            import traceback
            traceback.print_exc()
        finally:
            # Phase 6: Non-Repudiation (Session Receipt)
            self.handle_session_closure()
    
    def handle_hello(self) -> bool:
        """Handle certificate exchange."""
        console.print("\n[cyan]═══ Phase 1: Certificate Exchange ═══[/cyan]")
        
        # Receive client hello
        msg = self.receive_message()
        if not msg or msg.get('type') != 'hello':
            console.print("[red][!] Expected hello message[/red]")
            return False
        
        hello = HelloMessage(**msg)
        console.print(f"[green]✓ Received client hello[/green]")
        
        # Load and validate client certificate
        try:
            from app.crypto.pki import load_certificate
            self.client_cert = load_certificate(hello.client_cert)
            
            # Validate client certificate
            validate_certificate_chain(self.client_cert, self.ca_cert)
            console.print(f"[green]✓ Client certificate validated[/green]")
            console.print(f"  CN: {self.client_cert.subject.rfc4514_string()}")
            
        except CertificateValidationError as e:
            console.print(f"[red]BAD_CERT: {e}[/red]")
            self.send_message(StatusMessage(type="status", status="BAD_CERT", message=str(e)).dict())
            return False
        
        # Send server hello
        server_hello = ServerHelloMessage(
            server_cert=certificate_to_pem(self.server_cert),
            nonce=b64e(secrets.token_bytes(16))
        )
        self.send_message(server_hello.dict())
        console.print(f"[green]✓ Sent server hello[/green]")
        
        return True
    
    def handle_initial_dh(self) -> bool:
        """Handle initial DH exchange for control plane encryption."""
        console.print("\n[cyan]═══ Phase 2: Initial DH Exchange ═══[/cyan]")
        
        # Receive DH client message
        msg = self.receive_message()
        if not msg or msg.get('type') != 'dh_client':
            return False
        
        dh_client = DHClientMessage(**msg)
        console.print(f"[green]✓ Received DH parameters from client[/green]")
        
        # Generate server DH key pair
        server_private = generate_dh_private_key()
        server_public = compute_dh_public_key(server_private, dh_client.g, dh_client.p)
        
        # Compute shared secret
        shared_secret = compute_dh_shared_secret(dh_client.A, server_private, dh_client.p)
        
        # Derive AES key
        self.control_key = derive_aes_key_from_dh(shared_secret)
        console.print(f"[green]✓ Control plane key derived[/green]")
        
        # Send DH server response
        dh_server = DHServerMessage(B=server_public)
        self.send_message(dh_server.dict())
        console.print(f"[green]✓ Sent DH response[/green]")
        
        return True
    
    def handle_authentication(self) -> bool:
        """Handle registration or login."""
        console.print("\n[cyan]═══ Phase 3: Authentication ═══[/cyan]")
        
        # Receive encrypted payload
        msg = self.receive_message()
        if not msg or msg.get('type') != 'encrypted':
            return False
        
        encrypted_payload = EncryptedPayload(**msg)
        
        # Decrypt payload
        try:
            plaintext = aes_decrypt(b64d(encrypted_payload.ct), self.control_key)
            auth_msg = json.loads(plaintext.decode())
        except Exception as e:
            console.print(f"[red][!] Decryption failed: {e}[/red]")
            return False
        
        # Handle register or login
        if auth_msg.get('type') == 'register':
            return self.handle_registration(auth_msg)
        elif auth_msg.get('type') == 'login':
            return self.handle_login(auth_msg)
        else:
            return False
    
    def handle_registration(self, auth_msg: dict) -> bool:
        """Handle user registration."""
        reg = RegisterMessage(**auth_msg)
        console.print(f"[cyan]Registration request for: {reg.username}[/cyan]")
        
        # Connect to database
        self.db.connect()
        
        # Check if user exists
        if self.db.user_exists(email=reg.email):
            console.print(f"[red]✗ User already exists: {reg.email}[/red]")
            response = StatusMessage(type="status", status="ERROR", message="User already exists")
            encrypted_response = aes_encrypt(json.dumps(response.dict()).encode(), self.control_key)
            self.send_message(EncryptedPayload(ct=b64e(encrypted_response)).dict())
            return False
        
        # Decode salt and password hash
        salt = b64d(reg.salt)
        pwd_hash_provided = reg.pwd  # This is already the hash sent by client
        
        # Store in database
        # Note: Client already computed the hash, we just store it
        try:
            # For registration, we need to store salt and the final hash
            # Client sends: base64(sha256(salt||pwd))
            # We need to decode and store
            pwd_hash = b64d(pwd_hash_provided).hex()
            
            # Manual insertion to control salt
            cursor = self.db.connection.cursor()
            sql = "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)"
            cursor.execute(sql, (reg.email, reg.username, salt, pwd_hash))
            self.db.connection.commit()
            
            console.print(f"[green]✓ User registered: {reg.username}[/green]")
            self.authenticated_user = reg.email
            
            # Send success response
            response = StatusMessage(type="status", status="OK", message="Registration successful")
            encrypted_response = aes_encrypt(json.dumps(response.dict()).encode(), self.control_key)
            self.send_message(EncryptedPayload(ct=b64e(encrypted_response)).dict())
            
            return True
            
        except Exception as e:
            console.print(f"[red]✗ Registration failed: {e}[/red]")
            response = StatusMessage(type="status", status="ERROR", message=str(e))
            encrypted_response = aes_encrypt(json.dumps(response.dict()).encode(), self.control_key)
            self.send_message(EncryptedPayload(ct=b64e(encrypted_response)).dict())
            return False
    
    def handle_login(self, auth_msg: dict) -> bool:
        """Handle user login."""
        login = LoginMessage(**auth_msg)
        console.print(f"[cyan]Login attempt for: {login.email}[/cyan]")
        
        # Connect to database
        self.db.connect()
        
        # Get user salt and stored hash
        cursor = self.db.connection.cursor()
        sql = "SELECT salt, pwd_hash FROM users WHERE email = %s"
        cursor.execute(sql, (login.email,))
        result = cursor.fetchone()
        
        if not result:
            console.print(f"[red]✗ User not found: {login.email}[/red]")
            response = StatusMessage(type="status", status="ERROR", message="Invalid credentials")
            encrypted_response = aes_encrypt(json.dumps(response.dict()).encode(), self.control_key)
            self.send_message(EncryptedPayload(ct=b64e(encrypted_response)).dict())
            return False
        
        salt = result['salt']
        stored_hash = result['pwd_hash']
        
        # Client sends: base64(sha256(salt||pwd))
        # We need to verify
        pwd_hash_provided = b64d(login.pwd).hex()
        
        # Constant-time comparison
        if secrets.compare_digest(pwd_hash_provided, stored_hash):
            console.print(f"[green]✓ Login successful: {login.email}[/green]")
            self.authenticated_user = login.email
            
            response = StatusMessage(type="status", status="OK", message="Login successful")
            encrypted_response = aes_encrypt(json.dumps(response.dict()).encode(), self.control_key)
            self.send_message(EncryptedPayload(ct=b64e(encrypted_response)).dict())
            
            return True
        else:
            console.print(f"[red]✗ Invalid password for: {login.email}[/red]")
            response = StatusMessage(type="status", status="ERROR", message="Invalid credentials")
            encrypted_response = aes_encrypt(json.dumps(response.dict()).encode(), self.control_key)
            self.send_message(EncryptedPayload(ct=b64e(encrypted_response)).dict())
            return False
    
    def handle_session_dh(self) -> bool:
        """Handle session DH exchange for data plane."""
        console.print("\n[cyan]═══ Phase 4: Session Key Establishment ═══[/cyan]")
        
        # Receive DH client message
        msg = self.receive_message()
        if not msg or msg.get('type') != 'dh_client':
            return False
        
        dh_client = DHClientMessage(**msg)
        
        # Generate server DH key pair
        server_private = generate_dh_private_key()
        server_public = compute_dh_public_key(server_private, dh_client.g, dh_client.p)
        
        # Compute shared secret
        shared_secret = compute_dh_shared_secret(dh_client.A, server_private, dh_client.p)
        
        # Derive session AES key
        self.session_key = derive_aes_key_from_dh(shared_secret)
        console.print(f"[green]✓ Session key established[/green]")
        
        # Send DH server response
        dh_server = DHServerMessage(B=server_public)
        self.send_message(dh_server.dict())
        
        # Initialize transcript
        self.session_id = secrets.token_hex(8)
        self.transcript = Transcript(self.session_id, "server")
        
        return True
    
    def handle_chat(self):
        """Handle encrypted chat messages."""
        console.print("\n[cyan]═══ Phase 5: Encrypted Chat ═══[/cyan]")
        console.print("[yellow]Chat session started. Press Ctrl+C to end session.[/yellow]\n")
        
        import threading
        
        # Start receive thread
        receive_thread = threading.Thread(target=self.receive_messages)
        receive_thread.daemon = True
        receive_thread.start()
        
        # Send messages from console
        try:
            while True:
                message = input()
                if message.lower() == '/quit':
                    break
                
                self.send_chat_message(message)
        except KeyboardInterrupt:
            console.print("\n[yellow]Ending chat session...[/yellow]")
    
    def send_chat_message(self, plaintext: str):
        """Send encrypted and signed chat message."""
        self.seqno += 1
        timestamp = now_ms()
        
        # Encrypt message
        ciphertext = aes_encrypt(plaintext.encode(), self.session_key)
        ct_b64 = b64e(ciphertext)
        
        # Compute digest: SHA-256(seqno || ts || ct)
        digest = compute_message_digest(self.seqno, timestamp, ct_b64)
        
        # Sign digest
        signature = rsa_sign(digest, self.server_key)
        sig_b64 = b64e(signature)
        
        # Create and send message
        chat_msg = ChatMessage(
            seqno=self.seqno,
            ts=timestamp,
            ct=ct_b64,
            sig=sig_b64
        )
        self.send_message(chat_msg.dict())
        
        # Log to transcript
        client_fingerprint = get_certificate_fingerprint(self.client_cert)
        self.transcript.add_entry(self.seqno, timestamp, ct_b64, sig_b64, client_fingerprint)
        
        console.print(f"[blue]You: {plaintext}[/blue]")
    
    def receive_messages(self):
        """Receive and verify chat messages."""
        while True:
            try:
                msg = self.receive_message()
                if not msg:
                    break
                
                if msg.get('type') == 'msg':
                    self.handle_chat_message(msg)
                elif msg.get('type') == 'receipt':
                    console.print("\n[green]✓ Received client session receipt[/green]")
                    break
            except Exception as e:
                console.print(f"[red]Error receiving message: {e}[/red]")
                break
    
    def handle_chat_message(self, msg: dict):
        """Handle incoming chat message."""
        chat_msg = ChatMessage(**msg)
        
        # Check sequence number (replay protection)
        if chat_msg.seqno <= self.client_seqno:
            console.print(f"[red]REPLAY: Rejected message with seqno {chat_msg.seqno}[/red]")
            return
        
        self.client_seqno = chat_msg.seqno
        
        # Verify signature
        digest = compute_message_digest(chat_msg.seqno, chat_msg.ts, chat_msg.ct)
        try:
            rsa_verify_from_cert(digest, b64d(chat_msg.sig), self.client_cert)
        except Exception:
            console.print(f"[red]SIG_FAIL: Message signature verification failed[/red]")
            return
        
        # Decrypt message
        try:
            ciphertext = b64d(chat_msg.ct)
            plaintext = aes_decrypt(ciphertext, self.session_key).decode()
        except Exception as e:
            console.print(f"[red]Decryption failed: {e}[/red]")
            return
        
        # Log to transcript
        client_fingerprint = get_certificate_fingerprint(self.client_cert)
        self.transcript.add_entry(chat_msg.seqno, chat_msg.ts, chat_msg.ct, chat_msg.sig, client_fingerprint)
        
        console.print(f"[green]Client: {plaintext}[/green]")
    
    def handle_session_closure(self):
        """Generate and exchange session receipt."""
        if not self.transcript:
            return
        
        console.print("\n[cyan]═══ Phase 6: Non-Repudiation ═══[/cyan]")
        
        # Compute transcript hash
        transcript_hash = self.transcript.compute_transcript_hash()
        
        # Sign transcript hash
        signature = rsa_sign(transcript_hash.encode(), self.server_key)
        sig_b64 = b64e(signature)
        
        # Create session receipt
        receipt = SessionReceipt(
            peer="server",
            first_seq=self.transcript.get_first_seq(),
            last_seq=self.transcript.get_last_seq(),
            transcript_sha256=transcript_hash,
            sig=sig_b64
        )
        
        # Finalize transcript
        self.transcript.finalize(json.dumps(receipt.dict(), indent=2))
        
        # Send receipt to client
        try:
            self.send_message(receipt.dict())
            console.print("[green]✓ Session receipt sent to client[/green]")
        except:
            pass
        
        console.print(f"[green]✓ Transcript saved: {self.transcript.filepath}[/green]")
        console.print(f"[green]✓ Transcript hash: {transcript_hash}[/green]")


def main():
    """Main server entry point."""
    server = SecureChatServer()
    try:
        server.start()
    except KeyboardInterrupt:
        console.print("\n[yellow]Server stopped[/yellow]")
    except Exception as e:
        console.print(f"[red]Fatal error: {e}[/red]")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
