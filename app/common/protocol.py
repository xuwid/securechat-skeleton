"""Pydantic models: hello, server_hello, register, login, dh_client, dh_server, msg, receipt."""
from pydantic import BaseModel
from typing import Optional


class HelloMessage(BaseModel):
    """Client hello message with certificate and nonce."""
    type: str = "hello"
    client_cert: str  # PEM format
    nonce: str  # base64 encoded


class ServerHelloMessage(BaseModel):
    """Server hello response with certificate and nonce."""
    type: str = "server_hello"
    server_cert: str  # PEM format
    nonce: str  # base64 encoded


class RegisterMessage(BaseModel):
    """Registration message (encrypted)."""
    type: str = "register"
    email: str
    username: str
    pwd: str  # base64(sha256(salt||pwd))
    salt: str  # base64 encoded


class LoginMessage(BaseModel):
    """Login message (encrypted)."""
    type: str = "login"
    email: str
    pwd: str  # base64(sha256(salt||pwd))
    nonce: str  # base64 encoded


class DHClientMessage(BaseModel):
    """Diffie-Hellman client parameters."""
    type: str = "dh_client"
    g: int
    p: int
    A: int  # g^a mod p


class DHServerMessage(BaseModel):
    """Diffie-Hellman server response."""
    type: str = "dh_server"
    B: int  # g^b mod p


class ChatMessage(BaseModel):
    """Encrypted chat message with signature."""
    type: str = "msg"
    seqno: int
    ts: int  # timestamp in milliseconds
    ct: str  # base64 encoded ciphertext
    sig: str  # base64 encoded RSA signature


class SessionReceipt(BaseModel):
    """Non-repudiation session receipt."""
    type: str = "receipt"
    peer: str  # "client" or "server"
    first_seq: int
    last_seq: int
    transcript_sha256: str  # hex
    sig: str  # base64 encoded RSA signature


class StatusMessage(BaseModel):
    """Status/error message."""
    type: str = "status"
    status: str  # "OK", "ERROR", "BAD_CERT", "SIG_FAIL", "REPLAY"
    message: Optional[str] = None


class EncryptedPayload(BaseModel):
    """Generic encrypted payload container."""
    type: str = "encrypted"
    ct: str  # base64 encoded ciphertext
