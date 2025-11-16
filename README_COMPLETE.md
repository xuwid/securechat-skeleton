# 🔒 Secure Chat System - Assignment #2

**Course:** Information Security (CS-3002, Fall 2025)  
**Institution:** FAST-NUCES  
**Repository:** https://github.com/maadilrehman/securechat-skeleton

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Protocol Phases](#protocol-phases)
- [Testing](#testing)
- [Security Features](#security-features)
- [Project Structure](#project-structure)
- [Troubleshooting](#troubleshooting)

## 🎯 Overview

A **console-based Secure Chat System** demonstrating practical cryptography by combining:
- **AES-128** (block cipher for confidentiality)
- **RSA with X.509 certificates** (authentication and digital signatures)
- **Diffie-Hellman** (key agreement)
- **SHA-256** (integrity)

This implementation achieves **CIANR**: **C**onfidentiality, **I**ntegrity, **A**uthenticity, and **N**on-**R**epudiation.

### Threat Model
- **Adversary**: Passive eavesdropper, active MitM (replay/modify/inject), untrusted client
- **Goals**: No plaintext leakage, peer authenticity, tamper detection, replay prevention, non-repudiation via signed transcripts

## ✨ Features

### Core Security
- ✅ **PKI Infrastructure**: Self-signed CA, server & client certificates
- ✅ **Mutual Authentication**: Certificate validation with expiry and CN checks
- ✅ **Key Agreement**: Diffie-Hellman for ephemeral session keys
- ✅ **Encrypted Communication**: AES-128-ECB with PKCS#7 padding
- ✅ **Message Integrity**: SHA-256 digests with RSA signatures
- ✅ **Replay Protection**: Sequence numbers and timestamps
- ✅ **Non-Repudiation**: Append-only transcripts with signed receipts

### Implementation
- ✅ **Dual-Phase Encryption**: Separate keys for control plane (auth) and data plane (chat)
- ✅ **MySQL Storage**: Salted password hashing (SHA-256)
- ✅ **Constant-Time Comparison**: Timing attack prevention
- ✅ **Graceful Error Handling**: BAD_CERT, SIG_FAIL, REPLAY errors

## 🏗️ Architecture

### Protocol Phases

```
┌─────────┐                                     ┌─────────┐
│ Client  │                                     │ Server  │
└────┬────┘                                     └────┬────┘
     │                                                │
     │  Phase 1: Certificate Exchange                │
     ├──────────────── HELLO ────────────────────────>
     │   (client_cert, nonce)                        │
     <────────────── SERVER_HELLO ────────────────────┤
     │   (server_cert, nonce)                        │
     │   [Mutual Certificate Validation]             │
     │                                                │
     │  Phase 2: Initial DH (Control Plane)          │
     ├──────────── DH_CLIENT ────────────────────────>
     │   (g, p, A)                                   │
     <──────────── DH_SERVER ────────────────────────┤
     │   (B)                                         │
     │   [Derive control_key for auth encryption]    │
     │                                                │
     │  Phase 3: Authentication                      │
     ├──────── ENCRYPTED(register/login) ───────────>
     │   [AES-encrypted with control_key]            │
     <────────── ENCRYPTED(status) ──────────────────┤
     │   [DB: salted SHA-256 storage/verification]   │
     │                                                │
     │  Phase 4: Session DH (Data Plane)             │
     ├──────────── DH_CLIENT ────────────────────────>
     │   (g, p, A)                                   │
     <──────────── DH_SERVER ────────────────────────┤
     │   (B)                                         │
     │   [Derive session_key for chat encryption]    │
     │                                                │
     │  Phase 5: Encrypted Chat                      │
     ├──────────── MSG ──────────────────────────────>
     │   {seqno, ts, ct, sig}                        │
     <──────────── MSG ──────────────────────────────┤
     │   [RSA sig over SHA-256(seqno||ts||ct)]       │
     │   [Replay check, decrypt, verify]             │
     │                                                │
     │  Phase 6: Non-Repudiation                     │
     ├──────────── RECEIPT ──────────────────────────>
     │   {peer, seqs, transcript_hash, sig}          │
     <──────────── RECEIPT ──────────────────────────┤
     │   [Signed SHA-256 of full transcript]         │
     │                                                │
```

### Security Layers

| Layer | Mechanism | Purpose |
|-------|-----------|---------|
| **Authentication** | X.509 Certificates | Verify peer identity |
| **Key Agreement** | Diffie-Hellman | Establish shared secrets |
| **Confidentiality** | AES-128-ECB | Encrypt message content |
| **Integrity** | SHA-256 | Detect tampering |
| **Authenticity** | RSA Signatures | Prove sender identity |
| **Replay Prevention** | Sequence Numbers | Reject old messages |
| **Non-Repudiation** | Signed Transcripts | Provable evidence |

## 🚀 Installation

### Prerequisites
- Python 3.8+
- MySQL 8.0+
- pip

### Quick Setup

```bash
# Clone the repository
git clone https://github.com/maadilrehman/securechat-skeleton.git
cd securechat-skeleton

# Run automated setup
chmod +x setup.sh
./setup.sh

# Or manual setup:
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Certificate Generation

```bash
# Activate virtual environment
source .venv/bin/activate

# Generate Root CA
python scripts/gen_ca.py

# Generate server certificate
python scripts/gen_cert.py --cn "securechat.server" --out certs/server --type server

# Generate client certificate
python scripts/gen_cert.py --cn "securechat.client" --out certs/client --type client

# Verify certificates
openssl x509 -in certs/ca-cert.pem -text -noout
openssl x509 -in certs/server-cert.pem -text -noout
openssl x509 -in certs/client-cert.pem -text -noout
```

### Database Setup

```bash
# Option 1: Using provided script (interactive)
chmod +x scripts/setup_mysql.sh
./scripts/setup_mysql.sh

# Option 2: Manual MySQL commands
mysql -u root -p
CREATE DATABASE securechat CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'scuser'@'localhost' IDENTIFIED BY 'scpass123';
GRANT ALL PRIVILEGES ON securechat.* TO 'scuser'@'localhost';
FLUSH PRIVILEGES;
exit;

# Initialize tables
python -m app.storage.db --init
```

## ⚙️ Configuration

### Environment Variables (.env)

```bash
# Database Configuration
DB_HOST=localhost
DB_PORT=3306
DB_USER=scuser
DB_PASSWORD=scpass123
DB_NAME=securechat

# Server Configuration
SERVER_HOST=127.0.0.1
SERVER_PORT=5555

# Certificate Paths
CA_CERT=certs/ca-cert.pem
SERVER_CERT=certs/server-cert.pem
SERVER_KEY=certs/server-key.pem
CLIENT_CERT=certs/client-cert.pem
CLIENT_KEY=certs/client-key.pem
```

## 💻 Usage

### Starting the Server

```bash
# Terminal 1
source .venv/bin/activate
python -m app.server

# Expected output:
# ╭────────── Server Started ──────────╮
# │ 🔒 Secure Chat Server Running     │
# │ Listening on 127.0.0.1:5555       │
# ╰────────────────────────────────────╯
```

### Starting the Client

```bash
# Terminal 2
source .venv/bin/activate
python -m app.client

# Follow the interactive prompts:
# 1. Certificate exchange
# 2. Choose: Register (1) or Login (2)
# 3. Enter credentials
# 4. Start chatting
# 5. Type /quit to end session
```

### Sample Session

```
Client Terminal:
═══ Phase 1: Certificate Exchange ═══
✓ Sent client hello
✓ Received server hello
✓ Server certificate validated

═══ Phase 2: Initial DH Exchange ═══
✓ Sent DH parameters
✓ Received DH response from server
✓ Control plane key derived

═══ Phase 3: Authentication ═══
Select an option:
1. Register new account
2. Login to existing account
> 1

Email: alice@example.com
Username: alice
Password: ********
✓ Sent registration request
✓ Registration successful

═══ Phase 4: Session Key Establishment ═══
✓ Sent DH parameters
✓ Received DH response from server
✓ Session key established

═══ Phase 5: Encrypted Chat ═══
Chat session started. Type your messages below.
Type '/quit' to end session.

> Hello, this is a secure message!
You: Hello, this is a secure message!
Server: Message received securely!

> /quit

═══ Phase 6: Non-Repudiation ═══
✓ Session receipt sent to server
✓ Transcript saved: transcripts/client_a1b2c3d4_20251116_102745.transcript
✓ Transcript hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

## 🧪 Testing

### Certificate Tests

```bash
# Run certificate validation tests
python tests/test_certificates.py

# Expected output:
# ═══ Test 1: Valid Certificates ═══
# ✓ Server certificate is VALID
# ✓ Client certificate is VALID
#
# ═══ Test 2: Expired Certificate ═══
# ✓ Expired certificate correctly rejected
#
# ═══ Test 3: Self-Signed Certificate ═══
# ✓ Self-signed certificate correctly rejected
#
# ═══ Test 4: CN Mismatch ═══
# ✓ CN mismatch correctly detected
```

### Wireshark Capture

```bash
# Start Wireshark or tcpdump
sudo tcpdump -i lo -w securechat.pcap port 5555

# In another terminal, run server and client
# Then analyze the capture
wireshark securechat.pcap

# Display filter to use:
tcp.port == 5555
```

**Expected**: All payload data should be encrypted (base64-encoded ciphertext), no plaintext credentials visible.

### Tampering Test

Modify `tests/test_tampering.py`:
```python
# Flip a bit in ciphertext
original_ct = chat_msg['ct']
tampered_ct = flip_bit(original_ct)
chat_msg['ct'] = tampered_ct

# Send tampered message
# Expected: SIG_FAIL error
```

### Replay Attack Test

```python
# Save a valid message
saved_msg = chat_msg.copy()

# Send saved_msg again
# Expected: REPLAY error (seqno not strictly increasing)
```

### Non-Repudiation Verification

```bash
# After chat session, verify transcript
python tests/verify_transcript.py transcripts/client_*.transcript

# Expected:
# ✓ All message signatures valid
# ✓ Receipt signature valid
# ✓ Transcript hash matches receipt
```

## 🔒 Security Features

### Confidentiality
- **AES-128-ECB**: All messages encrypted with session key
- **No Plaintext Transit**: Credentials encrypted during auth phase
- **Key Separation**: Different keys for control plane and data plane

### Integrity
- **SHA-256 Digests**: Computed over seqno||timestamp||ciphertext
- **Tamper Detection**: Any modification breaks signature
- **Salted Password Hashing**: SHA-256(salt || password)

### Authenticity
- **X.509 Certificates**: CA-signed certificates for both parties
- **RSA Signatures**: PKCS#1 v1.5 with SHA-256
- **Certificate Validation**: Chain, expiry, and CN checks

### Non-Repudiation
- **Append-Only Transcripts**: Immutable log of all messages
- **Signed Receipts**: RSA signature over transcript hash
- **Offline Verifiable**: Third party can validate entire session

### Anti-Replay
- **Sequence Numbers**: Strictly increasing per session
- **Timestamps**: Unix milliseconds for freshness
- **State Tracking**: Reject seqno ≤ last_seen

## 📁 Project Structure

```
securechat-skeleton/
├── app/
│   ├── client.py                 # Client application
│   ├── server.py                 # Server application
│   ├── crypto/
│   │   ├── aes.py               # AES-128-ECB encryption
│   │   ├── dh.py                # Diffie-Hellman key exchange
│   │   ├── pki.py               # Certificate validation
│   │   └── sign.py              # RSA signing/verification
│   ├── common/
│   │   ├── protocol.py          # Pydantic message models
│   │   └── utils.py             # Utility functions
│   └── storage/
│       ├── db.py                # MySQL database handler
│       └── transcript.py        # Transcript management
├── scripts/
│   ├── gen_ca.py                # Generate Root CA
│   ├── gen_cert.py              # Generate certificates
│   └── setup_mysql.sh           # Database setup script
├── tests/
│   ├── test_certificates.py     # Certificate tests
│   └── manual/
│       └── NOTES.md             # Manual testing notes
├── certs/                       # Certificate storage (gitignored)
├── transcripts/                 # Session transcripts (gitignored)
├── .env                         # Environment configuration (gitignored)
├── .env.example                 # Example configuration
├── .gitignore                   # Git ignore rules
├── requirements.txt             # Python dependencies
├── setup.sh                     # Automated setup script
└── README.md                    # This file
```

## 🐛 Troubleshooting

### Common Issues

#### Certificate Errors
```
Error: BAD_CERT: Certificate expired
Solution: Regenerate certificates with longer validity
```

#### Database Connection Failed
```
Error: Can't connect to MySQL server
Solution: 
1. Check MySQL is running: sudo systemctl status mysql
2. Verify credentials in .env match database user
3. Ensure database exists: mysql -u root -p -e "SHOW DATABASES;"
```

#### Import Errors
```
Error: ModuleNotFoundError: No module named 'app'
Solution: Run from project root: python -m app.server
```

#### Port Already in Use
```
Error: Address already in use
Solution: 
1. Find process: lsof -i :5555
2. Kill it: kill -9 <PID>
3. Or change SERVER_PORT in .env
```

### Debugging

Enable verbose logging:
```bash
# Add to .env
DEBUG=True
LOG_LEVEL=DEBUG
```

Check logs:
```bash
# Server logs
tail -f logs/server.log

# Client logs
tail -f logs/client.log
```

## 📚 References

- [SEED Security Labs - PKI](https://seedsecuritylabs.org/Labs_20.04/Crypto/Crypto_PKI/)
- [RFC 3526 - DH Parameters](https://tools.ietf.org/html/rfc3526)
- [RFC 5280 - X.509 Certificates](https://tools.ietf.org/html/rfc5280)
- [Cryptography Python Library](https://cryptography.io/)

## 👨‍💻 Development

### Commit Guidelines

This project follows semantic commit messages:
```
feat: Add certificate validation
fix: Correct replay detection logic
docs: Update README with usage examples
test: Add tampering test case
```

Minimum 10 meaningful commits required for submission.

### Code Style

- Follow PEP 8
- Type hints encouraged
- Docstrings for all functions
- No secrets in version control

## 📝 License

This project is for educational purposes as part of FAST-NUCES Information Security course.

## 👥 Authors

- **Course Instructor**: [FAST-NUCES Faculty]
- **Student Implementation**: [Your Name] - [Roll Number]

## 🙏 Acknowledgments

- FAST-NUCES Information Security Course
- Python Cryptography Library maintainers
- SEED Security Labs

---

**Note**: This implementation is for educational purposes. For production use, employ battle-tested libraries like TLS/SSL instead of custom application-layer crypto.
