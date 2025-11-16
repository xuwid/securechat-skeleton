# 🚀 Quick Start Guide - Secure Chat System

## Prerequisites Check
```bash
# Python version (need 3.8+)
python3 --version

# MySQL installed
mysql --version

# Git installed
git --version
```

## 1. Initial Setup (5 minutes)

```bash
# Navigate to project
cd /home/kali/Documents/INFOSEC2/securechat-skeleton

# Activate virtual environment (already created)
source .venv/bin/activate

# Verify installation
python tests/test_crypto.py
python tests/test_certificates.py
```

**Expected**: All tests should pass ✅

## 2. Database Setup (2 minutes)

### Option A: Automated (Recommended)
```bash
# Run the setup script
chmod +x scripts/setup_mysql.sh
./scripts/setup_mysql.sh

# When prompted, enter your MySQL root password
# Database 'securechat' will be created automatically
```

### Option B: Manual
```bash
# Login to MySQL
mysql -u root -p

# Run these commands:
CREATE DATABASE securechat CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'scuser'@'localhost' IDENTIFIED BY 'scpass123';
GRANT ALL PRIVILEGES ON securechat.* TO 'scuser'@'localhost';
FLUSH PRIVILEGES;
exit;

# Initialize tables
python -m app.storage.db --init
```

**Expected Output**:
```
[+] Database tables initialized successfully
```

## 3. Verify Configuration

```bash
# Check .env file
cat .env

# Should contain:
# DB_HOST=localhost
# DB_USER=scuser
# DB_PASSWORD=scpass123
# DB_NAME=securechat
# SERVER_HOST=127.0.0.1
# SERVER_PORT=5555
```

## 4. Verify Certificates

```bash
# List certificates
ls -la certs/

# Should see:
# ca-cert.pem, ca-key.pem
# server-cert.pem, server-key.pem
# client-cert.pem, client-key.pem

# Inspect server certificate
openssl x509 -in certs/server-cert.pem -text -noout | head -20
```

## 5. Run the System

### Terminal 1 - Start Server
```bash
cd /home/kali/Documents/INFOSEC2/securechat-skeleton
source .venv/bin/activate
python -m app.server
```

**Expected Output**:
```
╭────────── Server Started ──────────╮
│ 🔒 Secure Chat Server Running     │
│ Listening on 127.0.0.1:5555       │
╰────────────────────────────────────╯

Waiting for client connection...
```

### Terminal 2 - Start Client
```bash
cd /home/kali/Documents/INFOSEC2/securechat-skeleton
source .venv/bin/activate
python -m app.client
```

**Expected Flow**:
```
╭────────── SecureChat ──────────╮
│ 🔒 Secure Chat Client         │
│ Connecting to server...       │
╰───────────────────────────────╯

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
>
```

## 6. Test Registration & Login

### First Time User - Registration
```
> 1  (Choose Register)
Email: alice@example.com
Username: alice
Password: ********
✓ Registration successful
```

### Returning User - Login
```
> 2  (Choose Login)
Email: alice@example.com
Password: ********
✓ Login successful
```

## 7. Send Secure Messages

```
═══ Phase 5: Encrypted Chat ═══
Chat session started. Type your messages below.
Type '/quit' to end session.

> Hello from client!
You: Hello from client!

# Server will respond...
Server: Hello from server!

# Continue chatting...
> This message is encrypted end-to-end
You: This message is encrypted end-to-end

# To exit:
> /quit
```

## 8. Verify Non-Repudiation

After chat session ends, verify the transcript:

```bash
# Find transcript files
ls transcripts/

# Example: client_a1b2c3d4_20251116_103045.transcript
#          server_a1b2c3d4_20251116_103045.transcript

# Verify transcript
python tests/verify_transcript.py transcripts/client_*.transcript

# Expected Output:
# ✓ All message signatures valid
# ✓ Receipt signature valid
# ✓ Transcript hash matches receipt
```

## 9. Capture Traffic (Optional - for Testing Evidence)

### Using tcpdump:
```bash
# Terminal 1
sudo tcpdump -i lo -w securechat.pcap port 5555

# Terminal 2 - Run server
# Terminal 3 - Run client
# After session, stop tcpdump (Ctrl+C)

# Analyze with Wireshark
wireshark securechat.pcap
```

**Filter**: `tcp.port == 5555`

**Expected**: All payloads are base64-encoded ciphertext, no plaintext visible.

## 10. Common Issues & Solutions

### Issue: "Can't connect to MySQL"
```bash
# Solution: Start MySQL service
sudo systemctl start mysql
sudo systemctl status mysql
```

### Issue: "Port 5555 already in use"
```bash
# Solution 1: Find and kill process
lsof -i :5555
kill -9 <PID>

# Solution 2: Change port in .env
SERVER_PORT=5556
```

### Issue: "ModuleNotFoundError"
```bash
# Solution: Ensure virtual environment is activated
source .venv/bin/activate
pip install -r requirements.txt
```

### Issue: "Certificate validation failed"
```bash
# Solution: Regenerate certificates
rm certs/*.pem
python scripts/gen_ca.py
python scripts/gen_cert.py --cn "securechat.server" --out certs/server --type server
python scripts/gen_cert.py --cn "securechat.client" --out certs/client --type client
```

## 11. Testing Checklist

Run each test to verify implementation:

```bash
# ✅ Crypto modules
python tests/test_crypto.py

# ✅ Certificate validation
python tests/test_certificates.py

# ✅ End-to-end test (manual)
# Terminal 1: python -m app.server
# Terminal 2: python -m app.client
# Register, login, chat, verify transcript

# ✅ Verify transcript
python tests/verify_transcript.py transcripts/client_*.transcript
```

## 12. Demonstration Checklist

For TA/Instructor demonstration:

- [ ] Show certificate generation
- [ ] Show certificate inspection (openssl)
- [ ] Show database schema (MySQL)
- [ ] Run test_crypto.py
- [ ] Run test_certificates.py
- [ ] Start server
- [ ] Start client (register new user)
- [ ] Send encrypted messages
- [ ] Exit gracefully
- [ ] Verify transcript with signature
- [ ] Show Wireshark capture (if requested)
- [ ] Show invalid certificate rejection (test_certificates.py)
- [ ] Show replay protection (sequence numbers in code)

## 13. Project Structure Reference

```
securechat-skeleton/
├── app/
│   ├── server.py          # Run with: python -m app.server
│   ├── client.py          # Run with: python -m app.client
│   ├── crypto/            # AES, DH, RSA, PKI modules
│   ├── common/            # Protocol messages, utilities
│   └── storage/           # Database, transcripts
├── scripts/
│   ├── gen_ca.py          # Generate Root CA
│   ├── gen_cert.py        # Generate certificates
│   └── setup_mysql.sh     # Database setup
├── tests/
│   ├── test_crypto.py     # Crypto module tests
│   ├── test_certificates.py  # Certificate tests
│   └── verify_transcript.py  # Non-repudiation verification
├── certs/                 # Certificates (gitignored)
├── transcripts/           # Session logs (gitignored)
└── .env                   # Configuration
```

## 14. Next Steps

After successful setup:

1. **Read the documentation**: 
   - `README_COMPLETE.md` - Full system documentation
   - `IMPLEMENTATION_SUMMARY.md` - Implementation details

2. **Prepare evidence**:
   - Run Wireshark capture
   - Take screenshots of tests passing
   - Document the chat session

3. **Prepare submission**:
   - Export database schema: `mysqldump -u scuser -p securechat > schema.sql`
   - Verify git commits: `git log --oneline`
   - Create report document

## 15. Support & Resources

- **Documentation**: See `README_COMPLETE.md`
- **Implementation Details**: See `IMPLEMENTATION_SUMMARY.md`
- **Code Comments**: All modules have inline documentation
- **Test Scripts**: See `tests/` directory

---

## Summary - Three Commands to Run

```bash
# 1. Setup database
./scripts/setup_mysql.sh

# 2. Start server (Terminal 1)
source .venv/bin/activate && python -m app.server

# 3. Start client (Terminal 2)
source .venv/bin/activate && python -m app.client
```

**That's it!** You now have a fully functional secure chat system. 🎉
