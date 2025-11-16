# 🔍 Wireshark Packet Capture Demo Guide

## Overview
This guide demonstrates how to capture and analyze SecureChat network traffic using Wireshark/tcpdump to verify the encryption and security properties of the system.

## Quick Capture Method

### Option 1: Automated Script
```bash
# Run the automated capture script
sudo ./scripts/capture_demo.sh
```

Then in separate terminals:
1. Start server: `python3 app/server.py`
2. Start client: `python3 app/client.py`
3. Perform chat session
4. Stop capture with Ctrl+C

### Option 2: Manual Capture
```bash
# Terminal 1: Start packet capture
sudo tcpdump -i lo -w securechat_demo.pcap port 5555

# Terminal 2: Start the server
python3 app/server.py

# Terminal 3: Start the client
python3 app/client.py

# After demo, stop tcpdump with Ctrl+C
```

## What to Demonstrate

### 1. Certificate Exchange (Phase 1)
- **Expected**: Server and client exchange X.509 certificates
- **Visible**: `HELLO` and `HELLO_RESPONSE` messages with certificate data
- **Verification**: Certificates are in plaintext during initial handshake

### 2. Diffie-Hellman Key Exchange (Phase 2)
- **Expected**: DH public keys exchanged
- **Visible**: Large integers (2048-bit DH public keys)
- **Verification**: No shared secret visible (only public keys transmitted)

### 3. Authentication (Phase 3)
- **Expected**: Username transmitted, signature verification
- **Visible**: Username in `AUTH_REQUEST`, encrypted response
- **Verification**: Password never transmitted (only used for database lookup)

### 4. Session Key Establishment (Phase 4)
- **Expected**: Second DH exchange for session keys
- **Visible**: New DH public keys
- **Verification**: Session keys derived locally, never transmitted

### 5. Encrypted Chat (Phase 5)
- **Expected**: All messages encrypted with AES-128
- **Visible**: Base64-encoded ciphertext in `CHAT_MSG` messages
- **Verification**: Original plaintext NOT visible in packet capture

### 6. Non-Repudiation (Phase 6)
- **Expected**: Signed receipts and transcript
- **Visible**: Digital signatures in `CHAT_RECEIPT` messages
- **Verification**: Signatures can be verified offline using certificates

## Wireshark Analysis

### Open the Capture
```bash
wireshark securechat_demo.pcap
```

### Apply Filters

#### View All SecureChat Traffic
```
tcp.port == 5555
```

#### View Only Data Packets
```
tcp.port == 5555 && tcp.len > 0
```

#### View Client → Server Messages
```
tcp.port == 5555 && tcp.srcport != 5555
```

#### View Server → Client Messages
```
tcp.port == 5555 && tcp.dstport != 5555
```

### What to Look For

1. **TCP 3-Way Handshake**
   - SYN → SYN-ACK → ACK
   - Establishes connection before SecureChat protocol begins

2. **Certificate Exchange**
   - Look for PEM-encoded certificates (BEGIN CERTIFICATE)
   - Should be visible in plaintext

3. **DH Public Keys**
   - Large base64-encoded strings
   - Transmitted in plaintext (public keys are not secret)

4. **Encrypted Messages**
   - `CHAT_MSG` packets contain encrypted payload
   - Plaintext message content should NOT be visible
   - Only base64-encoded ciphertext visible

5. **Digital Signatures**
   - `CHAT_RECEIPT` messages contain RSA signatures
   - Base64-encoded signature data

## Command-Line Analysis

### View Packet Summary
```bash
tcpdump -r securechat_demo.pcap -n | head -50
```

### Extract Readable Text
```bash
tcpdump -r securechat_demo.pcap -A | grep -E "HELLO|DH_EXCHANGE|AUTH|CHAT"
```

### Count Protocol Messages
```bash
tcpdump -r securechat_demo.pcap -A | grep -c "CHAT_MSG"
tcpdump -r securechat_demo.pcap -A | grep -c "CHAT_RECEIPT"
```

### View Encrypted Payloads
```bash
tcpdump -r securechat_demo.pcap -A | grep -A 3 "encrypted_message"
```

## Expected Results

### ✅ Security Properties Verified

1. **Confidentiality**
   - Message content encrypted (only ciphertext visible)
   - AES-128 encryption applied to all chat messages
   - Keys never transmitted (derived via DH)

2. **Integrity**
   - Digital signatures on all messages
   - Tampering would invalidate signatures
   - Hash verification in receipts

3. **Authenticity**
   - X.509 certificates validate identities
   - Certificate chain verification
   - Username authentication via database

4. **Non-Repudiation**
   - All messages signed by sender
   - Receipts signed by receiver
   - Transcript provides proof of communication

5. **Replay Protection**
   - Timestamps on all messages
   - Session-based encryption keys
   - Old messages cannot be replayed

## Analysis Report Template

```
WIRESHARK CAPTURE ANALYSIS REPORT
==================================

Capture File: securechat_demo.pcap
Date: [Date of capture]
Duration: [Length of capture]

TRAFFIC SUMMARY:
- Total Packets: [Count from Wireshark]
- TCP Streams: [Number of complete sessions]
- Data Transferred: [Total bytes]

PROTOCOL PHASES OBSERVED:
☑ Phase 1: Certificate Exchange - [Packet numbers]
☑ Phase 2: DH Key Exchange - [Packet numbers]
☑ Phase 3: Authentication - [Packet numbers]
☑ Phase 4: Session DH Exchange - [Packet numbers]
☑ Phase 5: Encrypted Chat - [Packet numbers]
☑ Phase 6: Session Closure - [Packet numbers]

ENCRYPTION VERIFICATION:
- Plaintext messages visible: NO ✓
- Encrypted ciphertext visible: YES ✓
- AES encryption applied: YES ✓
- Key material transmitted: NO ✓

AUTHENTICATION VERIFICATION:
- Certificates exchanged: YES ✓
- Digital signatures present: YES ✓
- Password transmitted: NO ✓
- Valid signature format: YES ✓

CONCLUSION:
All security properties (CIANR) verified through packet analysis.
No sensitive data exposed in network traffic.
System successfully implements secure communication.
```

## Troubleshooting

### tcpdump: Permission Denied
```bash
# Solution: Run with sudo
sudo tcpdump -i lo -w securechat_demo.pcap port 5555
```

### No Packets Captured
```bash
# Check if server is running on correct port
netstat -tuln | grep 5555

# Verify interface
ip addr show lo
```

### Wireshark Not Showing Data
```bash
# Check file was created
ls -lh securechat_demo.pcap

# Verify capture has data
tcpdump -r securechat_demo.pcap | wc -l
```

## Submission Checklist

- [ ] `.pcap` file created and tested
- [ ] Wireshark can open the file
- [ ] At least one complete chat session captured
- [ ] All 6 protocol phases visible in capture
- [ ] Encrypted messages confirmed (plaintext not visible)
- [ ] Analysis report written
- [ ] Screenshots of Wireshark showing encrypted traffic (optional)

---

**Note**: For your assignment submission, include:
1. The `.pcap` file itself
2. Screenshots from Wireshark showing key protocol phases
3. Brief analysis explaining what the capture demonstrates
