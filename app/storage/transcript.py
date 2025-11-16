"""Append-only transcript + TranscriptHash helpers."""
import hashlib
import os
from typing import List
from datetime import datetime


class Transcript:
    """Manage append-only session transcript for non-repudiation."""
    
    def __init__(self, session_id: str, role: str, output_dir: str = "transcripts"):
        """
        Initialize transcript.
        
        Args:
            session_id: Unique session identifier
            role: "client" or "server"
            output_dir: Directory to store transcript files
        """
        self.session_id = session_id
        self.role = role
        self.output_dir = output_dir
        self.entries = []
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        # Create transcript file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.filename = f"{role}_{session_id}_{timestamp}.transcript"
        self.filepath = os.path.join(output_dir, self.filename)
        
        # Create file with header
        with open(self.filepath, 'w') as f:
            f.write(f"# SecureChat Transcript\n")
            f.write(f"# Session ID: {session_id}\n")
            f.write(f"# Role: {role}\n")
            f.write(f"# Started: {datetime.now().isoformat()}\n")
            f.write(f"# Format: seqno|timestamp|ciphertext|signature|peer_cert_fingerprint\n")
            f.write("="*80 + "\n")
    
    def add_entry(self, seqno: int, timestamp: int, ciphertext: str, 
                  signature: str, peer_cert_fingerprint: str):
        """
        Add entry to transcript (append-only).
        
        Args:
            seqno: Sequence number
            timestamp: Unix timestamp in milliseconds
            ciphertext: Base64 encoded ciphertext
            signature: Base64 encoded signature
            peer_cert_fingerprint: SHA-256 fingerprint of peer's certificate
        """
        entry = f"{seqno}|{timestamp}|{ciphertext}|{signature}|{peer_cert_fingerprint}"
        self.entries.append(entry)
        
        # Append to file immediately (append-only)
        with open(self.filepath, 'a') as f:
            f.write(entry + "\n")
    
    def compute_transcript_hash(self) -> str:
        """
        Compute SHA-256 hash of all transcript entries.
        
        Returns:
            Hex string of transcript hash
        """
        # Concatenate all entries
        transcript_data = "\n".join(self.entries)
        
        # Compute SHA-256
        return hashlib.sha256(transcript_data.encode()).hexdigest()
    
    def get_entry_count(self) -> int:
        """Get number of entries in transcript."""
        return len(self.entries)
    
    def get_first_seq(self) -> int:
        """Get first sequence number."""
        if not self.entries:
            return 0
        return int(self.entries[0].split('|')[0])
    
    def get_last_seq(self) -> int:
        """Get last sequence number."""
        if not self.entries:
            return 0
        return int(self.entries[-1].split('|')[0])
    
    def export_transcript(self) -> str:
        """Return full transcript as string."""
        with open(self.filepath, 'r') as f:
            return f.read()
    
    def finalize(self, receipt_data: str = None):
        """
        Finalize transcript and optionally append receipt.
        
        Args:
            receipt_data: JSON string of session receipt (optional)
        """
        with open(self.filepath, 'a') as f:
            f.write("="*80 + "\n")
            f.write(f"# Session ended: {datetime.now().isoformat()}\n")
            f.write(f"# Total messages: {len(self.entries)}\n")
            f.write(f"# Transcript hash: {self.compute_transcript_hash()}\n")
            
            if receipt_data:
                f.write("\n# Session Receipt:\n")
                f.write(receipt_data + "\n")
        
        print(f"[+] Transcript finalized: {self.filepath}")


def load_transcript(filepath: str) -> List[str]:
    """
    Load transcript from file.
    
    Args:
        filepath: Path to transcript file
        
    Returns:
        List of transcript entries
    """
    entries = []
    
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if line and not line.startswith('#') and not line.startswith('='):
                    entries.append(line)
        return entries
    except FileNotFoundError:
        print(f"[!] Transcript file not found: {filepath}")
        return []
    except Exception as e:
        print(f"[!] Error loading transcript: {e}")
        return []


def verify_transcript_hash(entries: List[str], expected_hash: str) -> bool:
    """
    Verify transcript hash matches expected value.
    
    Args:
        entries: List of transcript entries
        expected_hash: Expected SHA-256 hash (hex)
        
    Returns:
        True if hash matches
    """
    transcript_data = "\n".join(entries)
    computed_hash = hashlib.sha256(transcript_data.encode()).hexdigest()
    
    return computed_hash == expected_hash


def compute_message_digest(seqno: int, timestamp: int, ciphertext: str) -> bytes:
    """
    Compute SHA-256 digest for message signing: SHA-256(seqno || ts || ct).
    
    Args:
        seqno: Sequence number
        timestamp: Unix timestamp in milliseconds
        ciphertext: Base64 encoded ciphertext
        
    Returns:
        SHA-256 digest bytes
    """
    # Concatenate: seqno || timestamp || ciphertext
    message_data = f"{seqno}||{timestamp}||{ciphertext}".encode()
    
    return hashlib.sha256(message_data).digest()
