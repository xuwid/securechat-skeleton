#!/usr/bin/env python3
"""
Transcript Verification Script
Verifies message signatures and session receipts for non-repudiation.
"""

import sys
import os
import json
import argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.crypto.pki import load_certificate_from_file
from app.crypto.sign import rsa_verify_from_cert
from app.common.utils import b64d
from app.storage.transcript import load_transcript, verify_transcript_hash, compute_message_digest
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


def verify_message_signature(entry: str, cert):
    """Verify a single message signature."""
    parts = entry.split('|')
    if len(parts) != 5:
        return False, "Invalid entry format"
    
    seqno, ts, ct, sig, fingerprint = parts
    
    try:
        # Recompute digest
        digest = compute_message_digest(int(seqno), int(ts), ct)
        
        # Verify signature
        sig_bytes = b64d(sig)
        rsa_verify_from_cert(digest, sig_bytes, cert)
        return True, "Valid"
    except Exception as e:
        return False, str(e)


def verify_transcript(transcript_path: str, cert_path: str, receipt_data: dict = None):
    """Verify entire transcript."""
    console.print(Panel.fit(
        f"📋 Verifying Transcript\n{transcript_path}",
        border_style="cyan"
    ))
    
    # Load certificate
    try:
        cert = load_certificate_from_file(cert_path)
        console.print(f"[green]✓ Loaded certificate: {cert_path}[/green]")
    except Exception as e:
        console.print(f"[red]✗ Failed to load certificate: {e}[/red]")
        return False
    
    # Load transcript
    entries = load_transcript(transcript_path)
    if not entries:
        console.print("[yellow]⚠ Transcript is empty[/yellow]")
        return True
    
    console.print(f"[blue]Found {len(entries)} entries[/blue]")
    
    # Verify each message
    table = Table(title="Message Verification")
    table.add_column("Seq", style="cyan")
    table.add_column("Timestamp", style="blue")
    table.add_column("Signature", style="green")
    table.add_column("Status", style="bold")
    
    all_valid = True
    for entry in entries:
        parts = entry.split('|')
        if len(parts) >= 2:
            seqno, ts = parts[0], parts[1]
            valid, message = verify_message_signature(entry, cert)
            
            status = "[green]✓ VALID[/green]" if valid else f"[red]✗ INVALID: {message}[/red]"
            table.add_row(seqno, ts, "RSA+SHA-256", status)
            
            if not valid:
                all_valid = False
    
    console.print(table)
    
    # Verify receipt if provided
    if receipt_data:
        console.print("\n[cyan]═══ Verifying Session Receipt ═══[/cyan]")
        
        # Verify transcript hash
        expected_hash = receipt_data.get('transcript_sha256')
        if verify_transcript_hash(entries, expected_hash):
            console.print(f"[green]✓ Transcript hash matches receipt[/green]")
            console.print(f"  Hash: {expected_hash}")
        else:
            console.print(f"[red]✗ Transcript hash mismatch![/red]")
            all_valid = False
        
        # Verify receipt signature
        try:
            sig_bytes = b64d(receipt_data.get('sig'))
            rsa_verify_from_cert(expected_hash.encode(), sig_bytes, cert)
            console.print(f"[green]✓ Receipt signature valid[/green]")
        except Exception as e:
            console.print(f"[red]✗ Receipt signature invalid: {e}[/red]")
            all_valid = False
    
    # Summary
    console.print()
    if all_valid:
        console.print(Panel.fit(
            "✓ All Verifications Passed\nTranscript is authentic and unmodified",
            border_style="green",
            title="Success"
        ))
    else:
        console.print(Panel.fit(
            "✗ Verification Failed\nTranscript may be tampered or invalid",
            border_style="red",
            title="Failure"
        ))
    
    return all_valid


def extract_receipt_from_transcript(transcript_path: str):
    """Extract session receipt JSON from transcript file."""
    try:
        with open(transcript_path, 'r') as f:
            content = f.read()
        
        # Find receipt JSON
        if '# Session Receipt:' in content:
            receipt_start = content.find('# Session Receipt:') + len('# Session Receipt:')
            receipt_json = content[receipt_start:].strip()
            
            # Extract JSON (basic approach)
            if receipt_json.startswith('{'):
                # Find matching closing brace
                brace_count = 0
                for i, char in enumerate(receipt_json):
                    if char == '{':
                        brace_count += 1
                    elif char == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            receipt_json = receipt_json[:i+1]
                            break
                
                return json.loads(receipt_json)
    except Exception as e:
        console.print(f"[yellow]⚠ Could not extract receipt: {e}[/yellow]")
    
    return None


def main():
    """Main verification entry point."""
    parser = argparse.ArgumentParser(description="Verify transcript and session receipt")
    parser.add_argument("transcript", help="Path to transcript file")
    parser.add_argument("--cert", help="Path to peer certificate (auto-detected if not provided)")
    parser.add_argument("--receipt", help="Path to receipt JSON file (auto-extracted if not provided)")
    
    args = parser.parse_args()
    
    # Auto-detect certificate path based on transcript role
    cert_path = args.cert
    if not cert_path:
        if "client_" in args.transcript:
            cert_path = "certs/server-cert.pem"
            console.print("[blue]Auto-detected: Client transcript, using server certificate[/blue]")
        elif "server_" in args.transcript:
            cert_path = "certs/client-cert.pem"
            console.print("[blue]Auto-detected: Server transcript, using client certificate[/blue]")
        else:
            console.print("[red]Could not auto-detect certificate. Please specify --cert[/red]")
            return 1
    
    # Load or extract receipt
    receipt_data = None
    if args.receipt:
        with open(args.receipt, 'r') as f:
            receipt_data = json.load(f)
    else:
        receipt_data = extract_receipt_from_transcript(args.transcript)
    
    # Verify transcript
    success = verify_transcript(args.transcript, cert_path, receipt_data)
    
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
