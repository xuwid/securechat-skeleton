#!/usr/bin/env python3
"""
Certificate Verification Test Script
Tests certificate validation, expiry checking, and CN verification.
"""

import sys
import os
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.crypto.pki import (
    load_certificate_from_file,
    validate_certificate_chain,
    get_certificate_fingerprint,
    extract_common_name,
    CertificateValidationError
)
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from rich.console import Console
from rich.table import Table

console = Console()


def test_valid_certificates():
    """Test valid certificate chain."""
    console.print("\n[cyan]═══ Test 1: Valid Certificates ═══[/cyan]")
    
    try:
        ca_cert = load_certificate_from_file("certs/ca-cert.pem")
        server_cert = load_certificate_from_file("certs/server-cert.pem")
        client_cert = load_certificate_from_file("certs/client-cert.pem")
        
        # Display certificate info
        table = Table(title="Certificate Information")
        table.add_column("Certificate", style="cyan")
        table.add_column("CN", style="green")
        table.add_column("Valid From", style="yellow")
        table.add_column("Valid Until", style="yellow")
        table.add_column("Fingerprint", style="blue")
        
        for name, cert in [("CA", ca_cert), ("Server", server_cert), ("Client", client_cert)]:
            cn = extract_common_name(cert)
            fingerprint = get_certificate_fingerprint(cert)[:16] + "..."
            table.add_row(
                name,
                cn,
                str(cert.not_valid_before_utc),
                str(cert.not_valid_after_utc),
                fingerprint
            )
        
        console.print(table)
        
        # Validate server certificate
        validate_certificate_chain(server_cert, ca_cert)
        console.print("[green]✓ Server certificate is VALID[/green]")
        
        # Validate client certificate
        validate_certificate_chain(client_cert, ca_cert)
        console.print("[green]✓ Client certificate is VALID[/green]")
        
        return True
    except Exception as e:
        console.print(f"[red]✗ Test failed: {e}[/red]")
        return False


def test_expired_certificate():
    """Test expired certificate detection."""
    console.print("\n[cyan]═══ Test 2: Expired Certificate ═══[/cyan]")
    
    try:
        # Create an expired certificate
        ca_cert = load_certificate_from_file("certs/ca-cert.pem")
        
        from app.crypto.pki import load_private_key_from_file
        ca_key = load_private_key_from_file("certs/ca-key.pem")
        
        # Generate a certificate that expired yesterday
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "expired.test"),
        ])
        
        expired_cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            ca_cert.subject
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow() - timedelta(days=30)
        ).not_valid_after(
            datetime.utcnow() - timedelta(days=1)  # Expired yesterday
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).sign(ca_key, hashes.SHA256(), default_backend())
        
        # Try to validate expired certificate
        try:
            validate_certificate_chain(expired_cert, ca_cert)
            console.print("[red]✗ Test failed: Expired certificate was accepted![/red]")
            return False
        except CertificateValidationError as e:
            if "BAD_CERT" in str(e) and "expired" in str(e).lower():
                console.print(f"[green]✓ Expired certificate correctly rejected[/green]")
                console.print(f"  Error: {e}")
                return True
            else:
                console.print(f"[yellow]? Unexpected error: {e}[/yellow]")
                return False
    
    except Exception as e:
        console.print(f"[red]✗ Test failed: {e}[/red]")
        import traceback
        traceback.print_exc()
        return False


def test_self_signed_certificate():
    """Test self-signed certificate detection."""
    console.print("\n[cyan]═══ Test 3: Self-Signed Certificate ═══[/cyan]")
    
    try:
        ca_cert = load_certificate_from_file("certs/ca-cert.pem")
        
        # Generate a self-signed certificate
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "selfsigned.test"),
        ])
        
        selfsigned_cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer  # Self-signed: issuer == subject
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).sign(private_key, hashes.SHA256(), default_backend())  # Signed by itself
        
        # Try to validate self-signed certificate
        try:
            validate_certificate_chain(selfsigned_cert, ca_cert)
            console.print("[red]✗ Test failed: Self-signed certificate was accepted![/red]")
            return False
        except CertificateValidationError as e:
            if "BAD_CERT" in str(e):
                console.print(f"[green]✓ Self-signed certificate correctly rejected[/green]")
                console.print(f"  Error: {e}")
                return True
            else:
                console.print(f"[yellow]? Unexpected error: {e}[/yellow]")
                return False
    
    except Exception as e:
        console.print(f"[red]✗ Test failed: {e}[/red]")
        import traceback
        traceback.print_exc()
        return False


def test_cn_mismatch():
    """Test Common Name mismatch detection."""
    console.print("\n[cyan]═══ Test 4: CN Mismatch ═══[/cyan]")
    
    try:
        server_cert = load_certificate_from_file("certs/server-cert.pem")
        ca_cert = load_certificate_from_file("certs/ca-cert.pem")
        
        actual_cn = extract_common_name(server_cert)
        console.print(f"[blue]Server certificate CN: {actual_cn}[/blue]")
        
        # Test with wrong CN
        try:
            from app.crypto.pki import verify_common_name
            verify_common_name(server_cert, "wrong.hostname.com")
            console.print("[red]✗ Test failed: CN mismatch was not detected![/red]")
            return False
        except CertificateValidationError as e:
            if "CN mismatch" in str(e):
                console.print(f"[green]✓ CN mismatch correctly detected[/green]")
                console.print(f"  Error: {e}")
                return True
            else:
                console.print(f"[yellow]? Unexpected error: {e}[/yellow]")
                return False
    
    except Exception as e:
        console.print(f"[red]✗ Test failed: {e}[/red]")
        return False


def main():
    """Run all certificate tests."""
    console.print("[bold cyan]Certificate Validation Test Suite[/bold cyan]")
    console.print("="*60)
    
    tests = [
        ("Valid Certificates", test_valid_certificates),
        ("Expired Certificate Detection", test_expired_certificate),
        ("Self-Signed Certificate Detection", test_self_signed_certificate),
        ("CN Mismatch Detection", test_cn_mismatch),
    ]
    
    results = []
    for name, test_func in tests:
        result = test_func()
        results.append((name, result))
    
    # Summary
    console.print("\n[bold cyan]═══ Test Summary ═══[/bold cyan]")
    summary_table = Table()
    summary_table.add_column("Test", style="cyan")
    summary_table.add_column("Result", style="bold")
    
    passed = 0
    for name, result in results:
        status = "[green]✓ PASS[/green]" if result else "[red]✗ FAIL[/red]"
        summary_table.add_row(name, status)
        if result:
            passed += 1
    
    console.print(summary_table)
    console.print(f"\n[bold]Passed: {passed}/{len(tests)}[/bold]")
    
    return passed == len(tests)


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
