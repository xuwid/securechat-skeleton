#!/usr/bin/env python3
"""
Quick Crypto Test - Verify all crypto modules work correctly
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.crypto.aes import aes_encrypt, aes_decrypt
from app.crypto.dh import (generate_dh_private_key, compute_dh_public_key, 
                           compute_dh_shared_secret, derive_aes_key_from_dh, DH_G, DH_P)
from app.crypto.sign import rsa_sign, rsa_verify
from app.crypto.pki import load_certificate_from_file, load_private_key_from_file
from app.common.utils import b64e, b64d, sha256_hex
from rich.console import Console
from rich.panel import Panel

console = Console()


def test_aes():
    """Test AES encryption/decryption."""
    console.print("\n[cyan]Testing AES-128-ECB...[/cyan]")
    
    key = b"0123456789abcdef"  # 16 bytes
    plaintext = b"Hello, Secure Chat!"
    
    # Encrypt
    ciphertext = aes_encrypt(plaintext, key)
    console.print(f"[blue]Plaintext:  {plaintext.decode()}[/blue]")
    console.print(f"[yellow]Ciphertext: {b64e(ciphertext)}[/yellow]")
    
    # Decrypt
    decrypted = aes_decrypt(ciphertext, key)
    console.print(f"[blue]Decrypted:  {decrypted.decode()}[/blue]")
    
    assert decrypted == plaintext, "AES decryption failed!"
    console.print("[green]✓ AES encryption/decryption works![/green]")
    return True


def test_dh():
    """Test Diffie-Hellman key exchange."""
    console.print("\n[cyan]Testing Diffie-Hellman...[/cyan]")
    
    # Client side
    client_private = generate_dh_private_key()
    client_public = compute_dh_public_key(client_private, DH_G, DH_P)
    console.print(f"[blue]Client public key (first 50 digits): {str(client_public)[:50]}...[/blue]")
    
    # Server side
    server_private = generate_dh_private_key()
    server_public = compute_dh_public_key(server_private, DH_G, DH_P)
    console.print(f"[blue]Server public key (first 50 digits): {str(server_public)[:50]}...[/blue]")
    
    # Compute shared secrets
    client_shared = compute_dh_shared_secret(server_public, client_private, DH_P)
    server_shared = compute_dh_shared_secret(client_public, server_private, DH_P)
    
    console.print(f"[yellow]Client shared secret (first 50 digits): {str(client_shared)[:50]}...[/yellow]")
    console.print(f"[yellow]Server shared secret (first 50 digits): {str(server_shared)[:50]}...[/yellow]")
    
    assert client_shared == server_shared, "DH shared secrets don't match!"
    console.print("[green]✓ DH key exchange works![/green]")
    
    # Derive AES keys
    client_aes_key = derive_aes_key_from_dh(client_shared)
    server_aes_key = derive_aes_key_from_dh(server_shared)
    
    console.print(f"[blue]Derived AES key: {b64e(client_aes_key)}[/blue]")
    
    assert client_aes_key == server_aes_key, "Derived AES keys don't match!"
    assert len(client_aes_key) == 16, "AES key must be 16 bytes!"
    console.print("[green]✓ AES key derivation works![/green]")
    
    return True


def test_rsa_signatures():
    """Test RSA signatures."""
    console.print("\n[cyan]Testing RSA Signatures...[/cyan]")
    
    # Load keys
    server_key = load_private_key_from_file("certs/server-key.pem")
    server_cert = load_certificate_from_file("certs/server-cert.pem")
    
    message = b"This is a test message"
    console.print(f"[blue]Message: {message.decode()}[/blue]")
    
    # Sign
    signature = rsa_sign(message, server_key)
    console.print(f"[yellow]Signature: {b64e(signature)[:50]}...[/yellow]")
    
    # Verify
    public_key = server_cert.public_key()
    rsa_verify(message, signature, public_key)
    console.print("[green]✓ RSA signature verification works![/green]")
    
    # Test tampering detection
    tampered_message = b"This is a tampered message"
    try:
        rsa_verify(tampered_message, signature, public_key)
        console.print("[red]✗ Failed to detect tampering![/red]")
        return False
    except:
        console.print("[green]✓ Tampering correctly detected![/green]")
    
    return True


def test_hashing():
    """Test SHA-256 hashing."""
    console.print("\n[cyan]Testing SHA-256...[/cyan]")
    
    data = b"Hello, World!"
    hash_value = sha256_hex(data)
    
    console.print(f"[blue]Data: {data.decode()}[/blue]")
    console.print(f"[yellow]SHA-256: {hash_value}[/yellow]")
    
    expected = "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
    assert hash_value == expected, "SHA-256 hash doesn't match expected value!"
    console.print("[green]✓ SHA-256 hashing works![/green]")
    
    return True


def test_base64():
    """Test Base64 encoding/decoding."""
    console.print("\n[cyan]Testing Base64...[/cyan]")
    
    data = b"SecureChat"
    encoded = b64e(data)
    decoded = b64d(encoded)
    
    console.print(f"[blue]Original: {data.decode()}[/blue]")
    console.print(f"[yellow]Encoded:  {encoded}[/yellow]")
    console.print(f"[blue]Decoded:  {decoded.decode()}[/blue]")
    
    assert decoded == data, "Base64 round-trip failed!"
    console.print("[green]✓ Base64 encoding/decoding works![/green]")
    
    return True


def main():
    """Run all crypto tests."""
    console.print(Panel.fit(
        "🔒 Secure Chat - Crypto Module Tests",
        border_style="cyan",
        title="Test Suite"
    ))
    
    tests = [
        ("Base64 Encoding", test_base64),
        ("SHA-256 Hashing", test_hashing),
        ("AES-128 Encryption", test_aes),
        ("Diffie-Hellman", test_dh),
        ("RSA Signatures", test_rsa_signatures),
    ]
    
    results = []
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result))
        except Exception as e:
            console.print(f"[red]✗ {name} failed: {e}[/red]")
            import traceback
            traceback.print_exc()
            results.append((name, False))
    
    # Summary
    console.print("\n" + "="*60)
    console.print("[bold cyan]Test Summary[/bold cyan]")
    console.print("="*60)
    
    passed = sum(1 for _, result in results if result)
    for name, result in results:
        status = "[green]✓ PASS[/green]" if result else "[red]✗ FAIL[/red]"
        console.print(f"{status} {name}")
    
    console.print("="*60)
    console.print(f"[bold]Passed: {passed}/{len(tests)}[/bold]")
    
    if passed == len(tests):
        console.print(Panel.fit(
            "✓ All crypto modules working correctly!\nSystem ready for use.",
            border_style="green",
            title="Success"
        ))
        return 0
    else:
        console.print(Panel.fit(
            "✗ Some tests failed. Please check configuration.",
            border_style="red",
            title="Failure"
        ))
        return 1


if __name__ == "__main__":
    sys.exit(main())
