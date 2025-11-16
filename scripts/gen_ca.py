"""Create Root CA (RSA + self-signed X.509) using cryptography."""
import os
import sys
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import argparse


def generate_ca(ca_name="FAST-NU Root CA", output_dir="certs", validity_days=3650):
    """
    Generate a self-signed root CA certificate.
    
    Args:
        ca_name: Name for the CA
        output_dir: Directory to store the CA certificate and key
        validity_days: Number of days the CA certificate is valid
    """
    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"[*] Generating Root CA: {ca_name}")
    
    # Generate private key for CA
    print("[*] Generating RSA private key (4096 bits)...")
    ca_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )
    
    # Create CA certificate subject
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Punjab"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Lahore"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NUCES"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "SecureChat Root CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, ca_name),
    ])
    
    # Build CA certificate
    print("[*] Building self-signed CA certificate...")
    ca_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        ca_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=validity_days)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=0),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=True,
            crl_sign=True,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(ca_private_key.public_key()),
        critical=False,
    ).sign(ca_private_key, hashes.SHA256(), default_backend())
    
    # Write CA private key to file
    ca_key_path = os.path.join(output_dir, "ca-key.pem")
    with open(ca_key_path, "wb") as f:
        f.write(ca_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"[+] CA private key saved to: {ca_key_path}")
    
    # Write CA certificate to file
    ca_cert_path = os.path.join(output_dir, "ca-cert.pem")
    with open(ca_cert_path, "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    print(f"[+] CA certificate saved to: {ca_cert_path}")
    
    print("\n[+] Root CA generated successfully!")
    print(f"[+] Valid from: {ca_cert.not_valid_before}")
    print(f"[+] Valid until: {ca_cert.not_valid_after}")
    print(f"[+] Serial Number: {ca_cert.serial_number}")
    
    return ca_cert_path, ca_key_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate Root CA")
    parser.add_argument("--name", default="FAST-NU Root CA", help="CA name")
    parser.add_argument("--output", default="certs", help="Output directory")
    parser.add_argument("--days", type=int, default=3650, help="Validity in days")
    
    args = parser.parse_args()
    
    try:
        generate_ca(args.name, args.output, args.days)
    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)
