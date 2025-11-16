"""Issue server/client cert signed by Root CA (SAN=DNSName(CN))."""
import os
import sys
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import argparse
import ipaddress


def load_ca(ca_cert_path, ca_key_path):
    """Load CA certificate and private key from files."""
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    
    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    
    return ca_cert, ca_key


def generate_certificate(
    common_name,
    output_prefix,
    ca_cert,
    ca_key,
    validity_days=365,
    cert_type="server"
):
    """
    Generate a certificate signed by the CA.
    
    Args:
        common_name: Common name for the certificate
        output_prefix: Output file prefix (e.g., "certs/server")
        ca_cert: CA certificate object
        ca_key: CA private key object
        validity_days: Number of days the certificate is valid
        cert_type: Type of certificate ("server" or "client")
    """
    print(f"\n[*] Generating {cert_type} certificate for: {common_name}")
    
    # Generate private key
    print(f"[*] Generating RSA private key (2048 bits)...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Create certificate subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Punjab"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Lahore"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NUCES"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, f"SecureChat {cert_type.title()}"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    # Build certificate
    print(f"[*] Building certificate signed by CA...")
    cert_builder = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=validity_days)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
        critical=False,
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
        critical=False,
    )
    
    # Add appropriate key usage and SAN based on cert type
    if cert_type == "server":
        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            ]),
            critical=True,
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(common_name),
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
    else:  # client
        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=True,
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(common_name),
            ]),
            critical=False,
        )
    
    # Sign certificate with CA key
    cert = cert_builder.sign(ca_key, hashes.SHA256(), default_backend())
    
    # Ensure output directory exists
    output_dir = os.path.dirname(output_prefix)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    
    # Write private key to file
    key_path = f"{output_prefix}-key.pem"
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"[+] Private key saved to: {key_path}")
    
    # Write certificate to file
    cert_path = f"{output_prefix}-cert.pem"
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"[+] Certificate saved to: {cert_path}")
    
    print(f"[+] {cert_type.title()} certificate generated successfully!")
    print(f"[+] Valid from: {cert.not_valid_before}")
    print(f"[+] Valid until: {cert.not_valid_after}")
    print(f"[+] Serial Number: {cert.serial_number}")
    
    return cert_path, key_path


def main():
    """Generate server or client certificate."""
    parser = argparse.ArgumentParser(description="Generate certificate signed by CA")
    parser.add_argument("--cn", required=True, help="Common Name")
    parser.add_argument("--out", required=True, help="Output prefix (e.g., certs/server)")
    parser.add_argument("--type", choices=["server", "client"], default="server", help="Certificate type")
    parser.add_argument("--ca-cert", default="certs/ca-cert.pem", help="CA certificate path")
    parser.add_argument("--ca-key", default="certs/ca-key.pem", help="CA key path")
    parser.add_argument("--days", type=int, default=365, help="Validity in days")
    
    args = parser.parse_args()
    
    # Check if CA exists
    if not os.path.exists(args.ca_cert) or not os.path.exists(args.ca_key):
        print("[!] Error: CA certificate or key not found!", file=sys.stderr)
        print("[!] Please run gen_ca.py first to generate the root CA.", file=sys.stderr)
        sys.exit(1)
    
    try:
        # Load CA
        print("[*] Loading CA certificate and key...")
        ca_cert, ca_key = load_ca(args.ca_cert, args.ca_key)
        print("[+] CA loaded successfully")
        
        # Generate certificate
        generate_certificate(
            common_name=args.cn,
            output_prefix=args.out,
            ca_cert=ca_cert,
            ca_key=ca_key,
            validity_days=args.days,
            cert_type=args.type
        )
        
        print("\n" + "="*60)
        print("[+] Certificate generated successfully!")
        print("="*60)
        
    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
