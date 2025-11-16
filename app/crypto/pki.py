"""X.509 validation: signed-by-CA, validity window, CN/SAN."""
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature
from datetime import datetime
from typing import Tuple


class CertificateValidationError(Exception):
    """Custom exception for certificate validation failures."""
    pass


def load_certificate(cert_pem: str) -> x509.Certificate:
    """Load X.509 certificate from PEM string."""
    try:
        return x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
    except Exception as e:
        raise CertificateValidationError(f"Failed to load certificate: {e}")


def load_private_key(key_pem: str):
    """Load private key from PEM string."""
    try:
        return serialization.load_pem_private_key(
            key_pem.encode(),
            password=None,
            backend=default_backend()
        )
    except Exception as e:
        raise CertificateValidationError(f"Failed to load private key: {e}")


def load_certificate_from_file(cert_path: str) -> x509.Certificate:
    """Load X.509 certificate from PEM file."""
    try:
        with open(cert_path, 'rb') as f:
            return x509.load_pem_x509_certificate(f.read(), default_backend())
    except Exception as e:
        raise CertificateValidationError(f"Failed to load certificate from {cert_path}: {e}")


def load_private_key_from_file(key_path: str):
    """Load private key from PEM file."""
    try:
        with open(key_path, 'rb') as f:
            return serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
    except Exception as e:
        raise CertificateValidationError(f"Failed to load private key from {key_path}: {e}")


def verify_certificate_signature(cert: x509.Certificate, ca_cert: x509.Certificate) -> bool:
    """
    Verify that certificate is signed by CA.
    
    Args:
        cert: Certificate to verify
        ca_cert: CA certificate
        
    Returns:
        True if signature is valid
        
    Raises:
        CertificateValidationError if signature is invalid
    """
    try:
        # Get CA's public key
        ca_public_key = ca_cert.public_key()
        
        # Get the signature algorithm from the certificate
        from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
        
        # Verify the signature using PKCS1v15 padding and the hash algorithm from cert
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            asym_padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )
        return True
    except InvalidSignature:
        raise CertificateValidationError("Certificate signature verification failed")
    except Exception as e:
        raise CertificateValidationError(f"Signature verification error: {e}")


def check_certificate_validity(cert: x509.Certificate) -> bool:
    """
    Check if certificate is within its validity period.
    
    Args:
        cert: Certificate to check
        
    Returns:
        True if certificate is currently valid
        
    Raises:
        CertificateValidationError if certificate is expired or not yet valid
    """
    now = datetime.utcnow()
    
    if now < cert.not_valid_before:
        raise CertificateValidationError(
            f"Certificate not yet valid. Valid from: {cert.not_valid_before}"
        )
    
    if now > cert.not_valid_after:
        raise CertificateValidationError(
            f"Certificate expired. Valid until: {cert.not_valid_after}"
        )
    
    return True


def extract_common_name(cert: x509.Certificate) -> str:
    """Extract Common Name from certificate subject."""
    try:
        cn_attributes = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        if cn_attributes:
            return cn_attributes[0].value
        return ""
    except Exception as e:
        raise CertificateValidationError(f"Failed to extract CN: {e}")


def verify_common_name(cert: x509.Certificate, expected_cn: str) -> bool:
    """
    Verify certificate Common Name matches expected value.
    
    Args:
        cert: Certificate to check
        expected_cn: Expected Common Name
        
    Returns:
        True if CN matches
        
    Raises:
        CertificateValidationError if CN doesn't match
    """
    actual_cn = extract_common_name(cert)
    
    if actual_cn != expected_cn:
        # Also check Subject Alternative Names (SAN)
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            san_names = san_ext.value.get_values_for_type(x509.DNSName)
            
            if expected_cn in san_names:
                return True
        except x509.ExtensionNotFound:
            pass
        
        raise CertificateValidationError(
            f"CN mismatch. Expected: {expected_cn}, Got: {actual_cn}"
        )
    
    return True


def validate_certificate_chain(
    cert: x509.Certificate,
    ca_cert: x509.Certificate,
    expected_cn: str = None
) -> bool:
    """
    Perform full certificate validation.
    
    Args:
        cert: Certificate to validate
        ca_cert: CA certificate that should have signed it
        expected_cn: Expected Common Name (optional)
        
    Returns:
        True if certificate is valid
        
    Raises:
        CertificateValidationError with "BAD_CERT" on any validation failure
    """
    try:
        # Check validity period
        check_certificate_validity(cert)
        
        # Verify signature chain
        verify_certificate_signature(cert, ca_cert)
        
        # Optionally check Common Name
        if expected_cn:
            verify_common_name(cert, expected_cn)
        
        return True
        
    except CertificateValidationError as e:
        # Re-raise with BAD_CERT prefix for easier identification
        raise CertificateValidationError(f"BAD_CERT: {e}")


def get_certificate_fingerprint(cert: x509.Certificate) -> str:
    """Get SHA-256 fingerprint of certificate."""
    fingerprint = cert.fingerprint(hashes.SHA256())
    return fingerprint.hex()


def certificate_to_pem(cert: x509.Certificate) -> str:
    """Convert certificate object to PEM string."""
    return cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
