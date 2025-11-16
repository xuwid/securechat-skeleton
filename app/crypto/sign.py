"""RSA PKCS#1 v1.5 SHA-256 sign/verify."""
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography import x509


def rsa_sign(message: bytes, private_key) -> bytes:
    """
    Sign message using RSA with SHA-256 and PKCS#1 v1.5 padding.
    
    Args:
        message: Data to sign
        private_key: RSA private key object
        
    Returns:
        Signature bytes
    """
    signature = private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature


def rsa_verify(message: bytes, signature: bytes, public_key) -> bool:
    """
    Verify RSA signature using SHA-256 and PKCS#1 v1.5 padding.
    
    Args:
        message: Original message that was signed
        signature: Signature to verify
        public_key: RSA public key object
        
    Returns:
        True if signature is valid
        
    Raises:
        InvalidSignature if verification fails
    """
    try:
        public_key.verify(
            signature,
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        raise InvalidSignature("RSA signature verification failed")


def rsa_verify_from_cert(message: bytes, signature: bytes, cert: x509.Certificate) -> bool:
    """
    Verify RSA signature using public key from certificate.
    
    Args:
        message: Original message that was signed
        signature: Signature to verify
        cert: X.509 certificate containing public key
        
    Returns:
        True if signature is valid
        
    Raises:
        InvalidSignature if verification fails
    """
    public_key = cert.public_key()
    return rsa_verify(message, signature, public_key)


def load_private_key_from_file(key_path: str):
    """Load RSA private key from PEM file."""
    with open(key_path, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    return private_key


def load_public_key_from_cert(cert: x509.Certificate):
    """Extract public key from certificate."""
    return cert.public_key()
