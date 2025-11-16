"""Classic DH helpers + Trunc16(SHA256(Ks)) derivation."""
import hashlib
import secrets
from typing import Tuple


# Standard DH parameters (2048-bit MODP Group - RFC 3526 Group 14)
DH_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
)

DH_G = 2


def generate_dh_private_key() -> int:
    """Generate a random private key for DH."""
    # Generate a random number between 2 and p-2
    return secrets.randbelow(DH_P - 2) + 2


def compute_dh_public_key(private_key: int, g: int = DH_G, p: int = DH_P) -> int:
    """Compute public key: A = g^a mod p"""
    return pow(g, private_key, p)


def compute_dh_shared_secret(peer_public_key: int, private_key: int, p: int = DH_P) -> int:
    """Compute shared secret: Ks = B^a mod p or A^b mod p"""
    return pow(peer_public_key, private_key, p)


def derive_aes_key_from_dh(shared_secret: int) -> bytes:
    """
    Derive AES-128 key from DH shared secret.
    K = Trunc16(SHA256(big-endian(Ks)))
    
    Args:
        shared_secret: DH shared secret (integer)
        
    Returns:
        16-byte AES key
    """
    # Convert shared secret to big-endian bytes
    # Calculate byte length needed
    byte_length = (shared_secret.bit_length() + 7) // 8
    ks_bytes = shared_secret.to_bytes(byte_length, byteorder='big')
    
    # Hash with SHA-256
    digest = hashlib.sha256(ks_bytes).digest()
    
    # Truncate to 16 bytes for AES-128
    return digest[:16]


def dh_exchange_client() -> Tuple[int, int, int]:
    """
    Perform client side of DH exchange.
    
    Returns:
        (private_key, public_key_A, shared parameters)
    """
    private_key = generate_dh_private_key()
    public_key = compute_dh_public_key(private_key, DH_G, DH_P)
    return private_key, public_key, DH_P


def dh_exchange_server(client_public_key: int) -> Tuple[int, int, int]:
    """
    Perform server side of DH exchange.
    
    Args:
        client_public_key: Client's public key A
        
    Returns:
        (private_key, public_key_B, shared_secret)
    """
    private_key = generate_dh_private_key()
    public_key = compute_dh_public_key(private_key, DH_G, DH_P)
    shared_secret = compute_dh_shared_secret(client_public_key, private_key, DH_P)
    return private_key, public_key, shared_secret
