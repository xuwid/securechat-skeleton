"""AES-128(ECB)+PKCS#7 helpers (use library)."""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding


def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt plaintext using AES-128 in ECB mode with PKCS#7 padding.
    
    Args:
        plaintext: Data to encrypt
        key: 16-byte AES key
        
    Returns:
        Ciphertext bytes
    """
    if len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key")
    
    # Apply PKCS#7 padding
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    
    # Encrypt using AES-128-ECB
    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    return ciphertext


def aes_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt ciphertext using AES-128 in ECB mode and remove PKCS#7 padding.
    
    Args:
        ciphertext: Data to decrypt
        key: 16-byte AES key
        
    Returns:
        Plaintext bytes
    """
    if len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key")
    
    # Decrypt using AES-128-ECB
    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove PKCS#7 padding
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    
    return plaintext
