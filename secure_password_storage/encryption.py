"""
Encryption module for Secure Password Storage System.
Course: Cryptography and Network Security (E1CSA311)
Alliance University - Alliance School of Advanced Computing

Implements password hashing using SHA-256 with cryptographic salting.
NEVER stores or logs plaintext passwords.
"""

import hashlib


def hash_password(password: str, salt: bytes) -> str:
    """
    Hashes a password with a cryptographic salt using SHA-256.

    Academic Cryptographic Specification:
        1. Encodes password string to UTF-8 bytes.
        2. Concatenates salt (bytes) with password (bytes): data = salt + password_bytes.
        3. Computes SHA-256 digest over the concatenated data.
        4. Returns the 64-character hexadecimal representation of the digest.

    Parameters:
        password (str): Plaintext password provided by user.
        salt (bytes): Random cryptographic salt (16 bytes).

    Returns:
        str: Hexadecimal SHA-256 hash string.
    """
    if isinstance(password, str):
        password_bytes = password.encode("utf-8")
    elif isinstance(password, (bytes, bytearray)):
        password_bytes = bytes(password)
    else:
        raise TypeError("Password must be a string or bytes.")

    if not isinstance(salt, (bytes, bytearray)):
        raise TypeError("Salt must be provided as bytes.")

    data = salt + password_bytes
    return hashlib.sha256(data).hexdigest()
