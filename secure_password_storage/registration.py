"""
Registration module for Secure Password Storage System.
Course: Cryptography and Network Security (E1CSA311)
Alliance University - Alliance School of Advanced Computing

Implements user registration, random salt generation via os.urandom(16),
and credential hashing using SHA-256 before persistent storage.
"""

import os
from typing import Tuple
from encryption import hash_password
from storage import load_credentials, save_credentials

try:
    from config import MIN_PASSWORD_LENGTH, SALT_BYTE_LENGTH
except ImportError:
    MIN_PASSWORD_LENGTH = 6
    SALT_BYTE_LENGTH = 16


def generate_salt() -> bytes:
    """
    Generates a cryptographically strong random salt.

    Uses os.urandom(16) to produce 16 bytes (128 bits) of high-entropy randomness
    sourced from the operating system's cryptographic CSPRNG.

    Returns:
        bytes: 16-byte random salt.
    """
    return os.urandom(SALT_BYTE_LENGTH)


def register_user(username: str, password: str) -> Tuple[bool, str]:
    """
    Registers a new user in the system.

    Steps:
    1. Validate username and password presence and constraints.
    2. Check whether username already exists in users.json.
    3. Generate a fresh random 16-byte salt via os.urandom(16).
    4. Compute SHA-256 hash of (salt + password).
    5. Save credentials (username, salt.hex(), password_hash).
    6. Return (True, "Registration successful.") on success.

    Returns:
        tuple[bool, str]: (Success status, descriptive message).
    """
    if not username or not str(username).strip():
        return False, "Username cannot be empty."

    username = str(username).strip()

    if not password:
        return False, "Password cannot be empty."

    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters long."

    # Step 1: Check whether username already exists
    existing_credentials = load_credentials(username)
    if existing_credentials is not None:
        return False, "User already exists."

    # Step 2: Generate random 16-byte salt
    salt = generate_salt()

    # Step 3: Generate password hash using SHA-256
    password_hash = hash_password(password, salt)

    # Step 4: Save credentials to persistent JSON storage
    saved = save_credentials(username, salt, password_hash)
    if not saved:
        return False, "Failed to save credentials. Storage error."

    # Step 5: Return success
    return True, "Registration successful."
