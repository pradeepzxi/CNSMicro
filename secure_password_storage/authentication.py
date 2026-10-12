"""
Authentication module for Secure Password Storage System.
Course: Cryptography and Network Security (E1CSA311)
Alliance University - Alliance School of Advanced Computing

Implements secure password verification:
- Retrieves stored hexadecimal salt and converts back to bytes.
- Hashes the entered password using stored salt + SHA-256.
- Compares computed hash with stored hash using constant-time comparison.
- Prevents user enumeration by always returning 'Invalid username or password.' on failure.
"""

import hmac
from typing import Tuple
from encryption import hash_password
from storage import load_credentials


def verify_password(username: str, password: str) -> bool:
    """
    Verifies an entered password against stored salt and SHA-256 hash.

    Verification Workflow:
    1. Load credentials for the given username from storage.
    2. Return False if user does not exist.
    3. Retrieve stored salt and convert from hexadecimal representation back to bytes.
    4. Compute SHA-256(salt + entered_password).
    5. Compare computed hash with stored hash (using hmac.compare_digest to prevent timing attacks).
    6. Return True if matched, False otherwise.

    Parameters:
        username (str): The username attempting verification.
        password (str): The plaintext password entered by the user.

    Returns:
        bool: True if password matches stored hash, False otherwise.
    """
    if not username or not password:
        return False

    username = str(username).strip()
    credentials = load_credentials(username)
    if not credentials:
        return False

    stored_salt_hex = credentials.get("salt")
    stored_hash = credentials.get("hash")

    if not stored_salt_hex or not stored_hash:
        return False

    try:
        salt_bytes = bytes.fromhex(stored_salt_hex)
    except (ValueError, TypeError):
        return False

    computed_hash = hash_password(password, salt_bytes)
    return hmac.compare_digest(computed_hash, stored_hash)


def login_user(username: str, password: str) -> Tuple[bool, str]:
    """
    Authenticates a user attempting to log into the application.

    Security Rule:
    Does NOT reveal whether the username exists or not.
    Always returns 'Invalid username or password.' on any failure.

    Parameters:
        username (str): Entered username.
        password (str): Entered plaintext password.

    Returns:
        tuple[bool, str]: (Success status, descriptive message).
    """
    if not username or not password:
        return False, "Invalid username or password."

    if verify_password(username, password):
        return True, "Login successful."

    return False, "Invalid username or password."
