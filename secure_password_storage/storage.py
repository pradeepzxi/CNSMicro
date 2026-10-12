"""
Storage module for Secure Password Storage System.
Course: Cryptography and Network Security (E1CSA311)
Alliance University - Alliance School of Advanced Computing

Handles persistent storage of user credentials using JSON file format.
Stores only hexadecimal salt and SHA-256 hash. Plaintext passwords are NEVER stored.
"""

import json
import os
from typing import Dict, Any, Optional

try:
    from config import USERS_FILE
except ImportError:
    USERS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'users.json')


def get_storage_path() -> str:
    """Returns the current path to the users.json file."""
    return USERS_FILE


def load_all() -> Dict[str, Dict[str, str]]:
    """
    Loads all credentials from users.json.

    Handles:
    - users.json not existing (returns empty dict)
    - invalid JSON formatting (returns empty dict)
    - file read errors (returns empty dict)

    Returns:
        dict: Dictionary of users with their salt and hash.
    """
    file_path = get_storage_path()
    if not os.path.exists(file_path):
        return {}

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if not content:
                return {}
            data = json.loads(content)
            if isinstance(data, dict):
                return data
            return {}
    except (json.JSONDecodeError, OSError, IOError):
        return {}


def load_credentials(username: str) -> Optional[Dict[str, str]]:
    """
    Loads stored credentials for a specific username.

    Parameters:
        username (str): The username to query.

    Returns:
        dict | None: Dictionary {"salt": "hex_salt", "hash": "hex_hash"} or None.
    """
    if not username:
        return None
    users = load_all()
    return users.get(username)


def save_credentials(username: str, salt: Any, password_hash: str) -> bool:
    """
    Saves a user's salt and password hash to users.json.

    Parameters:
        username (str): User identifier.
        salt (bytes | str): 16-byte random salt or hexadecimal salt string.
        password_hash (str): 64-character SHA-256 hexadecimal hash.

    Returns:
        bool: True if write succeeded, False otherwise.
    """
    if not username or not salt or not password_hash:
        return False

    # Convert salt bytes to hexadecimal string for JSON serialization
    if isinstance(salt, (bytes, bytearray)):
        salt_hex = salt.hex()
    elif isinstance(salt, str):
        salt_hex = salt
    else:
        return False

    file_path = get_storage_path()
    users = load_all()

    # Prepend new user at the top (newest account at top of database)
    new_users = {
        username: {
            "salt": salt_hex,
            "hash": password_hash
        }
    }
    for existing_user, creds in users.items():
        if existing_user != username:
            new_users[existing_user] = creds

    try:
        # Atomic file write: write to temporary file first, then replace
        temp_file = file_path + ".tmp"
        directory = os.path.dirname(file_path)
        if directory and not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)

        with open(temp_file, 'w', encoding='utf-8') as f:
            json.dump(new_users, f, indent=4)

        if os.path.exists(file_path):
            os.replace(temp_file, file_path)
        else:
            os.rename(temp_file, file_path)
        return True
    except (OSError, IOError):
        return False
