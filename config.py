"""
Configuration module for the Secure Password Storage System.
Course: Cryptography and Network Security (E1CSA311)
Alliance University - Alliance School of Advanced Computing
"""

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_FILE = os.path.join(BASE_DIR, 'users.json')

# Cryptographically strong secret key for Flask session signing
SECRET_KEY = os.environ.get('SECRET_KEY', 'cns-micro-project-alliance-e1csa311-secret-key-2026')

# Cryptographic and Validation Constraints
MIN_PASSWORD_LENGTH = 6
SALT_BYTE_LENGTH = 16  # 16 bytes = 128 bits of cryptographic entropy
