"""
Unit and module-level test prototype for Secure Password Storage System.
Course: Cryptography and Network Security (E1CSA311)
Alliance University - Alliance School of Advanced Computing

Tests core cryptographic operations, salting entropy, hashing, registration,
authentication, and storage formatting directly without browser dependencies.
"""

import os
import unittest
import tempfile
import json
import shutil

from encryption import hash_password
from registration import generate_salt, register_user
from authentication import verify_password, login_user
import storage


class TestPrototype(unittest.TestCase):
    def setUp(self):
        """Set up an isolated temporary storage file for testing."""
        self.test_dir = tempfile.mkdtemp()
        self.test_users_file = os.path.join(self.test_dir, 'test_users.json')
        # Point storage to isolated test file
        self.original_users_file = storage.USERS_FILE
        storage.USERS_FILE = self.test_users_file

    def tearDown(self):
        """Clean up temporary test directory and restore storage path."""
        storage.USERS_FILE = self.original_users_file
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_generate_salt(self):
        """Test 1: Verify that generate_salt produces exactly 16 bytes."""
        salt = generate_salt()
        self.assertIsInstance(salt, bytes)
        self.assertEqual(len(salt), 16)

    def test_02_different_salts(self):
        """Test 2: Verify that successive salts are cryptographically random and distinct."""
        salt1 = generate_salt()
        salt2 = generate_salt()
        self.assertNotEqual(salt1, salt2)

    def test_03_different_hashes(self):
        """Test 3: Verify that identical passwords with different salts yield different hashes."""
        password = "SecureCollegePassword2026!"
        salt1 = generate_salt()
        salt2 = generate_salt()
        hash1 = hash_password(password, salt1)
        hash2 = hash_password(password, salt2)

        self.assertEqual(len(hash1), 64)
        self.assertEqual(len(hash2), 64)
        self.assertNotEqual(hash1, hash2, "Identical passwords with different salts MUST produce different hashes!")

    def test_04_register_user(self):
        """Test 4: Verify standard registration with valid credentials."""
        success, message = register_user("student_pradeep", "AllianceCns@2026")
        self.assertTrue(success)
        self.assertEqual(message, "Registration successful.")

    def test_05_duplicate_registration(self):
        """Test 5: Verify that duplicate username registration is rejected."""
        # First registration
        success1, msg1 = register_user("shashidhar", "Password@123")
        self.assertTrue(success1)

        # Duplicate attempt with same username
        success2, msg2 = register_user("shashidhar", "DifferentPassword@456")
        self.assertFalse(success2)
        self.assertEqual(msg2, "User already exists.")

    def test_06_correct_password(self):
        """Test 6: Verify password authentication succeeds with the correct password."""
        register_user("basavanni", "StrongPassword#2026")
        self.assertTrue(verify_password("basavanni", "StrongPassword#2026"))
        success, msg = login_user("basavanni", "StrongPassword#2026")
        self.assertTrue(success)
        self.assertEqual(msg, "Login successful.")

    def test_07_incorrect_password(self):
        """Test 7: Verify password authentication fails with an incorrect password."""
        register_user("manish", "SecretKey@999")
        self.assertFalse(verify_password("manish", "WrongPassword!"))
        success, msg = login_user("manish", "WrongPassword!")
        self.assertFalse(success)
        self.assertEqual(msg, "Invalid username or password.")

    def test_08_missing_user(self):
        """Test 8: Verify authentication fails gracefully for nonexistent user."""
        self.assertFalse(verify_password("nonexistent_user", "AnyPassword123"))
        success, msg = login_user("nonexistent_user", "AnyPassword123")
        self.assertFalse(success)
        self.assertEqual(msg, "Invalid username or password.")

    def test_09_stored_credential_format(self):
        """Test 9: Verify storage structure and ensure plaintext password is NOT stored."""
        username = "crypto_user"
        plaintext_pw = "SuperSecretPlainText123"
        register_user(username, plaintext_pw)

        with open(self.test_users_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertIn(username, data)
        user_record = data[username]

        # Verify required keys
        self.assertIn("salt", user_record)
        self.assertIn("hash", user_record)

        # Salt must be 32 hex characters (16 bytes)
        self.assertEqual(len(user_record["salt"]), 32)
        # Hash must be 64 hex characters (SHA-256)
        self.assertEqual(len(user_record["hash"]), 64)

        # CRITICAL SECURITY CHECK: Plaintext password must NOT appear anywhere in the storage file
        self.assertNotIn("password", user_record)
        with open(self.test_users_file, "r", encoding="utf-8") as f:
            raw_content = f.read()
            self.assertNotIn(plaintext_pw, raw_content, "Plaintext password was found in storage file!")


if __name__ == "__main__":
    unittest.main(verbosity=2)
