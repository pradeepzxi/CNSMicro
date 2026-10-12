"""
Integration and Web Route Test Suite for Secure Password Storage System.
Course: Cryptography and Network Security (E1CSA311)
Alliance University - Alliance School of Advanced Computing

Tests all 10 required system test cases:
TEST 1: Register new user
TEST 2: Correct password
TEST 3: Wrong password
TEST 4: Duplicate username
TEST 5: Same password + different salts
TEST 6: Stored credential does not contain plaintext password
TEST 7: Dashboard requires authentication
TEST 8: Logout destroys session
TEST 9: ShopKart demo login succeeds with correct demo credentials
TEST 10: ShopKart demo login fails with incorrect credentials
"""

import os
import unittest
import tempfile
import json
import shutil

from app import app, init_demo_account
import storage
from registration import generate_salt, register_user
from encryption import hash_password
from authentication import verify_password, login_user


class TestSecurePasswordStorageApp(unittest.TestCase):
    def setUp(self):
        """Set up Flask test client and isolated test storage file."""
        self.test_dir = tempfile.mkdtemp()
        self.test_users_file = os.path.join(self.test_dir, 'test_users.json')

        # Redirect storage to temporary file
        self.original_users_file = storage.USERS_FILE
        storage.USERS_FILE = self.test_users_file

        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        self.client = app.test_client()

        # Initialize demo account in the isolated test storage
        init_demo_account()

    def tearDown(self):
        """Restore original storage and remove temporary directory."""
        storage.USERS_FILE = self.original_users_file
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # TEST 1: Register new user
    def test_01_register_new_user(self):
        response = self.client.post('/register', data={
            'username': 'alice_student',
            'password': 'Password123!',
            'confirm_password': 'Password123!'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Registration successful", response.data)

        # Check storage directly
        creds = storage.load_credentials('alice_student')
        self.assertIsNotNone(creds)
        self.assertIn('salt', creds)
        self.assertIn('hash', creds)

    # TEST 2: Correct password
    def test_02_correct_password(self):
        register_user('bob_user', 'BobSecurePass@2026')
        response = self.client.post('/login', data={
            'username': 'bob_user',
            'password': 'BobSecurePass@2026'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Welcome, bob_user", response.data)
        with self.client.session_transaction() as sess:
            self.assertEqual(sess.get('username'), 'bob_user')
            # Security guarantee: password MUST NEVER be in session
            self.assertNotIn('password', sess)

    # TEST 3: Wrong password
    def test_03_wrong_password(self):
        register_user('charlie_user', 'CharliePass!99')
        response = self.client.post('/login', data={
            'username': 'charlie_user',
            'password': 'WrongPassword123'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Invalid username or password.", response.data)
        with self.client.session_transaction() as sess:
            self.assertNotIn('username', sess)

    # TEST 4: Duplicate username
    def test_04_duplicate_username(self):
        register_user('david_user', 'FirstPassword123')
        response = self.client.post('/register', data={
            'username': 'david_user',
            'password': 'SecondPassword456',
            'confirm_password': 'SecondPassword456'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"User already exists.", response.data)

    # TEST 5: Same password + different salts
    def test_05_same_password_different_salts(self):
        pw = "Hello123"
        salt_a = generate_salt()
        salt_b = generate_salt()
        self.assertNotEqual(salt_a, salt_b, "Salts must be randomly generated and distinct")

        hash_a = hash_password(pw, salt_a)
        hash_b = hash_password(pw, salt_b)
        self.assertEqual(len(hash_a), 64)
        self.assertEqual(len(hash_b), 64)
        self.assertNotEqual(hash_a, hash_b, "Identical password with different salts MUST yield distinct hashes!")

    # TEST 6: Stored credential does not contain plaintext password
    def test_06_stored_credential_no_plaintext_password(self):
        test_user = "eve_crypto"
        raw_pw = "SuperConfidentialPlainText123!"
        register_user(test_user, raw_pw)

        with open(self.test_users_file, 'r', encoding='utf-8') as f:
            data = json.load(f)

        self.assertIn(test_user, data)
        self.assertIn('salt', data[test_user])
        self.assertIn('hash', data[test_user])
        self.assertEqual(len(data[test_user]['salt']), 32)
        self.assertEqual(len(data[test_user]['hash']), 64)

        # Plaintext password must never appear in storage
        self.assertNotIn('password', data[test_user])
        with open(self.test_users_file, 'r', encoding='utf-8') as f:
            raw_content = f.read()
            self.assertNotIn(raw_pw, raw_content)

    # TEST 7: Dashboard requires authentication
    def test_07_dashboard_requires_authentication(self):
        # Unauthenticated request must redirect to /login
        response = self.client.get('/dashboard', follow_redirects=False)
        self.assertIn(response.status_code, (302, 303))
        self.assertIn('/login', response.headers.get('Location', ''))

    # TEST 8: Logout destroys session
    def test_08_logout_destroys_session(self):
        with self.client.session_transaction() as sess:
            sess['username'] = 'logged_in_tester'

        response = self.client.get('/logout', follow_redirects=False)
        self.assertIn(response.status_code, (302, 303))
        self.assertEqual(response.headers.get('Location'), '/')

        with self.client.session_transaction() as sess:
            self.assertNotIn('username', sess)

    # TEST 9: ShopKart demo login succeeds with correct demo credentials
    def test_09_shopkart_demo_login_succeeds(self):
        response = self.client.post('/shopping-demo/login', data={
            'username': 'demo@shopkart.local',
            'password': 'Demo@123'
        }, follow_redirects=False)
        self.assertIn(response.status_code, (302, 303))
        self.assertIn('/shopping-demo/account', response.headers.get('Location', ''))

        # Check session and access protected account page
        with self.client.session_transaction() as sess:
            self.assertEqual(sess.get('shopkart_user'), 'demo@shopkart.local')
            self.assertNotIn('password', sess)

        account_resp = self.client.get('/shopping-demo/account', follow_redirects=True)
        self.assertEqual(account_resp.status_code, 200)
        self.assertIn(b"Welcome to ShopKart!", account_resp.data)
        self.assertIn(b"Demo Login Successful", account_resp.data)

    # TEST 10: ShopKart demo login fails with incorrect credentials
    def test_10_shopkart_demo_login_fails(self):
        response = self.client.post('/shopping-demo/login', data={
            'username': 'demo@shopkart.local',
            'password': 'WrongPassword#999'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Invalid username or password.", response.data)

        # Ensure no session is created
        with self.client.session_transaction() as sess:
            self.assertNotIn('shopkart_user', sess)


if __name__ == '__main__':
    unittest.main(verbosity=2)
