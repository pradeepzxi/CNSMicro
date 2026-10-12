"""
Flask Web Application for Secure Password Storage System.
Course: Cryptography and Network Security (E1CSA311)
Alliance University - Alliance School of Advanced Computing

Team Members:
1. Shashidhar Pareet
2. Pradeep
3. Basavanni B Sanadi
4. Manish K A

Includes:
- Main Secure Password Storage System & Cryptographic Laboratory
- Fictional E-Commerce Demonstration ("ShopKart") reusing the exact same Python authentication core
"""

import os
import time
import tempfile
import shutil
import unittest
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash
)

import config
from encryption import hash_password
from registration import register_user, generate_salt
from authentication import login_user, verify_password
import storage

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

# Security headers and cookie configuration
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)


def init_demo_account():
    """
    Ensures the fictional ShopKart academic demonstration account exists.
    Account: demo@shopkart.local
    Password: Demo@123
    
    IMPORTANT:
    The password is NOT hardcoded or stored in plaintext in users.json.
    It is registered through the standard register_user() function, which
    generates a random 16-byte salt and SHA-256 hash.
    """
    demo_email = "demo@shopkart.local"
    demo_pass = "Demo@123"
    if not storage.load_credentials(demo_email):
        register_user(demo_email, demo_pass)


# Global context processor


@app.context_processor
def inject_global_data():
    """Injects university and project metadata into all templates."""
    return {
        "project_title": "SECURE PASSWORD STORAGE SYSTEM",
        "course_title": "Cryptography and Network Security",
        "course_code": "E1CSA311",
        "university": "Alliance University",
        "school": "Alliance School of Advanced Computing",
        "team_members": [
            "Shashidhar Pareet",
            "Pradeep",
            "Basavanni B Sanadi",
            "Manish K A"
        ],
        "academic_note": (
            "Academic implementation: This project uses SHA-256 with random salting "
            "because it follows the cryptographic method specified in the micro-project. "
            "In production password-storage systems, a password-specific key derivation "
            "function such as Argon2id, scrypt, bcrypt or PBKDF2 would normally be preferred."
        ),
        "current_user": session.get("username"),
        "shopkart_user": session.get("shopkart_user")
    }


# ============================================================
# MAIN SECUREPASS APPLICATION ROUTES
# ============================================================

@app.route('/')
def index():
    """Home page displaying project overview, live credential inspector, real-world demo promo, and cryptographic flow."""
    all_users = storage.load_all()
    latest_username = next(iter(all_users)) if all_users else None
    latest_creds = all_users.get(latest_username) if latest_username else None
    return render_template(
        'index.html',
        latest_username=latest_username,
        latest_creds=latest_creds,
        all_users=all_users
    )


@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    User registration route.
    Validates user input in Python, invokes register_user(),
    and prevents duplicate registrations.
    """
    if 'username' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        # Server-side validation in Python
        if not username:
            flash("Username is required.", "danger")
            return render_template('register.html', username=username)

        if not password:
            flash("Password is required.", "danger")
            return render_template('register.html', username=username)

        if len(password) < config.MIN_PASSWORD_LENGTH:
            flash(f"Password must be at least {config.MIN_PASSWORD_LENGTH} characters long.", "danger")
            return render_template('register.html', username=username)

        if password != confirm_password:
            flash("Passwords do not match. Please re-enter your password.", "danger")
            return render_template('register.html', username=username)

        # Call registration module
        success, message = register_user(username, password)
        if success:
            flash("Registration successful. Please log in with your credentials.", "success")
            return redirect(url_for('login'))
        else:
            flash(message, "danger")
            return render_template('register.html', username=username)

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    User login route.
    Authenticates user using stored salt + SHA-256 hash.
    On success: sets session['username'].
    On failure: returns generic 'Invalid username or password.' error.
    """
    if 'username' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            flash("Invalid username or password.", "danger")
            return render_template('login.html', username=username)

        success, message = login_user(username, password)
        if success:
            session['username'] = username
            flash(f"Login successful. Welcome, {username}!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password.", "danger")
            return render_template('login.html', username=username)

    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    """
    Protected user dashboard route.
    Requires active session. Shows credential metadata (never plaintext password).
    """
    if 'username' not in session:
        flash("Access denied. Please log in to view the dashboard.", "warning")
        return redirect(url_for('login'))

    username = session['username']
    credentials = storage.load_credentials(username)

    if not credentials:
        session.pop('username', None)
        flash("User record not found. Please log in again.", "danger")
        return redirect(url_for('login'))

    stored_salt = credentials.get("salt", "")
    stored_hash = credentials.get("hash", "")

    return render_template(
        'dashboard.html',
        username=username,
        stored_salt=stored_salt,
        stored_hash=stored_hash
    )


@app.route('/security')
def security():
    """Educational security page explaining salting, SHA-256, workflows, and unified architecture."""
    return render_template('security.html')


@app.route('/demo', methods=['GET', 'POST'])
def demo():
    """
    Main Cryptography Demonstration page ("Same Password, Different Salt").
    Demonstrates in real-time how identical passwords produce completely
    different 64-character SHA-256 hashes when salted with different 16-byte random values.
    Also provides a verification check simulation.
    All execution happens in pure Python.
    """
    # Default demonstration values
    sample_password = "Hello123"
    verify_test_password = sample_password

    if request.method == 'POST':
        sample_password = request.form.get('test_password', '').strip() or sample_password
        verify_test_password = request.form.get('verify_password', '').strip() or sample_password

    # Generate two independent random 16-byte salts
    salt_a_bytes = generate_salt()
    salt_b_bytes = generate_salt()

    salt_a_hex = salt_a_bytes.hex()
    salt_b_hex = salt_b_bytes.hex()

    # Compute SHA-256 hashes using the two different salts for the same password
    hash_a = hash_password(sample_password, salt_a_bytes)
    hash_b = hash_password(sample_password, salt_b_bytes)

    hashes_are_different = (hash_a != hash_b)

    # Verification demonstration against Salt A and Hash A
    computed_verify_hash = hash_password(verify_test_password, salt_a_bytes)
    is_match = (computed_verify_hash == hash_a)

    return render_template(
        'demo.html',
        sample_password=sample_password,
        verify_test_password=verify_test_password,
        salt_a_hex=salt_a_hex,
        salt_b_hex=salt_b_hex,
        hash_a=hash_a,
        hash_b=hash_b,
        hashes_are_different=hashes_are_different,
        computed_verify_hash=computed_verify_hash,
        is_match=is_match
    )


@app.route('/logout')
def logout():
    """Terminates session and redirects to home page."""
    session.pop('username', None)
    flash("You have been successfully logged out.", "info")
    return redirect(url_for('index'))


# ============================================================
# FICTIONAL SHOPPING WEBSITE DEMONSTRATION ("SHOPKART")
# ============================================================

# Fictional products for academic display
SHOPKART_PRODUCTS = [
    {
        "id": 1,
        "name": "Wireless Noise-Canceling Headphones",
        "category": "Audio",
        "price": "$79.99",
        "original_price": "$129.99",
        "badge": "Hot Deal"
    },
    {
        "id": 2,
        "name": "Mechanical Gaming Keyboard RGB",
        "category": "Peripherals",
        "price": "$119.99",
        "original_price": "$159.99",
        "badge": "Popular"
    },
    {
        "id": 3,
        "name": "Fitness Smart Watch & Heart Tracker",
        "category": "Wearables",
        "price": "$149.99",
        "original_price": "$199.99",
        "badge": "Best Seller"
    },
    {
        "id": 4,
        "name": "Ergonomic Water-Resistant Laptop Backpack",
        "category": "Accessories",
        "price": "$49.99",
        "original_price": "$69.99",
        "badge": "Sale"
    }
]


@app.route('/shopping-demo')
def shopping_demo():
    """
    ShopKart e-commerce portal home and login page.
    Demonstrates academic integration of the backend authentication system into an online store.
    """
    all_users = storage.load_all()
    return render_template(
        'shopping_demo.html',
        products=SHOPKART_PRODUCTS,
        all_users=all_users
    )


@app.route('/shopping-demo/login', methods=['POST'])
def shopping_login():
    """
    ShopKart login authentication handler.
    Strictly reuses authentication.py login_user(username, password)
    without separate auth logic.
    """
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')

    if not username or not password:
        flash("Invalid username or password.", "shopkart_danger")
        return redirect(url_for('shopping_demo'))

    # Reuses the exact same Python authentication module
    success, message = login_user(username, password)

    if success:
        session['shopkart_user'] = username
        return redirect(url_for('shopping_account'))
    else:
        # Uniform failure message to prevent username enumeration
        flash("Invalid username or password.", "shopkart_danger")
        return redirect(url_for('shopping_demo'))


@app.route('/shopping-demo/register', methods=['GET', 'POST'])
def shopping_register():
    """
    ShopKart e-commerce account creation route.
    Styled cleanly like Flipkart/Amazon sign-up, reusing register_user() from registration.py.
    """
    if 'shopkart_user' in session:
        return redirect(url_for('shopping_account'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        # Server-side validation in Python
        if not username:
            flash("Username / Email is required.", "shopkart_danger")
            return render_template('shopping_register.html', username=username)

        if not password:
            flash("Password is required.", "shopkart_danger")
            return render_template('shopping_register.html', username=username)

        if len(password) < config.MIN_PASSWORD_LENGTH:
            flash(f"Password must be at least {config.MIN_PASSWORD_LENGTH} characters long.", "shopkart_danger")
            return render_template('shopping_register.html', username=username)

        if password != confirm_password:
            flash("Passwords do not match. Please re-enter your password.", "shopkart_danger")
            return render_template('shopping_register.html', username=username)

        # Reuses core registration module
        success, message = register_user(username, password)
        if success:
            flash("ShopKart account created successfully! Please login with your credentials.", "shopkart_success")
            return redirect(url_for('shopping_demo'))
        else:
            flash(message, "shopkart_danger")
            return render_template('shopping_register.html', username=username)

    return render_template('shopping_register.html')


@app.route('/shopping-demo/account')
def shopping_account():
    """
    ShopKart user account dashboard.
    Protected route: accessible only when session['shopkart_user'] is active.
    """
    if 'shopkart_user' not in session:
        flash("Please log in to your ShopKart account.", "shopkart_warning")
        return redirect(url_for('shopping_demo'))

    username = session['shopkart_user']
    demo_creds = storage.load_credentials(username)

    return render_template(
        'shopping_account.html',
        username=username,
        demo_creds=demo_creds
    )


@app.route('/shopping-demo/logout')
def shopping_logout():
    """Logs out the user from ShopKart session."""
    session.pop('shopkart_user', None)
    flash("You have successfully logged out of ShopKart.", "shopkart_info")
    return redirect(url_for('shopping_demo'))


# ============================================================
# AUTOMATED TEST RUNNER (FOR /tests WEB DASHBOARD)
# ============================================================

@app.route('/tests')
def tests():
    """
    Runs the comprehensive automated test suite in Python and displays
    the results in the web interface.
    """
    test_results = run_all_system_tests()
    return render_template('tests.html', results=test_results)


def run_all_system_tests():
    """
    Executes all 10 required system test cases directly using real Python logic
    inside an isolated temporary storage environment so production users.json
    is never polluted with test records:
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
    results = []
    start_total = time.perf_counter()

    # Isolate storage in a temporary directory during automated tests
    test_dir = tempfile.mkdtemp()
    test_storage_file = os.path.join(test_dir, 'suite_test_users.json')
    original_storage_file = storage.USERS_FILE
    storage.USERS_FILE = test_storage_file

    try:
        def record_test(test_num, name, description, test_func):
            t0 = time.perf_counter()
            status = "FAIL"
            details = ""
            try:
                test_func()
                status = "PASS"
                details = "All assertions passed successfully."
            except AssertionError as ae:
                status = "FAIL"
                details = f"Assertion Failed: {str(ae)}"
            except Exception as e:
                status = "FAIL"
                details = f"Unexpected Error: {type(e).__name__} - {str(e)}"
            duration_ms = round((time.perf_counter() - t0) * 1000, 2)
            results.append({
                "id": test_num,
                "name": name,
                "description": description,
                "status": status,
                "duration_ms": duration_ms,
                "details": details
            })

        # TEST 1: Register new user
        def t1():
            unique_user = f"suite_user_{int(time.time() * 1000)}"
            success, msg = register_user(unique_user, "ValidPass123!")
            assert success is True, f"Registration failed: {msg}"
            assert msg == "Registration successful."
            creds = storage.load_credentials(unique_user)
            assert creds is not None, "Credential record was not saved"
        record_test(1, "Register New User", "Executes register_user() with valid credentials and confirms persistence", t1)

        # TEST 2: Correct password
        def t2():
            test_user = f"auth_ok_{int(time.time() * 1000)}"
            pw = "CorrectSecret99#"
            register_user(test_user, pw)
            assert verify_password(test_user, pw) is True, "verify_password returned False for correct password"
            success, msg = login_user(test_user, pw)
            assert success is True and msg == "Login successful.", "login_user failed for correct credentials"
        record_test(2, "Correct Password Verification", "Validates that login_user() and verify_password() authenticate valid credentials", t2)

        # TEST 3: Wrong password
        def t3():
            test_user = f"auth_err_{int(time.time() * 1000)}"
            register_user(test_user, "RealSecretPass123")
            assert verify_password(test_user, "IncorrectGuess") is False, "verify_password accepted wrong password"
            success, msg = login_user(test_user, "IncorrectGuess")
            assert success is False, "login_user succeeded with wrong password"
            assert msg == "Invalid username or password.", f"Unexpected error message: {msg}"
        record_test(3, "Wrong Password Rejection", "Ensures incorrect password is rejected with generic error message", t3)

        # TEST 4: Duplicate username
        def t4():
            test_user = f"dup_check_{int(time.time() * 1000)}"
            s1, _ = register_user(test_user, "FirstPass123")
            assert s1 is True
            s2, msg2 = register_user(test_user, "SecondPass456")
            assert s2 is False, "Duplicate registration was accepted"
            assert msg2 == "User already exists.", f"Wrong duplicate message: {msg2}"
        record_test(4, "Duplicate Username Check", "Verifies the system rejects registering an existing username", t4)

        # TEST 5: Same password + different salts
        def t5():
            pw = "SamePasswordAcrossAllUsers"
            salt_a = generate_salt()
            salt_b = generate_salt()
            hash_a = hash_password(pw, salt_a)
            hash_b = hash_password(pw, salt_b)
            assert salt_a != salt_b, "Salts are identical"
            assert hash_a != hash_b, "Identical password with different salts produced identical hash"
            assert len(hash_a) == 64 and len(hash_b) == 64, "SHA-256 digest length is not 64 hex characters"
        record_test(5, "Same Password, Different Salts", "Confirms that different salts produce distinct SHA-256 hashes for the same password", t5)

        # TEST 6: Stored credential does not contain plaintext password
        def t6():
            test_user = f"leak_check_{int(time.time() * 1000)}"
            secret_plaintext = "ConfidentialPlainTextPass#123"
            register_user(test_user, secret_plaintext)
            creds = storage.load_credentials(test_user)
            assert "password" not in creds, "Plaintext key 'password' found in credentials!"
            assert "salt" in creds and "hash" in creds
            raw_storage = storage.load_all()
            import json
            dumped = json.dumps(raw_storage)
            assert secret_plaintext not in dumped, "Plaintext password string found inside stored JSON!"
        record_test(6, "No Plaintext Password in Storage", "Asserts users.json contains only salt and hash, never the plaintext password", t6)

        # TEST 7: Dashboard requires authentication
        def t7():
            with app.test_client() as client:
                resp = client.get('/dashboard', follow_redirects=False)
                assert resp.status_code in (302, 303), f"Expected redirect, got status {resp.status_code}"
                assert '/login' in resp.headers.get('Location', ''), "Did not redirect to /login"
        record_test(7, "Dashboard Protected Route", "Guarantees unauthenticated access to /dashboard is blocked and redirected", t7)

        # TEST 8: Logout destroys session
        def t8():
            with app.test_client() as client:
                with client.session_transaction() as sess:
                    sess['username'] = 'active_user'
                resp = client.get('/logout', follow_redirects=False)
                assert resp.status_code in (302, 303), "Logout did not redirect"
                with client.session_transaction() as sess:
                    assert 'username' not in sess, "Session was not destroyed upon logout"
        record_test(8, "Logout Session Invalidation", "Verifies /logout clears user session and redirects to home page", t8)

        # TEST 9: ShopKart demo login succeeds with correct demo credentials
        def t9():
            init_demo_account()
            with app.test_client() as client:
                resp = client.post('/shopping-demo/login', data={
                    'username': 'demo@shopkart.local',
                    'password': 'Demo@123'
                }, follow_redirects=False)
                assert resp.status_code in (302, 303), "ShopKart login did not redirect"
                assert '/shopping-demo/account' in resp.headers.get('Location', '')
                with client.session_transaction() as sess:
                    assert sess.get('shopkart_user') == 'demo@shopkart.local'
        record_test(9, "ShopKart Demo Login (Success)", "Confirms demo@shopkart.local authenticates successfully via core auth module", t9)

        # TEST 10: ShopKart demo login fails with incorrect credentials
        def t10():
            init_demo_account()
            with app.test_client() as client:
                resp = client.post('/shopping-demo/login', data={
                    'username': 'demo@shopkart.local',
                    'password': 'WrongShopPassword!99'
                }, follow_redirects=True)
                assert resp.status_code == 200
                assert b"Invalid username or password." in resp.data
                with client.session_transaction() as sess:
                    assert 'shopkart_user' not in sess
        record_test(10, "ShopKart Demo Login (Failure)", "Ensures wrong password on ShopKart fails with uniform error and no session created", t10)

        total_time_ms = round((time.perf_counter() - start_total) * 1000, 2)
        passed_count = sum(1 for r in results if r["status"] == "PASS")
        total_count = len(results)

        return {
            "tests": results,
            "total": total_count,
            "passed": passed_count,
            "failed": total_count - passed_count,
            "all_passed": (passed_count == total_count),
            "total_time_ms": total_time_ms
        }
    finally:
        storage.USERS_FILE = original_storage_file
        shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == '__main__':
    # Run development server on port 5000
    app.run(host='127.0.0.1', port=5000, debug=True)
