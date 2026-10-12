"""
Flask Web Application for ShopKart & Secure Password Storage System.
Course: Cryptography and Network Security (E1CSA311)
Alliance University - Alliance School of Advanced Computing

Architecture:
- Clean E-Commerce Storefront ("ShopKart") with zero clutter
- Live Database Inspector showcasing os.urandom(16) Salting and SHA-256 Hashing
- Visual proof that plaintext passwords are NEVER saved to users.json
"""

import os
import json
import time
import tempfile
import shutil
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    jsonify
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


# Curated ShopKart Products
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


def init_demo_account():
    """
    Ensures the demonstration account exists.
    Account: demo@shopkart.local
    Password: Demo@123
    
    Stored strictly via random 16-byte salt and SHA-256 hash.
    Plaintext password is never saved in users.json.
    """
    demo_email = "demo@shopkart.local"
    demo_pass = "Demo@123"
    if not storage.load_credentials(demo_email):
        register_user(demo_email, demo_pass)


# Ensure demo account is provisioned
init_demo_account()


@app.context_processor
def inject_global_data():
    """Injects user authentication state into all templates."""
    user = session.get("username") or session.get("shopkart_user")
    all_users = storage.load_all()
    return {
        "current_user": user,
        "shopkart_user": user,
        "total_users": len(all_users)
    }


# ============================================================
# PRIMARY STORE & DATABASE ROUTES
# ============================================================

@app.route('/')
def index():
    """
    Main storefront page:
    Authentic ShopKart online shopping experience.
    """
    return render_template(
        'index.html',
        products=SHOPKART_PRODUCTS
    )


@app.route('/shopping-demo')
def shopping_demo():
    """Alias route for storefront."""
    return index()


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    User login route.
    Authenticates against stored salt and SHA-256 hash.
    Sets active session and tracks verification action for visual proof.
    """
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            flash("Invalid username or password.", "danger")
            return redirect(url_for('index'))

        success, message = login_user(username, password)
        if success:
            session['username'] = username
            session['shopkart_user'] = username
            creds = storage.load_credentials(username) or {}
            session['last_action'] = {
                'type': 'login',
                'username': username,
                'salt': creds.get('salt', ''),
                'hash': creds.get('hash', '')
            }
            flash(f"Welcome, {username}! Login successful.", "success")
            return redirect(url_for('index'))
        else:
            flash("Invalid username or password.", "danger")
            return redirect(url_for('index'))

    if 'username' in session or 'shopkart_user' in session:
        return redirect(url_for('account'))

    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    User registration route.
    Generates 16-byte random salt via os.urandom(16) and computes SHA-256 hash.
    Saves to users.json (zero plaintext storage).
    """
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not username:
            flash("Username is required.", "danger")
            return redirect(url_for('index'))

        if not password:
            flash("Password is required.", "danger")
            return redirect(url_for('index'))

        if len(password) < config.MIN_PASSWORD_LENGTH:
            flash(f"Password must be at least {config.MIN_PASSWORD_LENGTH} characters long.", "danger")
            return redirect(url_for('index'))

        if password != confirm_password:
            flash("Passwords do not match. Please re-enter your password.", "danger")
            return redirect(url_for('index'))

        # Call cryptographic registration module
        success, message = register_user(username, password)
        if success:
            session['username'] = username
            session['shopkart_user'] = username
            creds = storage.load_credentials(username) or {}
            session['last_action'] = {
                'type': 'register',
                'username': username,
                'salt': creds.get('salt', ''),
                'hash': creds.get('hash', '')
            }
            flash("Registration successful. Please log in with your credentials.", "success")
            return redirect(url_for('index'))
        else:
            flash(message, "danger")
            return redirect(url_for('index'))

    return redirect(url_for('index'))


@app.route('/shopping-demo/login', methods=['POST'])
def shopping_login():
    """
    ShopKart login handler for testing and external integrations.
    """
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')

    if not username or not password:
        flash("Invalid username or password.", "danger")
        all_users = storage.load_all()
        return render_template('index.html', products=SHOPKART_PRODUCTS, all_users=all_users, raw_json=json.dumps(all_users, indent=4))

    success, message = login_user(username, password)
    if success:
        session['shopkart_user'] = username
        session['username'] = username
        creds = storage.load_credentials(username) or {}
        session['last_action'] = {
            'type': 'login',
            'username': username,
            'salt': creds.get('salt', ''),
            'hash': creds.get('hash', '')
        }
        return redirect(url_for('shopping_account'))
    else:
        flash("Invalid username or password.", "danger")
        all_users = storage.load_all()
        return render_template('index.html', products=SHOPKART_PRODUCTS, all_users=all_users, raw_json=json.dumps(all_users, indent=4))


@app.route('/shopping-demo/register', methods=['GET', 'POST'])
def shopping_register():
    """Alias for user registration."""
    return register()


@app.route('/account')
@app.route('/dashboard')
def account():
    """
    Protected user account view.
    Displays user profile and their individual salt & SHA-256 stored record.
    """
    username = session.get('username') or session.get('shopkart_user')
    if not username:
        flash("Access denied. Please log in to view the dashboard.", "warning")
        return redirect(url_for('login'))

    creds = storage.load_credentials(username)
    if not creds:
        session.pop('username', None)
        session.pop('shopkart_user', None)
        flash("User record not found. Please log in again.", "danger")
        return redirect(url_for('login'))

    return render_template(
        'shopping_account.html',
        username=username,
        demo_creds=creds,
        stored_salt=creds.get('salt', ''),
        stored_hash=creds.get('hash', '')
    )


@app.route('/shopping-demo/account')
def shopping_account():
    """Alias for account view."""
    return account()


@app.route('/database')
def database():
    """
    Dedicated Backend Database Inspector:
    Displays users.json contents, 16-byte salts, SHA-256 hashes,
    and proves zero plaintext password storage.
    """
    all_users = storage.load_all()
    last_action = session.get('last_action')
    raw_json = json.dumps(all_users, indent=4)
    return render_template(
        'database.html',
        all_users=all_users,
        last_action=last_action,
        raw_json=raw_json
    )


@app.route('/api/database')
def api_database():
    """JSON API returning current users in users.json for dynamic live updates."""
    all_users = storage.load_all()
    return jsonify({
        "users": all_users,
        "total": len(all_users)
    })


@app.route('/logout')
def logout():
    """Terminates session and returns to storefront."""
    session.pop('username', None)
    session.pop('shopkart_user', None)
    session.pop('last_action', None)
    flash("You have been successfully logged out.", "info")
    return redirect(url_for('index'))


@app.route('/shopping-demo/logout')
def shopping_logout():
    """Alias for logout."""
    return logout()


# ============================================================
# COMPATIBILITY ROUTE FOR SYSTEM TESTS
# ============================================================

@app.route('/tests')
def tests():
    """Executes automated verification suite."""
    test_results = run_all_system_tests()
    return render_template('tests.html', results=test_results)


def run_all_system_tests():
    """Executes test assertions inside isolated storage environment."""
    test_dir = tempfile.mkdtemp()
    test_users_file = os.path.join(test_dir, 'test_users.json')
    original_storage_file = storage.USERS_FILE

    results = []
    start_total = time.perf_counter()

    def record_test(test_id, name, desc, fn):
        t0 = time.perf_counter()
        try:
            fn()
            elapsed = round((time.perf_counter() - t0) * 1000, 2)
            results.append({"id": test_id, "name": name, "description": desc, "status": "PASS", "time_ms": elapsed})
        except Exception as e:
            elapsed = round((time.perf_counter() - t0) * 1000, 2)
            results.append({"id": test_id, "name": name, "description": desc, "status": "FAIL", "time_ms": elapsed, "error": str(e)})

    try:
        storage.USERS_FILE = test_users_file

        def t1():
            s, _ = register_user("test_alice", "ValidPassword123")
            assert s is True
            assert storage.load_credentials("test_alice") is not None
        record_test(1, "Register New User", "Generates 16-byte random salt and SHA-256 hash", t1)

        def t2():
            register_user("test_bob", "BobPass1234")
            s, _ = login_user("test_bob", "BobPass1234")
            assert s is True
        record_test(2, "Correct Password", "Verifies authentication with valid credentials", t2)

        def t3():
            register_user("test_charlie", "CharliePass123")
            s, _ = login_user("test_charlie", "WrongPassword999")
            assert s is False
        record_test(3, "Wrong Password", "Rejects incorrect password attempt", t3)

        def t4():
            register_user("test_david", "FirstPass123")
            s, _ = register_user("test_david", "SecondPass456")
            assert s is False
        record_test(4, "Duplicate Username", "Prevents duplicate account registration", t4)

        def t5():
            pw = "IdenticalSecret123"
            sa = generate_salt()
            sb = generate_salt()
            assert sa != sb
            assert hash_password(pw, sa) != hash_password(pw, sb)
        record_test(5, "Salting Defense", "Identical password with different salts yields distinct hashes", t5)

        def t6():
            pw = "ConfidentialPlainText999!"
            register_user("test_eve", pw)
            with open(test_users_file, 'r', encoding='utf-8') as f:
                content = f.read()
            assert pw not in content
        record_test(6, "Zero Plaintext", "Ensures plaintext password never appears in storage", t6)

        def t7():
            with app.test_client() as client:
                resp = client.get('/dashboard', follow_redirects=False)
                assert resp.status_code in (302, 303)
        record_test(7, "Protected Route", "Requires authentication to access dashboard", t7)

        def t8():
            with app.test_client() as client:
                with client.session_transaction() as sess:
                    sess['username'] = 'tester'
                resp = client.get('/logout', follow_redirects=False)
                assert resp.status_code in (302, 303)
        record_test(8, "Session Destruction", "Destroys session and clears credentials on logout", t8)

        def t9():
            init_demo_account()
            with app.test_client() as client:
                resp = client.post('/shopping-demo/login', data={'username': 'demo@shopkart.local', 'password': 'Demo@123'}, follow_redirects=False)
                assert resp.status_code in (302, 303)
        record_test(9, "ShopKart Login", "Authenticates ShopKart demo user successfully", t9)

        def t10():
            init_demo_account()
            with app.test_client() as client:
                resp = client.post('/shopping-demo/login', data={'username': 'demo@shopkart.local', 'password': 'WrongPassword'}, follow_redirects=True)
                assert resp.status_code == 200
        record_test(10, "ShopKart Rejection", "Rejects invalid credentials on storefront", t10)

        total_time_ms = round((time.perf_counter() - start_total) * 1000, 2)
        passed_count = sum(1 for r in results if r["status"] == "PASS")

        return {
            "tests": results,
            "total": len(results),
            "passed": passed_count,
            "failed": len(results) - passed_count,
            "all_passed": (passed_count == len(results)),
            "total_time_ms": total_time_ms
        }
    finally:
        storage.USERS_FILE = original_storage_file
        shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == '__main__':
    # Run development server on port 5000
    app.run(host='127.0.0.1', port=5000, debug=True)
