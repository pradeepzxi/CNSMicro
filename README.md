# SECURE PASSWORD STORAGE SYSTEM

**Course:** Cryptography and Network Security  
**Course Code:** E1CSA311  
**Institution:** Alliance University — Alliance School of Advanced Computing  

### Project Team Members
1. **Shashidhar Pareet**
2. **Pradeep**
3. **Basavanni B Sanadi**
4. **Manish K A**

---

## 1. Project Objective

The primary objective of this college micro-project is to construct a production-modeled, academic, Python-first credential storage and authentication system based on cryptographic hashing and random salting. The project proves:
- How plaintext passwords are eliminated using **SHA-256** one-way cryptographic hashing.
- How rainbow table precomputations and hash collision vulnerabilities are defeated using **16-byte random salts** (`os.urandom(16)`).
- How zero-knowledge authentication is achieved through dynamic hash re-computation and constant-time comparison (`hmac.compare_digest`).
- How real-world web applications (such as a fictional e-commerce store, **ShopKart**) can seamlessly integrate and reuse the exact same backend cryptographic authentication modules.

---

## 2. Core Features

### Main Secure Password Storage Platform
- **Random Salt Generation:** Every registered user receives a unique 128-bit (16-byte) cryptographically secure pseudorandom salt generated via the operating system CSPRNG (`os.urandom(16)`).
- **SHA-256 Cryptographic Hashing:** Combines `salt + password.encode("utf-8")` to produce a deterministic 64-character hexadecimal digest.
- **Zero Plaintext Storage:** Passwords are never saved, logged, cached, or transmitted in plaintext.
- **Timing-Attack Resistance:** Constant-time verification prevents side-channel analysis.
- **User Enumeration Defense:** Uniform error responses (`"Invalid username or password."`) prevent malicious account discovery.
- **Protected User Dashboard:** Strict server-side Flask session protection (`session["username"]`).
- **Main Cryptography Demo (`/demo`):** "Same Password, Different Salt" laboratory proving identical passwords produce different SHA-256 digests when different salts are applied (`Hash A != Hash B`).
- **Automated Test Dashboard (`/tests`):** Real-time web and CLI test runner executing 10 system assertions across core authentication and e-commerce workflows.

### Fictional Shopping Website Demonstration ("ShopKart")
- **Academic E-Commerce Portal (`/shopping-demo`):** Demonstrates real-world integration of the password storage system on a modern e-commerce storefront.
- **Reuses Same Authentication Subsystem:** ShopKart uses the exact same `registration.py`, `authentication.py`, `encryption.py`, and `storage.py` backend.
- **Pre-Enrolled Academic Demo Account:**
  - **Email:** `demo@shopkart.local`
  - **Password:** `Demo@123`
  - *Security Guarantee:* This password is NOT stored in plaintext. It is enrolled via `register_user()`, saving only its random salt and SHA-256 hash.
- **Protected ShopKart Account Dashboard (`/shopping-demo/account`):** Displays mock orders, wishlist, cart, and account security verification status.
- **Sanitized Credential Visualizer:** Educational representation of stored records (`salt` and `hash` masked as `****************`).

---

## 3. Technology Stack

- **Backend Application Logic:** Python 3.9+
- **Web Framework:** Flask
- **Cryptographic Library:** Python standard library `hashlib` (SHA-256), `os` (`os.urandom`), `hmac` (`compare_digest`)
- **Persistence Layer:** Python standard library `json` file-based storage (`users.json`)
- **Session Management:** Secure HTTP-only Flask sessions
- **Templating Engine:** Jinja2 (HTML5)
- **Styling:** Custom Vanilla CSS3 (Cybersecurity dark theme + E-commerce accent theme, fully responsive)

> **Strict Constraints:** 100% Python-first. No React, Next.js, Node.js, TypeScript, JavaScript cryptography, or external authentication services.

---

## 4. System Architecture

Both the primary portal and the ShopKart e-commerce portal rely on the unified cryptographic engine:

```
                SECURE PASSWORD SYSTEM
                         |
                         v
                   FLASK APPLICATION
                         |
             +-----------+-----------+
             |                       |
             v                       v
        MAIN LOGIN             SHOPKART LOGIN
             |                       |
             +-----------+-----------+
                         |
                         v
                authentication.py
                         |
                         v
                   encryption.py
                         |
                         v
                     storage.py
                         |
                         v
                    users.json
```

### ShopKart Authentication Flow
```
SHOPKART
   ↓
LOGIN FORM
   ↓
FLASK
   ↓
login_user()
   ↓
verify_password()
   ↓
SHA-256 + Stored Salt
   ↓
Compare Hash
   ↓
Account Access
```

---

## 5. Directory & File Structure

```text
secure_password_storage/
│
├── app.py                 # Flask web application & session route controllers
├── encryption.py          # SHA-256 hashing and salt concatenation
├── registration.py        # 16-byte random salt generation & registration logic
├── authentication.py      # Zero-knowledge authentication & constant-time check
├── storage.py             # Atomic read/write operations for users.json
├── config.py              # Cryptographic constants and session settings
├── requirements.txt       # Python dependencies (Flask, pytest)
├── users.json             # Persistent JSON credential storage
├── test_app.py            # Automated Flask unit and integration test suite
├── test_prototype.py      # Core cryptographic & storage test suite
├── README.md              # Project documentation
│
├── templates/             # Jinja2 HTML5 templates
│   ├── base.html          # Global layout, navbar, alert banners, and footer
│   ├── index.html         # Homepage with features and flow visualizer
│   ├── register.html      # Registration form with Python validation
│   ├── login.html         # Login form with enumeration prevention
│   ├── dashboard.html     # Protected dashboard with stored salt/hash proof
│   ├── security.html      # Comprehensive theoretical security guide (7 topics)
│   ├── demo.html          # Main crypto demo ("Same Password, Different Salt")
│   ├── shopping_demo.html # Fictional ShopKart login & catalog page
│   ├── shopping_account.html # Protected ShopKart customer account page
│   └── tests.html         # Live web test runner dashboard
│
└── static/
    └── css/
        └── style.css      # Cybersecurity dark theme & ShopKart e-commerce styling
```

---

## 6. Cryptographic Implementation Details

### Registration Protocol
1. User provides `username` and `password`.
2. Server verifies username does not already exist.
3. Server executes `os.urandom(16)` to obtain a 16-byte random salt.
4. Server computes `data = salt + password.encode("utf-8")`.
5. Server generates `password_hash = hashlib.sha256(data).hexdigest()`.
6. Stored in `users.json`:
   ```json
   {
       "username": {
           "salt": "32-hexadecimal-salt-characters",
           "hash": "64-hexadecimal-sha256-hash-characters"
       }
   }
   ```

### Verification Protocol
1. User submits `username` and `candidate_password`.
2. Server loads record from `users.json`. If missing, returns failure.
3. Server retrieves hexadecimal salt and decodes to bytes via `bytes.fromhex(salt_hex)`.
4. Server generates `candidate_hash = hashlib.sha256(salt_bytes + candidate_password.encode("utf-8")).hexdigest()`.
5. Server compares hashes using `hmac.compare_digest(candidate_hash, stored_hash)`.
6. Returns success or uniform error: `"Invalid username or password."`

---

## 7. Installation & Running Locally

### 1. Prerequisites
- Python 3.9 or higher
- pip package manager

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Start the Flask Server
```bash
python app.py
```

Open your browser and navigate to:  
👉 **http://127.0.0.1:5000**

---

## 8. Automated Test Execution

### Run CLI Tests
```bash
# Run web route and ShopKart integration tests
python test_app.py

# Run standalone cryptographic prototype tests
python test_prototype.py
```

### Run Web Tests
Open `http://127.0.0.1:5000/tests` to execute and inspect the 10 system test cases directly in the browser:
- **TEST 1:** Register new user
- **TEST 2:** Correct password
- **TEST 3:** Wrong password
- **TEST 4:** Duplicate username
- **TEST 5:** Same password + different salts
- **TEST 6:** Stored credential does not contain plaintext password
- **TEST 7:** Dashboard requires authentication
- **TEST 8:** Logout destroys session
- **TEST 9:** ShopKart demo login succeeds with correct demo credentials
- **TEST 10:** ShopKart demo login fails with incorrect credentials

---

## 9. Viva Presentation Flow (Step-by-Step Guide)

Follow this sequence during project viva examination:

1. **STEP 1 — Homepage (`/`):**  
   Open `http://127.0.0.1:5000/`. Explain: *"This project demonstrates secure password storage using hashing and salting."* Highlight the cryptographic pipeline.
2. **STEP 2 — Registration (`/register`):**  
   Create a new account (e.g. `pradeep`, password `AlliancePass2026!`). Explain: *"The password is never stored directly."*
3. **STEP 3 — Storage Inspection (`users.json`):**  
   Open `users.json`. Show the newly created record containing `username`, `salt` (32 hex chars), and `hash` (64 hex chars). Explain: *"The original password does not appear here."*
4. **STEP 4 — Successful Login (`/login`):**  
   Enter correct credentials. Observe successful redirect to `/dashboard` showing authentication cards and proof of salt/hash storage.
5. **STEP 5 — Failed Login (`/login`):**  
   Log out, then enter an incorrect password. Observe uniform message: `"Invalid username or password."`
6. **STEP 6 — Cryptography Demonstration (`/demo`):**  
   Open `/demo`. Test the "Same Password, Different Salt" feature using password `Hello123`. Observe `Hash A != Hash B` proving collision resistance and rainbow table defense.
7. **STEP 7 — Real-World ShopKart Integration (`/shopping-demo`):**  
   Navigate to `/shopping-demo`. Explain: *"Now I will demonstrate how the same authentication system can be used in a real-world application."*
8. **STEP 8 — Enter Demo Credentials:**  
   Enter `demo@shopkart.local` and password `Demo@123`. Click Login.
9. **STEP 9 — ShopKart Account Dashboard (`/shopping-demo/account`):**  
   Show the account page with orders, wishlist, cart, and account security status. Explain: *"The ShopKart page is fictional. Its login uses the same Python authentication modules as our main application."*
10. **STEP 10 — Test Wrong ShopKart Password:**  
    Log out of ShopKart and enter a wrong password for `demo@shopkart.local`. Observe generic failure message: `"Invalid username or password."`
11. **STEP 11 — Automated Test Suite (`/tests`):**  
    Open `/tests`. Show all 10 tests executing real Python logic with 100% PASS badges.

---

## 10. Production Security Note

> **Academic Security Note:**  
> This project uses **SHA-256 with random salting** because it follows the cryptographic method specified in the micro-project. In production password-storage systems, a password-specific key derivation function such as **Argon2id**, **scrypt**, **bcrypt**, or **PBKDF2** would normally be preferred.
