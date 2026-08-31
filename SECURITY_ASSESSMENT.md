# Security Assessment

This document provides a detailed per-weakness analysis for the HMS training
lab.  Each entry follows the structure:

1. What the insecure pattern is
2. Why it is dangerous
3. How the secure implementation differs
4. Why the mitigation works
5. Which test verifies it

---

## VULN-01 — Hardcoded Secret Key

**Insecure pattern:**
```python
app.secret_key = "supersecret123"
```

**Why dangerous:**  
Flask uses the secret key to sign session cookies with HMAC-SHA1.  If the key
is in source code it is visible in every commit, every container image, and
every developer's machine.  Anyone who knows the key can forge a session cookie
claiming to be any user — without a password.

**Secure fix:**
```python
app.secret_key = os.environ.get("HMS_SECRET_KEY") or os.urandom(32)
```
In production the environment variable is set to the output of
`openssl rand -hex 32`.  The `os.urandom(32)` fallback generates a random key
per container restart (suitable for development — sessions don't persist across
restarts).

**Why it works:**  
An attacker reading the source code finds only `os.environ.get(...)` — the
actual key is never in the codebase.  Without the key, forging a valid HMAC
signature requires 2^128 guesses (computationally infeasible).

**Test:** `test_session_security.py` → all session tests rely on a valid key;
`test_password_storage.py::test_secure_admin_page_never_shows_password_hash`
confirms the session is working correctly for an admin user.

---

## VULN-02 — Insecure Session Cookie Flags

**Insecure pattern:**
```python
SESSION_COOKIE_HTTPONLY = False
SESSION_COOKIE_SAMESITE = None
```

**Why dangerous:**  
Without `HttpOnly`, any JavaScript running on the page (including injected by
an XSS payload) can read `document.cookie` and exfiltrate the session token.
Without `SameSite`, the browser will include the session cookie on cross-site
POST requests, enabling CSRF.

**Secure fix:**
```python
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
```

**Why it works:**  
`HttpOnly` is enforced by the browser: `document.cookie` does not include
HttpOnly cookies.  `SameSite=Lax` means the cookie is only sent when the top-
level navigation originates from the same site (or for safe GET requests).
Cross-site POST forms — the classic CSRF vector — do not include the cookie.

**Tests:** `test_session_security.py::TestSecureSessionCookies`

---

## VULN-03 — MD5 Password Hashing

**Insecure pattern:**
```python
import hashlib
md5pw = hashlib.md5(password.encode()).hexdigest()
```

**Why dangerous:**  
MD5 was designed for speed.  A modern GPU can compute ~10 billion MD5 hashes
per second.  There is no salt, so identical passwords produce identical hashes
— an attacker can use a precomputed rainbow table to crack every account in
seconds.  The admin password `admin123` → `0192023a7bbd73250516f069df18b500` is
in every public hash database.

**Secure fix:**
```python
import bcrypt
hashed = bcrypt.hashpw(plaintext.encode(), bcrypt.gensalt(rounds=12))
# Verification:
bcrypt.checkpw(submitted.encode(), stored_hash.encode())
```

**Why it works:**  
bcrypt's design is deliberately slow (cost factor 12 ≈ 250 ms/guess on a
modern CPU).  Each call to `gensalt()` generates a random 128-bit salt embedded
in the hash string, defeating precomputed tables.  bcrypt's `checkpw` runs in
constant time, eliminating timing side-channels.

**Tests:** `test_password_storage.py`

---

## VULN-04 — No Login Rate Limiting

**Insecure pattern:** No constraint on how many times `/login` can be called.

**Why dangerous:**  
An attacker can automate password guessing indefinitely — trying a leaked
password list or the top 1000 common passwords in under a second.

**Secure fix:**
```python
@limiter.limit("10 per minute")
def login():
    ...
```

**Why it works:**  
Flask-Limiter tracks requests by IP address.  After 10 attempts within any
60-second window, subsequent requests receive 429 Too Many Requests until the
window resets.  This limits an attacker to 10 guesses/minute per IP — making
brute-force impractical against strong passwords.

**Tests:** `test_rate_limiting.py`

---

## VULN-05 — SQL Injection

**Insecure pattern:**
```python
query = "SELECT * FROM users WHERE username='" + username + "'"
db.execute(query)
```

**Why dangerous:**  
If `username` is `' OR '1'='1`, the resulting query returns all users.
If `username` is `admin'--`, the password check is commented out and any
password grants admin access.  In search fields, `UNION SELECT` can dump
arbitrary tables.

**Secure fix:**
```python
db.execute("SELECT * FROM users WHERE username=?", (username,))
```

**Why it works:**  
The `?` placeholder tells the SQLite driver to pass the value as a parameter
separately from the query structure.  The driver handles quoting and escaping
at the protocol level.  No matter what `username` contains, it is always
treated as a literal string value — the query structure cannot be altered.

**Tests:** `test_sql_injection.py`

---

## VULN-06 — Verbose Error Messages

**Insecure pattern:** `debug=True` causes Flask to render Python stack traces
in the browser on any unhandled exception.

**Why dangerous:**  
Stack traces reveal file paths, library versions, variable names, and
sometimes data values.  This information helps an attacker understand the
application's internals and craft more effective attacks.

**Secure fix:** `debug=False`; custom error handlers return generic messages:
```python
@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404,
                           message="The page was not found."), 404
```

**Why it works:**  
The attacker receives no information about the application internals.  Internal
errors are still logged server-side (visible via `docker logs`) for debugging.

---

## VULN-07 — Insecure Direct Object Reference (IDOR)

**Insecure pattern:**
```python
@app.route("/patient/<int:patient_id>")
def patient_detail(patient_id):
    # No ownership check — any user reads any record
    patient = db.execute("SELECT * FROM patients WHERE id=?", (patient_id,)).fetchone()
    return render_template("patient_detail.html", patient=patient)
```

**Why dangerous:**  
By incrementing the URL integer (e.g., `/patient/1` → `/patient/2`) any
authenticated user reads any other patient's sensitive medical records.

**Secure fix:**
```python
if session["role"] == "patient" and patient["user_id"] != session["user_id"]:
    abort(403)
```

**Why it works:**  
Server-side ownership verification compares the record's stored `user_id`
against the session's authenticated `user_id`.  The session cannot be
manipulated by the client (it is HMAC-signed).  Doctors and admins are
explicitly permitted by the role check.

**Tests:** `test_authorization.py::TestIDOR`

---

## VULN-08 — Missing CSRF Protection

**Insecure pattern:**  
State-changing POST forms carry no token; any cross-site form submission
succeeds.

**Why dangerous:**  
A malicious page visited by a logged-in user can silently submit a form to
`/patient/1/update`, modifying medical notes without the user's knowledge.

**Secure fix:**  
`CSRFProtect(app)` from Flask-WTF is applied globally.  Every form template
includes `{{ form.hidden_tag() }}`.  Flask-WTF validates the token on every
POST, PUT, PATCH, and DELETE request.

**Why it works:**  
The CSRF token is a random value tied to the user's session.  A cross-site
attacker cannot read it (same-origin policy) and cannot forge a request that
passes validation.

**Tests:** `test_csrf.py`

---

## VULN-09 — Broken Access Control (Admin Panel)

**Insecure pattern:**
```python
@app.route("/admin")
def admin():
    if "user_id" not in session:
        return redirect(url_for("login"))
    # ← No role check; any authenticated user proceeds
```

**Why dangerous:**  
Any patient can navigate to `/admin`, see all user accounts, and in the
insecure version see their MD5 password hashes.

**Secure fix:**
```python
@app.route("/admin")
@roles_required("admin")
def admin():
    ...
```
The `roles_required` decorator reads `session["role"]` (set at login, stored
server-side in the signed cookie) and returns 403 if the role is not in the
allowed set.

**Why it works:**  
The role is stored in the session by the server at login time; the client
cannot alter it without forging the HMAC signature.

**Tests:** `test_authorization.py::TestAdminAccess`

---

## VULN-10 — Missing Security Headers

**Insecure pattern:** No response headers beyond Flask defaults.

**Why dangerous:**
- No CSP → XSS payloads can load scripts from any domain.
- No X-Frame-Options → clickjacking possible.
- No X-Content-Type-Options → browser MIME-sniffing can misexecute uploaded files.

**Secure fix:** Flask-Talisman adds on every response:
```
Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; ...
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN (implied by CSP frame-ancestors)
Referrer-Policy: no-referrer
```

**Why it works:**  
These headers are browser-enforced policies.  CSP tells the browser to reject
scripts not originating from `'self'`, dramatically limiting XSS impact.

**Tests:** `test_security_headers.py`

---

## VULN-11 — Debug Mode in Production

**Insecure pattern:** `app.run(debug=True)`

**Why dangerous:**  
In debug mode Flask enables the Werkzeug interactive debugger, which executes
arbitrary Python in the browser via a PIN-protected REPL.  If an attacker
obtains the PIN (derivable from server metadata) they have full code execution.

**Secure fix:** `debug=False` unconditionally; controlled by env var for
development only:
```python
debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
```
