# Architecture

## Overview

The lab contains two independent Flask web applications sharing the same
feature set but differing in their security posture. Both run in Docker
containers on `localhost` only.

```
┌─────────────────────────────────────────────────────────┐
│                    Developer machine                    │
│                                                         │
│  Browser ──► localhost:5000 ──► hms_insecure container │
│                                  │                      │
│                                  └── /data/hms_insecure.db (SQLite)
│                                                         │
│  Browser ──► localhost:5001 ──► hms_secure container   │
│                                  │                      │
│                                  └── /data/hms_secure.db   (SQLite)
│                                                         │
│  pytest  ──► localhost:5000 / :5001 (HTTP only)        │
└─────────────────────────────────────────────────────────┘
```

No external DNS lookups, no third-party APIs, no cloud services.

---

## Frontend

Plain HTML templates rendered server-side by Jinja2.  There is no SPA
framework.  Forms use standard HTML POST.  The insecure templates contain no
CSRF tokens.  The secure templates embed `{{ form.hidden_tag() }}` on every
state-changing form — this renders a hidden `<input>` carrying the CSRF token.

---

## Backend

**Framework:** Flask 3.0 (Python 3.11)

**Insecure app libraries:** Flask only.

**Secure app additional libraries:**

| Library        | Purpose                                     |
|----------------|---------------------------------------------|
| Flask-WTF      | CSRF token generation and validation        |
| Flask-Limiter  | Per-IP request rate limiting                |
| Flask-Talisman | Automatic security response headers         |
| WTForms        | Form validation (length, charset, pattern)  |
| bcrypt         | Password hashing with adaptive cost factor  |

---

## Database

SQLite (file at `/data/hms_<variant>.db` inside the container).  Persisted
via a named Docker volume so data survives container restarts.

**Tables:**

```
users (id, username, password, role)
patients (id, user_id, full_name, dob, diagnosis, notes)
appointments (id, patient_id, doctor_id, date, reason)
```

The `password` column stores either:
- Insecure: 32-character lowercase hex string (MD5, no salt)
- Secure: bcrypt hash string beginning with `$2b$12$`

---

## Authentication

**Insecure:** string-concatenated SQL query with MD5 comparison.

**Secure:** parameterized query retrieves the user row; `bcrypt.checkpw()`
performs a constant-time comparison of the submitted password against the
stored hash.  After a successful login, `session.clear()` prevents session
fixation, then the user's `id`, `username`, and `role` are stored in the
Flask session (a signed, encrypted client-side cookie).

---

## Authorization

See [AUTHORIZATION.md](AUTHORIZATION.md) for the full role model.

**Insecure:** no role checks after initial login gate.

**Secure:** two decorators in `app.py`:

- `@login_required` — redirects to `/login` if no session.
- `@roles_required("admin")` — aborts with 403 unless `session["role"]`
  matches one of the given roles.

Patient-record access adds an ownership check:
```python
if session["role"] == "patient" and patient["user_id"] != session["user_id"]:
    abort(403)
```

---

## Sessions

Flask stores sessions in a signed cookie on the client.  Tampering with the
cookie value invalidates the signature (using HMAC-SHA1 with the secret key).

**Insecure session config:**
```python
SECRET_KEY          = "supersecret123"   # hardcoded
COOKIE_SECURE       = False
COOKIE_HTTPONLY     = False
COOKIE_SAMESITE     = None
```

**Secure session config:**
```python
SECRET_KEY          = os.environ["HMS_SECRET_KEY"]   # 32-byte random hex
COOKIE_HTTPONLY     = True
COOKIE_SAMESITE     = "Lax"
COOKIE_SECURE       = True  (set False for local HTTP testing)
```

---

## Docker

Each app variant has its own `Dockerfile` and named Docker Compose file.

The containers expose their ports bound to `127.0.0.1` only:
```yaml
ports:
  - "127.0.0.1:5000:5000"   # insecure — localhost only
  - "127.0.0.1:5001:5001"   # secure — localhost only
```

This means even if the host firewall is misconfigured the ports are not
reachable from other machines on the network.

---

## Data Flow — Login Request (Secure App)

```
Browser                Flask                         SQLite
  │                      │                              │
  │──POST /login ────────►│                              │
  │  (form + CSRF token)  │                              │
  │                       │─ validate CSRF token ────────│
  │                       │─ validate form fields ───────│
  │                       │─ rate-limit check ───────────│
  │                       │─ SELECT * WHERE username=? ─►│
  │                       │◄──────────── user row ───────│
  │                       │─ bcrypt.checkpw() ───────────│
  │                       │─ session.clear() ────────────│
  │                       │─ session["user_id"] = id ────│
  │◄─ 302 /dashboard ─────│                              │
```
