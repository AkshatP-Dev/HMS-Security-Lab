# HMS Security Lab

> **A local, self-contained application-security training environment.**
> All testing runs against `localhost` Docker containers only.
> No external systems are targeted.

A Hospital Management System built in **two states** — intentionally vulnerable and hardened — to demonstrate the complete secure-development lifecycle:

```
INSECURE IMPLEMENTATION  →  SECURITY TESTING  →  IDENTIFY WEAKNESSES
        ↓
SECURE IMPLEMENTATION  →  REGRESSION TESTING  →  VERIFIED REMEDIATION
```

---

## ⚠️ Scope Notice

This project exists exclusively as a **local defensive-security training lab**.

- Ports are bound to `127.0.0.1` only — not exposed to the network.
- No external hosts, third-party APIs, or cloud infrastructure are used.
- The insecure version is a deliberate training target. Do not deploy it publicly.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Project Structure](#project-structure)
- [Application Accounts](#application-accounts)
- [Security Weaknesses Demonstrated](#security-weaknesses-demonstrated)
- [Running the Tests](#running-the-tests)
- [Make Targets](#make-targets)
- [Documentation](#documentation)

---

## Quick Start

### Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (or Docker Engine + Compose plugin)
- Python 3.10+

### 1 — Start both applications

```bash
# Insecure app → http://localhost:5000
make up-insecure

# Hardened app → http://localhost:5001
make up-secure
```

Or without Make:

```bash
docker compose -f docker-compose.insecure.yml up -d --build
docker compose -f docker-compose.secure.yml up -d --build
```

### 2 — Run the security regression suite

```bash
make test
# or manually:
pip install -r tests/requirements.txt
cd tests && pytest -v
```

### 3 — Compare security headers

```bash
make demo-headers
```

### 4 — Stop everything

```bash
make down
```

---

## Project Structure

```
hms-lab/
│
├── app/
│   ├── insecure/               ← INTENTIONALLY VULNERABLE (port 5000)
│   │   ├── app.py              ← 11 labelled weaknesses (VULN-01 … VULN-11)
│   │   ├── templates/
│   │   ├── requirements.txt    ← Flask only (no security libraries)
│   │   └── Dockerfile
│   │
│   └── secure/                 ← HARDENED IMPLEMENTATION (port 5001)
│       ├── app.py              ← 11 labelled fixes (FIX-01 … FIX-11)
│       ├── templates/
│       ├── requirements.txt    ← Flask + bcrypt + Flask-WTF + Limiter + Talisman
│       └── Dockerfile
│
├── tests/
│   ├── conftest.py             ← Shared fixtures; all requests go to localhost
│   ├── test_authentication.py
│   ├── test_authorization.py
│   ├── test_sql_injection.py
│   ├── test_password_storage.py
│   ├── test_csrf.py
│   ├── test_security_headers.py
│   ├── test_rate_limiting.py
│   └── test_session_security.py
│
├── database/
│   └── schema.sql              ← Annotated reference schema
│
├── docker-compose.insecure.yml
├── docker-compose.secure.yml
├── Makefile
├── .env.example
├── .gitignore
│
├── README.md
├── ARCHITECTURE.md
├── THREAT_MODEL.md
├── SECURITY_ASSESSMENT.md
├── TESTING.md
├── RESULTS.md                  ← Fill in after running pytest locally
├── SECURITY.md
└── AUTHORIZATION.md
```

---

## Application Accounts

Seeded in both app versions:

| Username | Password | Role    |
|----------|----------|---------|
| admin    | admin    | admin   |
| drsmith  | password | doctor  |
| alice    | alice123 | patient |
| bob      | bobpass  | patient |

---

## Security Weaknesses Demonstrated

Each weakness is labelled `VULN-xx` in `app/insecure/app.py` and the
corresponding fix is labelled `FIX-xx` in `app/secure/app.py`.

| ID      | Category                        | Insecure pattern                      | Secure fix                          |
|---------|---------------------------------|---------------------------------------|-------------------------------------|
| VULN-01 | Secret management               | `secret_key = "supersecret123"`       | `os.environ["HMS_SECRET_KEY"]`      |
| VULN-02 | Session cookie flags            | No HttpOnly, no SameSite              | HttpOnly=True, SameSite=Lax         |
| VULN-03 | Credential storage              | Unsalted MD5                          | bcrypt (cost factor 12)             |
| VULN-04 | Brute-force protection          | Unlimited login attempts              | Flask-Limiter (10 req/min)          |
| VULN-05 | SQL injection                   | String-concatenated queries           | Parameterized queries (`?`)         |
| VULN-06 | Information disclosure          | `debug=True`, verbose stack traces    | Generic error pages, debug=False    |
| VULN-07 | Insecure Direct Object Ref.     | No ownership check on patient records | Server-side user_id ownership check |
| VULN-08 | Cross-Site Request Forgery      | No token on state-changing forms      | Flask-WTF CSRFProtect               |
| VULN-09 | Broken access control           | Admin panel accessible to any role    | `@roles_required("admin")`          |
| VULN-10 | Missing security headers        | No security response headers          | Flask-Talisman (CSP, X-Frame, etc.) |
| VULN-11 | Debug mode                      | `app.run(debug=True)`                 | FLASK_DEBUG env var, default False  |

---

## Running the Tests

The test suite asserts **security properties**, not just behaviour.

```bash
cd tests
pip install -r requirements.txt
pytest -v
```

### How to read results

| Result   | Meaning                                                                    |
|----------|----------------------------------------------------------------------------|
| `PASSED` | Security property holds in the hardened app                                |
| `XFAIL`  | Vulnerability confirmed present in insecure app (expected — correct)       |
| `XPASS`  | xfail test unexpectedly passed — insecure app was accidentally hardened    |
| `FAILED` | Security property not met — investigate                                    |

Tests against the hardened app should all `PASS`.
Tests against the insecure app should all `XFAIL`.

---

## Make Targets

| Target             | Action                                              |
|--------------------|-----------------------------------------------------|
| `make up-insecure` | Build and start insecure app on :5000               |
| `make up-secure`   | Build and start hardened app on :5001               |
| `make up-both`     | Start both                                          |
| `make down`        | Stop and remove both containers                     |
| `make test`        | Run pytest suite                                    |
| `make test-verbose`| Run pytest and save output to RESULTS_raw.txt       |
| `make demo-headers`| curl both apps and compare security headers         |
| `make demo-sqli`   | Print SQL injection instructions for manual testing |
| `make clean`       | Remove containers, volumes, and local images        |

---

## Documentation

| File                    | Contents                                                  |
|-------------------------|-----------------------------------------------------------|
| ARCHITECTURE.md         | System design, data flow, Docker layout, auth/authz model |
| THREAT_MODEL.md         | Assets, actors, attack surface, per-threat analysis       |
| SECURITY_ASSESSMENT.md  | Per-weakness: insecure pattern → why dangerous → fix      |
| TESTING.md              | Test strategy, methodology, scope, limitations            |
| RESULTS.md              | Fill in after running pytest locally                      |
| SECURITY.md             | Disclosure policy, usage warnings                         |
| AUTHORIZATION.md        | Role model, enforcement layers, decision table            |
