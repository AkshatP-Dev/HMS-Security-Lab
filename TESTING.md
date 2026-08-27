# Testing Methodology

## Approach

This lab uses **property-based security testing**: each test asserts that a
specific security property either holds or is intentionally absent.  Tests are
not checking for specific CVE numbers or tool output — they are checking
whether the application behaves securely under adversarial input.

---

## Test Types

### Positive tests (must PASS on secure app)
Confirm that the hardened implementation satisfies the security requirement:
- Unauthorised requests are rejected (401/403/302)
- Ownership checks block cross-user access
- Rate limiter returns 429 on excess attempts
- Security headers are present

### Expected-failure tests (xfail on insecure app)
Confirm that the vulnerability is genuinely present in the training target:
```python
@pytest.mark.xfail(reason="VULN-05: insecure app uses string concatenation")
def test_insecure_not_injectable(self):
    ...
```
An `xfail` that unexpectedly **passes** (`xpass`) would mean the vulnerability
was accidentally fixed in the insecure app — that is a configuration error, not
a success.

---

## Test Scope

All tests run against `http://localhost:5000` (insecure) and
`http://localhost:5001` (secure).  No external hosts are contacted.
The test process is a Python `requests` client running on the same machine as
the Docker containers.

---

## Running the Tests

```bash
# From repo root — both containers must be running
cd tests
pip install -r requirements.txt
pytest -v
```

**Verbose output with xfail details:**
```bash
pytest -v --tb=short
```

**Single test file:**
```bash
pytest test_sql_injection.py -v
```

**Single test:**
```bash
pytest test_authorization.py::TestIDOR::test_secure_alice_cannot_read_bob -v
```

---

## Test File Map

| File                          | Security property tested            |
|-------------------------------|-------------------------------------|
| `test_authentication.py`      | Login/logout, unauthenticated block |
| `test_authorization.py`       | IDOR, role-based admin access       |
| `test_sql_injection.py`       | SQL injection in login and search   |
| `test_password_storage.py`    | Hash algorithm, salt, UI exposure   |
| `test_csrf.py`                | CSRF token validation               |
| `test_security_headers.py`    | HTTP security response headers      |
| `test_rate_limiting.py`       | Login brute-force rate limit        |
| `test_session_security.py`    | Cookie flags, logout invalidation   |

---

## Expected Results Summary

On the **secure** app, all non-xfail tests must PASS.

On the **insecure** app:
- xfail tests should `xfail` (expected failure — confirms vulnerability)
- If any xfail test `xpass` (unexpectedly passes), the insecure app was
  accidentally hardened — investigate before proceeding.

---

## Limitations and Honesty

The following are explicitly NOT tested by this suite because they require
specialised tools or cannot be meaningfully automated with `requests`:

- **XSS execution** — would require a headless browser (Playwright/Selenium)
- **TLS configuration** — the lab runs HTTP; add Certbot + nginx in production
- **SSRF / path traversal** — not present in the current feature set
- **Dependency vulnerability scanning** — use `pip-audit` or Dependabot

These are noted so that the scope of the test suite is honest.  Passing all
tests here does **not** mean the application is production-ready — it means
the eleven documented training weaknesses have been remediated.
