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
a success. The SQL-injection xfails are therefore marked `strict=True`, which
turns an xpass into a hard failure rather than a line of green output nobody
reads.

---

## Rate limiting and the test suite

The hardened app limits login POSTs to **10 per minute** in its shipped
configuration. The suite performs more than ten logins in a minute, so running
it against that threshold means every test after the tenth login fails with a
429 — for a reason that has nothing to do with what it is asserting. That is
worse than not testing at all, because the failures look like security
regressions.

Three things resolve it, and none of them weakens the control:

1. **The limit is configuration, not a constant.** `HMS_LOGIN_RATE_LIMIT`
   defaults to `10 per minute`; `make test-up` starts the same image with
   `20 per minute`. There is no code path that disables the limiter — this is a
   configuration seam, not a test-only backdoor.
2. **The test reads the same value.** `test_rate_limiting` derives its
   threshold from `HMS_LOGIN_RATE_LIMIT` and overshoots by three, so the
   limiter is verified against whatever the app is genuinely running with
   rather than a number hardcoded in the test.
3. **The rate-limit tests run last.** Verifying the limiter means exhausting
   it. `conftest.pytest_collection_modifyitems` moves those tests to the end of
   the run so nothing else logs in afterwards. pytest would otherwise collect
   `test_rate_limiting.py` alphabetically, in the middle.

Only POST is limited. `GET /login` renders the form and does not consume a
password guess, so throttling it punishes page reloads without slowing an
attacker down — and makes the control untestable, since every test must fetch a
CSRF token first.

The general limits (`5000/day`, `500/hour` per IP) are deliberately loose. A
per-IP cap tight enough to be a security control would also break every
legitimate user behind a corporate NAT or carrier gateway, where hundreds of
people share one address. The general limit dampens abuse; the login limit is
the security control.

---

## Reading the credential-storage tests

Those tests read the SQLite database directly rather than an HTTP response,
because what the control is *about* is what gets written to disk.
`conftest.query_db()` tries two routes in order — a local path in
`HMS_INSECURE_DB` / `HMS_SECURE_DB`, then `docker exec <container> sqlite3`
(both Dockerfiles install the CLI for this). If neither is available the tests
**skip** with an explanatory message rather than erroring, so the rest of the
suite still reports.

A skip here is not a pass. If you need those assertions, provide one of the two
routes.

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
