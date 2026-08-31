# Test Results

**Status: run and verified.** The figures below were produced by executing the
suite against both live applications, not estimated. Re-running is the point —
see "How to reproduce" at the bottom, and expect the same numbers.

- **Run date:** 29 August 2026
- **Result:** `40 passed, 13 xfailed in 4.98s`
- **Failures:** 0
- **Unexpected passes (XPASS):** 0
- **Environment:** Python 3.11.15, pytest 8.2.2, both apps served on
  127.0.0.1:5000 and :5001, login rate limit raised to `20 per minute` per
  [TESTING.md](TESTING.md#rate-limiting-and-the-test-suite)

**XFAIL** means a weakness was confirmed present in the insecure build — that
is the intended outcome, not a problem. **XPASS** would mean a weakness has
silently disappeared from the training target; the SQL-injection and search
xfails are marked `strict=True` so that would fail the run rather than pass
quietly.

---

## Summary by test file

| Test file                   | Tests | PASS | XFAIL | FAIL |
|-----------------------------|-------|------|-------|------|
| test_authentication.py      | 11    | 11   | 0     | 0    |
| test_authorization.py       | 8     | 6    | 2     | 0    |
| test_csrf.py                | 4     | 3    | 1     | 0    |
| test_password_storage.py    | 7     | 6    | 1     | 0    |
| test_rate_limiting.py       | 2     | 1    | 1     | 0    |
| test_security_headers.py    | 7     | 4    | 3     | 0    |
| test_session_security.py    | 5     | 3    | 2     | 0    |
| test_sql_injection.py       | 9     | 6    | 3     | 0    |
| **Total**                   | **53**| **40**| **13**| **0**|

---

## Raw pytest output

```
test_authentication.py ...........                                       [ 20%]
test_authorization.py x..x....                                           [ 35%]
test_csrf.py ...x                                                        [ 43%]
test_password_storage.py x......                                         [ 56%]
test_security_headers.py ....xxx                                         [ 69%]
test_session_security.py ..xx.                                           [ 79%]
test_sql_injection.py xx....x..                                          [ 96%]
test_rate_limiting.py .x                                                 [100%]

======================== 40 passed, 13 xfailed in 4.98s ========================
```

Note the ordering: `test_rate_limiting.py` runs last, not in its alphabetical
position. Verifying the login limiter means exhausting it, and anything that
logged in afterwards would get a 429 and fail for a reason unrelated to what it
asserts. `conftest.pytest_collection_modifyitems` enforces this.

---

## Exploit-and-retest evidence

Each weakness was exercised by hand against the insecure build and the same
request repeated against the hardened build. Captured 29 Aug 2026.

### VULN-05 / FIX-05 — SQL injection

Login bypass, `POST /login`:

| Payload (username) | Insecure app | Hardened app |
|---|---|---|
| `admin'--` | **authenticated** | rejected |
| `' OR 1=1--` | **authenticated** | rejected |
| `' OR '1'='1` | rejected | rejected |

The third row is the interesting one, and it is deliberate. The concatenated
query is `... WHERE username='<u>' AND password='<md5>'`. `AND` binds tighter
than `OR`, so `' OR '1'='1` parses as
`username='' OR ('1'='1' AND password='<md5>')` — the password condition still
has to hold. The injection is real; that particular payload just does not
exploit it. The two that do work delete the password test entirely with a
comment. Asserted explicitly in
`test_insecure_login_survives_ineffective_payload`.

UNION exfiltration, `GET /patients?name=`:

```
%' UNION SELECT id,username,password,role,NULL,NULL FROM users--
```

| | Result |
|---|---|
| Insecure app | admin MD5 `0192023a7bbd73250516f069df18b500` **rendered in the results table** |
| Hardened app | no hash present; zero rows returned — the payload is literal search text |

The UNION arm projects six columns because `patients` has six. A five-column
payload makes SQLite reject the statement outright, which looks exactly like a
working defence — a false negative worth knowing about.

### VULN-07 / FIX-07 — IDOR

`GET /patient/2` as **alice** (who owns patient 1, not 2):

| | Status | Bob's record visible |
|---|---|---|
| Insecure app | `200` | yes — "Bob Williams" rendered |
| Hardened app | `403` | no |

### VULN-09 / FIX-09 — Broken access control

`GET /admin`:

| | alice (patient) | admin |
|---|---|---|
| Insecure app | `200` | `200` |
| Hardened app | `403` | `200` |

### VULN-08 / FIX-08 — CSRF

`POST /patient/1/update` with no CSRF token:

| | Status |
|---|---|
| Insecure app | `302` — update accepted |
| Hardened app | `400` — rejected by Flask-WTF |

### VULN-03 / FIX-03 — Credential storage

Read directly from each database:

```
insecure                                     hardened
admin    0192023a7bbd73250516f069df18b500    admin    $2b$12$...
drsmith  5f4dcc3b5aa765d61d8327deb882cf99    drsmith  $2b$12$...
alice    7abdccbea8473767e91378e37850d296    alice    $2b$12$...
bob      6a3c7c6166b4ffcf922329d0e821003b    bob      $2b$12$...
```

All four hardened hashes carry the `$2b$12$` prefix — **bcrypt, cost factor
12**, asserted by `test_secure_bcrypt_cost_factor_is_12` rather than merely
inferred from the `$2b$` prefix. All four insecure hashes are 32-character
unsalted MD5 of known plaintexts and resolve instantly by lookup.

### VULN-10 / FIX-10 — Security headers

`curl -sI http://localhost:5001/login`:

```
Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline';
                         script-src 'self'; img-src 'self' data:;
                         frame-ancestors 'none'
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Permissions-Policy: browsing-topics=()
Set-Cookie: session=...; HttpOnly; Path=/; SameSite=Lax
```

The same request against the insecure app on port 5000 returns **none** of
these headers, and its cookie carries no `HttpOnly` or `SameSite` flag.

`Secure` is absent from the hardened cookie because this lab runs over plain
HTTP; it is driven by the `HTTPS` environment variable and is set whenever the
app runs behind TLS. See the note above the Talisman configuration in
`app/secure/app.py` — Talisman otherwise forces `Secure` on regardless of
`force_https`, which silently breaks every session on an HTTP-only deployment.

---

## What these results do and do not establish

**They establish** that each of the eleven weaknesses is present in the
insecure build, that each corresponding control is present and effective in the
hardened build, and that the difference is verifiable by a suite someone else
can re-run.

**They do not establish** anything about weaknesses this lab does not model.
[OWASP_MAPPING.md](OWASP_MAPPING.md) lists the Top 10 categories with no
coverage here, and [TESTING.md](TESTING.md) lists the classes of test the suite
deliberately does not attempt — XSS execution, TLS configuration, SSRF, path
traversal, dependency scanning.

---

## How to reproduce

```bash
# Start both apps in test configuration, then run the suite
make test-up
make test
```

To reproduce the run above without Docker, serve both apps directly and point
the suite at them:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r app/secure/requirements.txt -r tests/requirements.txt
mkdir -p /tmp/hms

HMS_DB_PATH=/tmp/hms/insecure.db python app/insecure/app.py &
HMS_DB_PATH=/tmp/hms/secure.db HMS_SECRET_KEY=dev-only \
  HMS_LOGIN_RATE_LIMIT="20 per minute" python app/secure/app.py &

cd tests
HMS_INSECURE_DB=/tmp/hms/insecure.db \
HMS_SECURE_DB=/tmp/hms/secure.db \
HMS_LOGIN_RATE_LIMIT="20 per minute" pytest -v
```

If the credential-storage tests **skip**, neither database route was available:
set `HMS_INSECURE_DB` / `HMS_SECURE_DB`, or run under Docker so
`docker exec ... sqlite3` can reach them. They skip rather than fail so the
rest of the suite still reports.
