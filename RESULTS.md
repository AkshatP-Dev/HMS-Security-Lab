# Test Results

> **All results in this file require local verification.**
> The automated test suite must be run against live Docker containers on your
> machine.  No results have been fabricated or pre-filled.

---

## How to Fill This File

After running `pytest -v` from the `tests/` directory, paste the output below
under "Raw pytest output."  Then complete the summary table.

```bash
cd tests
pip install -r requirements.txt
pytest -v 2>&1 | tee ../RESULTS_raw.txt
```

---

## Expected Summary (to be verified)

| Test file                   | Tests | Expected PASS | Expected XFAIL | Expected FAIL |
|-----------------------------|-------|---------------|----------------|---------------|
| test_authentication.py      | 9     | 9             | 0              | 0             |
| test_authorization.py       | 7     | 5             | 2              | 0             |
| test_sql_injection.py       | 7     | 4             | 3              | 0             |
| test_password_storage.py    | 7     | 5             | 1              | 0             |
| test_csrf.py                | 4     | 3             | 1              | 0             |
| test_security_headers.py    | 7     | 4             | 3              | 0             |
| test_rate_limiting.py       | 2     | 1             | 1              | 0             |
| test_session_security.py    | 7     | 5             | 2              | 0             |
| **Total**                   | **50**| **36**        | **13**         | **0**         |

**XFAIL** = vulnerability confirmed present in insecure app (correct behaviour)  
**XPASS** = test marked xfail unexpectedly passed (investigate — insecure app may have been accidentally hardened)

---

## Raw pytest Output

```
REQUIRES LOCAL VERIFICATION

Paste the output of:
    pytest -v 2>&1
here after running on your machine.
```

---

## Secure App Header Verification

Run manually:
```bash
curl -si http://localhost:5001/login | grep -i "content-security\|x-frame\|x-content\|referrer"
```

Expected output:
```
REQUIRES LOCAL VERIFICATION
```

---

## Insecure App SQL Injection — Manual Verification

1. Open http://localhost:5000 and log in as `alice / alice123`
2. Navigate to http://localhost:5000/patients
3. In the search box enter:
   ```
   %' UNION SELECT id,username,password,role,NULL FROM users--
   ```
4. Observe: MD5 password hashes from the users table appear in the patient results.

**Status:** REQUIRES LOCAL VERIFICATION

---

## Hardened App SQL Injection — Manual Verification

1. Open http://localhost:5001 and log in as `alice / alice123`
2. Navigate to http://localhost:5001/patients
3. Enter the same payload as above.
4. Expected: zero results (the payload is treated as a literal search string,
   not SQL).

**Status:** REQUIRES LOCAL VERIFICATION

---

## Rate Limit — Manual Verification

```bash
for i in $(seq 1 15); do
  curl -si -X POST http://localhost:5001/login \
    -d "username=alice&password=wrong" | head -1
done
```

Expected: first 10 lines show `HTTP/1.1 200 OK`; lines 11-15 show
`HTTP/1.1 429 TOO MANY REQUESTS`.

**Status:** REQUIRES LOCAL VERIFICATION
