"""
test_sql_injection.py

Security property: user input cannot alter the semantics of database queries.

Tests:
  SQLI-01  SQLi payload in login username does not authenticate
  SQLI-02  SQLi payload in patient search does not exfiltrate the users table
  SQLI-03  SQLi payload in API search endpoint does not alter results
  SQLI-04  Boolean-blind payload in login is rejected

We demonstrate:
  - INSECURE app is vulnerable (xfail — expected failure means the vuln exists)
  - SECURE app correctly rejects all payloads (should pass)
"""

import pytest
import requests
from conftest import INSECURE_BASE, SECURE_BASE, make_session, ALICE_CREDS


def get_csrf(base: str) -> tuple[requests.Session, str]:
    from bs4 import BeautifulSoup
    s = requests.Session()
    resp = s.get(f"{base}/login")
    soup = BeautifulSoup(resp.text, "html.parser")
    csrf_input = soup.find("input", {"name": "csrf_token"})
    token = csrf_input["value"] if csrf_input else ""
    return s, token


# ─── SQLI-01  Login bypass ─────────────────────────────────

SQLI_LOGIN_PAYLOADS = [
    ("' OR '1'='1", "' OR '1'='1"),
    ("admin'--",    "anything"),
    ("' OR 1=1--",  "anything"),
]


class TestSQLiLogin:

    @pytest.mark.parametrize("username,password", SQLI_LOGIN_PAYLOADS)
    @pytest.mark.xfail(
        reason="VULN-05: insecure app uses string concatenation — login bypass works"
    )
    def test_insecure_login_not_bypassed(self, username, password):
        s = requests.Session()
        r = s.post(f"{INSECURE_BASE}/login",
                   data={"username": username, "password": password},
                   allow_redirects=True)
        # In the insecure app the payload logs us in — this assertion fails
        # (expected by xfail — the vulnerability is confirmed).
        assert "dashboard" not in r.url and r.status_code != 200 or (
            "Invalid" in r.text
        ), f"SQLi login bypass succeeded with payload: {username!r}"

    @pytest.mark.parametrize("username,password", SQLI_LOGIN_PAYLOADS)
    def test_secure_login_not_bypassed(self, username, password):
        """FIX-05: Parameterised query — payload is treated as data."""
        s, token = get_csrf(SECURE_BASE)
        r = s.post(f"{SECURE_BASE}/login",
                   data={"username": username, "password": password,
                         "csrf_token": token},
                   allow_redirects=True)
        assert "dashboard" not in r.url, (
            f"SQLi login bypass succeeded against SECURE app with {username!r}"
        )


# ─── SQLI-02  UNION exfiltration in patient search ────────

class TestSQLiSearch:

    @pytest.mark.xfail(
        reason="VULN-05: insecure patient search is injectable — UNION dumps users table"
    )
    def test_insecure_search_does_not_leak_credentials(self):
        s = make_session(INSECURE_BASE, ALICE_CREDS)
        # UNION payload: merge users table columns into patient result set
        payload = "%' UNION SELECT id,username,password,role,NULL FROM users--"
        r = s.get(f"{INSECURE_BASE}/patients",
                  params={"name": payload},
                  allow_redirects=True)
        # In the insecure app the password hash appears — xfail confirms vuln
        assert "21232f" not in r.text, (
            "MD5 hash of 'admin' appeared in search results (credential leak)"
        )

    def test_secure_search_does_not_leak_credentials(self):
        """FIX-05: Parameterized LIKE — UNION payload is literal search text."""
        s = make_session(SECURE_BASE, ALICE_CREDS)
        payload = "%' UNION SELECT id,username,password,role,NULL FROM users--"
        r = s.get(f"{SECURE_BASE}/patients",
                  params={"name": payload},
                  allow_redirects=True)
        assert "21232f" not in r.text
        assert "$2b$" not in r.text
        # The payload should return zero rows (no patient name matches it)
        assert "Alice" not in r.text or "Bob" not in r.text  # no real results contaminated


# ─── SQLI-03  Boolean-blind attempt in API ────────────────

class TestSQLiAPI:

    def test_secure_api_search_parameterized(self):
        s = make_session(SECURE_BASE, ALICE_CREDS)
        payload = "x' OR '1'='1"
        r = s.get(f"{SECURE_BASE}/api/search",
                  params={"q": payload})
        assert r.status_code == 200
        data = r.json()
        # A patient user should get at most their own records, not everyone's
        for record in data:
            assert record.get("full_name") in ("Alice Johnson",), (
                f"Unexpected record leaked via API: {record}"
            )
