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

import hashlib

import pytest
import requests
from conftest import (
    INSECURE_BASE, SECURE_BASE, make_session, ALICE_CREDS, ADMIN_CREDS,
)

# The insecure build stores unsalted MD5, so this is exactly what a successful
# UNION exfiltration puts on the page.
ADMIN_MD5 = hashlib.md5(ADMIN_CREDS["password"].encode()).hexdigest()


def get_csrf(base: str) -> tuple[requests.Session, str]:
    from bs4 import BeautifulSoup
    s = requests.Session()
    resp = s.get(f"{base}/login")
    soup = BeautifulSoup(resp.text, "html.parser")
    csrf_input = soup.find("input", {"name": "csrf_token"})
    token = csrf_input["value"] if csrf_input else ""
    return s, token


# ─── SQLI-01  Login bypass ─────────────────────────────────

# Payloads that genuinely authenticate against the concatenated query
#     SELECT * FROM users WHERE username='<u>' AND password='<md5>'
# Both work by commenting the password test out of the statement entirely.
SQLI_BYPASS_PAYLOADS = [
    ("admin'--",   "anything"),
    ("' OR 1=1--", "anything"),
]

# A payload that alters the query but does NOT authenticate. Kept deliberately,
# because the distinction is the actual lesson:
#     username = ' OR '1'='1
#     SELECT * FROM users WHERE username='' OR '1'='1' AND password='<md5>'
# SQL's AND binds tighter than OR, so this parses as
#     username='' OR ('1'='1' AND password='<md5>')
# and the password condition still has to hold. The injection is real — the
# attacker controls the query structure — but this particular payload does not
# exploit it. "The query changed" and "I got in" are different claims.
SQLI_INEFFECTIVE_PAYLOADS = [
    ("' OR '1'='1", "' OR '1'='1"),
]

ALL_SQLI_PAYLOADS = SQLI_BYPASS_PAYLOADS + SQLI_INEFFECTIVE_PAYLOADS


def _is_authenticated(response) -> bool:
    """True if the response indicates a logged-in session."""
    return "/dashboard" in response.url


class TestSQLiLogin:

    @pytest.mark.parametrize("username,password", SQLI_BYPASS_PAYLOADS)
    @pytest.mark.xfail(
        strict=True,
        reason="VULN-05: insecure app concatenates SQL — these payloads bypass login",
    )
    def test_insecure_login_not_bypassed(self, username, password):
        """Expected to FAIL against the insecure build — that failure is the finding.

        strict=True matters: if this ever XPASSes, the bypass has stopped
        working and the training target is no longer demonstrating VULN-05.
        That should break the run, not pass quietly.
        """
        s = requests.Session()
        r = s.post(f"{INSECURE_BASE}/login",
                   data={"username": username, "password": password},
                   allow_redirects=True)
        assert not _is_authenticated(r), (
            f"SQLi login bypass succeeded with payload: {username!r}"
        )

    @pytest.mark.parametrize("username,password", SQLI_INEFFECTIVE_PAYLOADS)
    def test_insecure_login_survives_ineffective_payload(self, username, password):
        """Even the vulnerable build rejects `' OR '1'='1` — operator precedence.

        This test PASSES against the insecure app, and it exists so the suite
        records why: AND binds tighter than OR, so the password condition is
        still evaluated. Without it, the best-known payload in the world would
        sit in this file looking like a working exploit that merely failed.
        """
        s = requests.Session()
        r = s.post(f"{INSECURE_BASE}/login",
                   data={"username": username, "password": password},
                   allow_redirects=True)
        assert not _is_authenticated(r), (
            "`' OR '1'='1` unexpectedly authenticated — the query shape must "
            "have changed; re-check the precedence note in insecure/app.py VULN-05."
        )

    @pytest.mark.parametrize("username,password", ALL_SQLI_PAYLOADS)
    def test_secure_login_not_bypassed(self, username, password):
        """FIX-05: Parameterised query — every payload is treated as data."""
        s, token = get_csrf(SECURE_BASE)
        r = s.post(f"{SECURE_BASE}/login",
                   data={"username": username, "password": password,
                         "csrf_token": token},
                   allow_redirects=True)
        assert not _is_authenticated(r), (
            f"SQLi login bypass succeeded against SECURE app with {username!r}"
        )


# ─── SQLI-02  UNION exfiltration in patient search ────────

class TestSQLiSearch:

    @pytest.mark.xfail(
        strict=True,
        reason="VULN-05: insecure patient search is injectable — UNION dumps users table",
    )
    def test_insecure_search_does_not_leak_credentials(self):
        """Expected to FAIL: the UNION payload pulls the users table into the view."""
        s = make_session(INSECURE_BASE, ALICE_CREDS)
        # patients has six columns (id, user_id, full_name, dob, diagnosis, notes),
        # so the UNION arm must project six as well or SQLite rejects the
        # statement outright and no data is returned — a column-count mismatch
        # looks exactly like a working defence.
        payload = "%' UNION SELECT id,username,password,role,NULL,NULL FROM users--"
        r = s.get(f"{INSECURE_BASE}/patients",
                  params={"name": payload},
                  allow_redirects=True)
        assert ADMIN_MD5 not in r.text, (
            "Admin password hash appeared in search results (credential leak)"
        )

    def test_secure_search_does_not_leak_credentials(self):
        """FIX-05: Parameterised LIKE — the UNION payload is literal search text."""
        s = make_session(SECURE_BASE, ALICE_CREDS)
        # patients has six columns (id, user_id, full_name, dob, diagnosis, notes),
        # so the UNION arm must project six as well or SQLite rejects the
        # statement outright and no data is returned — a column-count mismatch
        # looks exactly like a working defence.
        payload = "%' UNION SELECT id,username,password,role,NULL,NULL FROM users--"
        r = s.get(f"{SECURE_BASE}/patients",
                  params={"name": payload},
                  allow_redirects=True)
        assert r.status_code == 200, (
            f"Search page unreachable ({r.status_code}) — the assertions below "
            f"would pass vacuously."
        )
        assert ADMIN_MD5 not in r.text
        assert "$2b$" not in r.text
        # The payload is now just a search string, and no patient name contains
        # it — so the result set must be empty, not merely hash-free.
        assert "Alice Johnson" not in r.text and "Bob Williams" not in r.text, (
            "Parameterised search returned patient rows for a payload that "
            "matches no name — the parameter may not be bound as data."
        )


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
