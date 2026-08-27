"""
test_session_security.py

Security property: session cookies are configured to resist hijacking,
XSS theft, and cross-site submission.

Tests:
  SESS-01  Session cookie has HttpOnly flag set (secure app)
  SESS-02  Session cookie has SameSite=Lax or Strict (secure app)
  SESS-03  Secure app does NOT expose session cookie to JavaScript (HttpOnly)
  SESS-04  Insecure app is missing HttpOnly (xfail — vuln confirmed)
  SESS-05  Insecure app is missing SameSite (xfail — vuln confirmed)
  SESS-06  Logout clears the session (both apps)

Cookie flag anatomy:
  HttpOnly — browser hides the cookie from document.cookie; XSS cannot steal it.
  SameSite=Lax — cookie not sent on cross-site POST requests; CSRF mitigation.
  Secure — cookie only sent over HTTPS (not tested here — running plain HTTP in lab).
"""

import pytest
import requests
from bs4 import BeautifulSoup
from conftest import INSECURE_BASE, SECURE_BASE, ALICE_CREDS


def login_and_get_session_cookie(base: str) -> requests.cookies.RequestsCookieJar:
    s = requests.Session()
    resp = s.get(f"{base}/login")
    soup = BeautifulSoup(resp.text, "html.parser")
    csrf_input = soup.find("input", {"name": "csrf_token"})
    data = dict(ALICE_CREDS)
    if csrf_input:
        data["csrf_token"] = csrf_input["value"]
    s.post(f"{base}/login", data=data, allow_redirects=True)
    return s.cookies


def get_set_cookie_header(base: str) -> str:
    """Return the raw Set-Cookie header value after login."""
    s = requests.Session()
    resp = s.get(f"{base}/login")
    soup = BeautifulSoup(resp.text, "html.parser")
    csrf_input = soup.find("input", {"name": "csrf_token"})
    data = dict(ALICE_CREDS)
    if csrf_input:
        data["csrf_token"] = csrf_input["value"]
    r = s.post(f"{base}/login", data=data, allow_redirects=False)
    # Follow the redirect manually to catch the cookie
    if r.status_code in (301, 302):
        r2 = s.get(f"{base}{r.headers.get('Location', '/')}", allow_redirects=False)
    return r.headers.get("Set-Cookie", "")


# ─── SESS-01/02  Secure cookie flags ──────────────────────

class TestSecureSessionCookies:

    def setup_method(self):
        self.raw = get_set_cookie_header(SECURE_BASE).lower()

    def test_httponly_flag_set(self):
        """FIX-02: HttpOnly prevents JavaScript access to the session cookie."""
        assert "httponly" in self.raw, (
            f"HttpOnly flag missing from Set-Cookie: {self.raw!r}"
        )

    def test_samesite_lax_or_strict(self):
        """FIX-02: SameSite=Lax or Strict prevents cross-site submission."""
        assert "samesite=lax" in self.raw or "samesite=strict" in self.raw, (
            f"SameSite flag missing or None in Set-Cookie: {self.raw!r}"
        )


# ─── SESS-04/05  Insecure app missing flags ────────────────

class TestInsecureSessionCookies:

    def setup_method(self):
        self.raw = get_set_cookie_header(INSECURE_BASE).lower()

    @pytest.mark.xfail(
        reason="VULN-02: insecure app does not set HttpOnly"
    )
    def test_insecure_httponly_flag_missing(self):
        assert "httponly" in self.raw

    @pytest.mark.xfail(
        reason="VULN-02: insecure app does not set SameSite"
    )
    def test_insecure_samesite_missing(self):
        assert "samesite=lax" in self.raw or "samesite=strict" in self.raw


# ─── SESS-06  Logout clears session ───────────────────────

class TestLogout:

    def _is_authenticated(self, s: requests.Session, base: str) -> bool:
        r = s.get(f"{base}/dashboard", allow_redirects=False)
        return r.status_code == 200

    def test_secure_logout_invalidates_session(self):
        s = requests.Session()
        resp = s.get(f"{SECURE_BASE}/login")
        soup = BeautifulSoup(resp.text, "html.parser")
        csrf_input = soup.find("input", {"name": "csrf_token"})
        data = dict(ALICE_CREDS)
        if csrf_input:
            data["csrf_token"] = csrf_input["value"]
        s.post(f"{SECURE_BASE}/login", data=data, allow_redirects=True)

        assert self._is_authenticated(s, SECURE_BASE), "Login did not work"

        s.get(f"{SECURE_BASE}/logout", allow_redirects=True)
        assert not self._is_authenticated(s, SECURE_BASE), (
            "Session still valid after logout"
        )
