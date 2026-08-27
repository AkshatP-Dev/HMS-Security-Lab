"""
test_authentication.py

Security property: unauthenticated requests are rejected.

Tests:
  AUTH-01  Unauthenticated access to dashboard is refused
  AUTH-02  Unauthenticated access to patients list is refused
  AUTH-03  Unauthenticated access to admin panel is refused
  AUTH-04  Valid credentials produce an authenticated session
  AUTH-05  Invalid credentials are rejected (wrong password)
  AUTH-06  Invalid credentials are rejected (nonexistent user)
"""

import requests
from conftest import INSECURE_BASE, SECURE_BASE, ALICE_CREDS


# ─── helpers ──────────────────────────────────────────────

def unauthenticated_get(base: str, path: str) -> requests.Response:
    """Fresh session (no cookies) — should be redirected or blocked."""
    s = requests.Session()
    return s.get(f"{base}{path}", allow_redirects=False)


def get_csrf(base: str) -> tuple[requests.Session, str]:
    from bs4 import BeautifulSoup
    s = requests.Session()
    resp = s.get(f"{base}/login")
    soup = BeautifulSoup(resp.text, "html.parser")
    csrf_input = soup.find("input", {"name": "csrf_token"})
    token = csrf_input["value"] if csrf_input else ""
    return s, token


# ─── AUTH-01/02/03  Unauthenticated redirects ─────────────

class TestUnauthenticatedAccess:
    """Both app versions must redirect or block unauthenticated requests."""

    PROTECTED_PATHS = ["/dashboard", "/patients", "/admin"]

    def test_insecure_redirects_dashboard(self):
        r = unauthenticated_get(INSECURE_BASE, "/dashboard")
        assert r.status_code in (302, 401, 403), (
            f"Expected redirect/block, got {r.status_code}"
        )

    def test_insecure_redirects_patients(self):
        r = unauthenticated_get(INSECURE_BASE, "/patients")
        assert r.status_code in (302, 401, 403)

    def test_insecure_redirects_admin(self):
        r = unauthenticated_get(INSECURE_BASE, "/admin")
        assert r.status_code in (302, 401, 403)

    def test_secure_redirects_dashboard(self):
        r = unauthenticated_get(SECURE_BASE, "/dashboard")
        assert r.status_code in (302, 401, 403)

    def test_secure_redirects_patients(self):
        r = unauthenticated_get(SECURE_BASE, "/patients")
        assert r.status_code in (302, 401, 403)

    def test_secure_redirects_admin(self):
        r = unauthenticated_get(SECURE_BASE, "/admin")
        assert r.status_code in (302, 401, 403)


# ─── AUTH-04  Valid login works ────────────────────────────

class TestValidLogin:
    def test_insecure_valid_login(self):
        s = requests.Session()
        r = s.post(f"{INSECURE_BASE}/login",
                   data=ALICE_CREDS, allow_redirects=True)
        assert r.status_code == 200
        assert "Dashboard" in r.text or "dashboard" in r.url

    def test_secure_valid_login(self):
        s, token = get_csrf(SECURE_BASE)
        data = {**ALICE_CREDS, "csrf_token": token}
        r = s.post(f"{SECURE_BASE}/login", data=data, allow_redirects=True)
        assert r.status_code == 200
        assert "Dashboard" in r.text or "dashboard" in r.url


# ─── AUTH-05/06  Invalid login rejected ───────────────────

class TestInvalidLogin:
    def test_insecure_wrong_password(self):
        s = requests.Session()
        r = s.post(f"{INSECURE_BASE}/login",
                   data={"username": "alice", "password": "wrongpass"},
                   allow_redirects=True)
        # Must not reach dashboard
        assert "dashboard" not in r.url
        assert r.status_code == 200

    def test_secure_wrong_password(self):
        s, token = get_csrf(SECURE_BASE)
        r = s.post(f"{SECURE_BASE}/login",
                   data={"username": "alice", "password": "wrongpass",
                         "csrf_token": token},
                   allow_redirects=True)
        assert "dashboard" not in r.url
        assert r.status_code == 200

    def test_secure_nonexistent_user(self):
        s, token = get_csrf(SECURE_BASE)
        r = s.post(f"{SECURE_BASE}/login",
                   data={"username": "nobody", "password": "anything",
                         "csrf_token": token},
                   allow_redirects=True)
        assert "dashboard" not in r.url
