"""
test_csrf.py

Security property: state-changing requests require a valid CSRF token.

Tests:
  CSRF-01  POST without CSRF token is rejected by secure app (400)
  CSRF-02  POST with invalid CSRF token is rejected (400)
  CSRF-03  POST with valid CSRF token is accepted (200/302)
  CSRF-04  Insecure app accepts POST without any token (xfail — vuln confirmed)

How CSRF works in the secure app:
  Flask-WTF generates a per-session random token, embeds it in every form,
  and validates it on every state-changing request.  A cross-site attacker
  cannot read the victim's token (same-origin policy), so forged requests fail.
"""

import pytest
import requests
from bs4 import BeautifulSoup
from conftest import INSECURE_BASE, SECURE_BASE, make_session, ALICE_CREDS


ALICE_PATIENT_ID = 1


def get_login_session_and_csrf(base: str) -> tuple[requests.Session, str]:
    """Log in and return (session, update_csrf_token)."""
    s = make_session(base, ALICE_CREDS)
    # Fetch patient detail page to get a fresh CSRF token for the update form
    r = s.get(f"{base}/patient/{ALICE_PATIENT_ID}", allow_redirects=True)
    soup = BeautifulSoup(r.text, "html.parser")
    csrf_input = soup.find("input", {"name": "csrf_token"})
    token = csrf_input["value"] if csrf_input else ""
    return s, token


# ─── CSRF-01  No token → rejected (secure) ────────────────

class TestCSRFProtection:

    def test_secure_post_without_token_rejected(self):
        """FIX-08: POST with no CSRF token returns 400."""
        s = make_session(SECURE_BASE, ALICE_CREDS)
        r = s.post(
            f"{SECURE_BASE}/patient/{ALICE_PATIENT_ID}/update",
            data={"notes": "Injected note — no CSRF token"},
            allow_redirects=False,
        )
        assert r.status_code == 400, (
            f"Expected 400 Bad Request, got {r.status_code} — CSRF not enforced"
        )

    def test_secure_post_with_invalid_token_rejected(self):
        """FIX-08: A forged/wrong token is rejected."""
        s = make_session(SECURE_BASE, ALICE_CREDS)
        r = s.post(
            f"{SECURE_BASE}/patient/{ALICE_PATIENT_ID}/update",
            data={"notes": "Injected note", "csrf_token": "badtoken12345"},
            allow_redirects=False,
        )
        assert r.status_code == 400, (
            f"Expected 400 Bad Request, got {r.status_code}"
        )

    def test_secure_post_with_valid_token_accepted(self):
        """FIX-08: A valid same-session token is accepted."""
        s, token = get_login_session_and_csrf(SECURE_BASE)
        r = s.post(
            f"{SECURE_BASE}/patient/{ALICE_PATIENT_ID}/update",
            data={"notes": "Legitimate update", "csrf_token": token},
            allow_redirects=True,
        )
        # Should redirect back to the patient page (200 after follow)
        assert r.status_code == 200

    # ─── CSRF-04  Insecure app has no protection ───────────

    @pytest.mark.xfail(
        reason="VULN-08: insecure app has no CSRF protection — forged POST succeeds"
    )
    def test_insecure_post_without_token_rejected(self):
        """
        DEMONSTRATES THE VULNERABILITY.
        The insecure app does not check for a token, so this POST succeeds.
        The xfail marks that this is the EXPECTED insecure behaviour.
        """
        s = make_session(INSECURE_BASE, ALICE_CREDS)
        r = s.post(
            f"{INSECURE_BASE}/patient/{ALICE_PATIENT_ID}/update",
            data={"notes": "CSRF-forged note"},
            allow_redirects=False,
        )
        # In the insecure app this will be 302 (success), not 400
        assert r.status_code == 400, (
            f"Expected 400 but got {r.status_code} — CSRF not enforced (VULN-08)"
        )
