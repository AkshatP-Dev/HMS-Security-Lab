"""
test_rate_limiting.py

Security property: the login endpoint limits the number of attempts per IP
so that brute-force password attacks are not feasible.

Tests:
  RATE-01  Secure app returns 429 after exceeding the login rate limit
  RATE-02  Insecure app does NOT enforce a rate limit (xfail — vuln confirmed)

Note on test design:
  The secure app is configured for 10 requests/minute on /login.
  We send 12 requests in quick succession and expect the 12th to return 429.
  All requests go to localhost only.

  Because rate-limit state is in-memory and per-container, running this test
  may temporarily block the test user from logging in for up to 60 seconds.
  A fresh Docker container restores the counter.
"""

import time
import pytest
import requests
from bs4 import BeautifulSoup
from conftest import INSECURE_BASE, SECURE_BASE


LIMIT_THRESHOLD = 10      # configured in secure/app.py: "10 per minute"
OVERSHOOT       = 13      # requests to send (must exceed limit)


def attempt_login(base: str, n: int) -> list[int]:
    """Send n login POSTs with wrong credentials. Return list of status codes."""
    status_codes = []
    for _ in range(n):
        s = requests.Session()
        # Get CSRF if needed
        resp = s.get(f"{base}/login")
        soup = BeautifulSoup(resp.text, "html.parser")
        csrf_input = soup.find("input", {"name": "csrf_token"})
        data = {"username": "alice", "password": "wrongpassword"}
        if csrf_input:
            data["csrf_token"] = csrf_input["value"]
        r = s.post(f"{base}/login", data=data, allow_redirects=False)
        status_codes.append(r.status_code)
    return status_codes


# ─── RATE-01  Secure app enforces limit ───────────────────

class TestRateLimiting:

    def test_secure_login_rate_limited(self):
        """FIX-04: After >10 attempts/minute the server returns 429."""
        codes = attempt_login(SECURE_BASE, OVERSHOOT)
        assert 429 in codes, (
            f"Expected 429 Too Many Requests within {OVERSHOOT} attempts, "
            f"got codes: {codes}"
        )

    # ─── RATE-02  Insecure app has no limit ───────────────

    @pytest.mark.xfail(
        reason="VULN-04: insecure app has no rate limiting — all 13 attempts succeed"
    )
    def test_insecure_login_rate_limited(self):
        """
        DEMONSTRATES THE VULNERABILITY.
        The insecure app never returns 429; an attacker can guess indefinitely.
        """
        codes = attempt_login(INSECURE_BASE, OVERSHOOT)
        assert 429 in codes, (
            f"Rate limit not enforced on insecure app — codes: {codes}"
        )
