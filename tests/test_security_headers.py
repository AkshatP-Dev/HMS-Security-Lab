"""
test_security_headers.py

Security property: HTTP responses include headers that instruct browsers to
enforce security policies.

Tests:
  HDR-01  X-Content-Type-Options: nosniff
  HDR-02  X-Frame-Options: DENY or SAMEORIGIN (or CSP frame-ancestors: none)
  HDR-03  Content-Security-Policy is present
  HDR-04  Referrer-Policy is present
  HDR-05  Insecure app is missing all of these (xfail — vuln confirmed)

Why headers matter:
  X-Content-Type-Options: nosniff — prevents browsers from guessing MIME types.
    An attacker-uploaded file misidentified as script could execute.
  X-Frame-Options / CSP frame-ancestors — prevents the app being framed in an
    iframe on a malicious page (clickjacking).
  Content-Security-Policy — restricts where scripts and resources may load from,
    greatly limiting XSS impact.
  Referrer-Policy — controls how much URL information is sent to external sites.
"""

import pytest
import requests
from conftest import INSECURE_BASE, SECURE_BASE


# ─── Helper ───────────────────────────────────────────────

def get_headers(base: str) -> dict:
    """Fetch the login page and return its response headers (lower-cased keys)."""
    r = requests.get(f"{base}/login", allow_redirects=True)
    return {k.lower(): v for k, v in r.headers.items()}


# ─── HDR-01/02/03/04  Secure app has required headers ─────

class TestSecureHeaders:

    def setup_method(self):
        self.headers = get_headers(SECURE_BASE)

    def test_x_content_type_options(self):
        assert self.headers.get("x-content-type-options", "").lower() == "nosniff", (
            "X-Content-Type-Options: nosniff missing from secure app"
        )

    def test_x_frame_options_or_csp_frame_ancestors(self):
        """Either X-Frame-Options or a CSP frame-ancestors directive is acceptable."""
        has_xfo = "x-frame-options" in self.headers
        csp = self.headers.get("content-security-policy", "")
        has_frame_ancestors = "frame-ancestors" in csp
        assert has_xfo or has_frame_ancestors, (
            "Neither X-Frame-Options nor CSP frame-ancestors found"
        )

    def test_content_security_policy_present(self):
        assert "content-security-policy" in self.headers, (
            "Content-Security-Policy header missing from secure app"
        )

    def test_referrer_policy_present(self):
        assert "referrer-policy" in self.headers, (
            "Referrer-Policy header missing from secure app"
        )


# ─── HDR-05  Insecure app is missing headers (xfail) ──────

class TestInsecureHeadersMissing:

    def setup_method(self):
        self.headers = get_headers(INSECURE_BASE)

    @pytest.mark.xfail(
        reason="VULN-10: insecure app does not set security headers"
    )
    def test_insecure_missing_csp(self):
        assert "content-security-policy" in self.headers, (
            "CSP not set (expected — VULN-10)"
        )

    @pytest.mark.xfail(
        reason="VULN-10: insecure app does not set security headers"
    )
    def test_insecure_missing_x_frame_options(self):
        has_xfo = "x-frame-options" in self.headers
        csp = self.headers.get("content-security-policy", "")
        assert has_xfo or "frame-ancestors" in csp

    @pytest.mark.xfail(
        reason="VULN-10: insecure app does not set security headers"
    )
    def test_insecure_missing_x_content_type(self):
        assert "x-content-type-options" in self.headers
