"""
test_authorization.py

Security property: authenticated users can only access resources they own
or are permitted to access by their role.

Tests:
  AUTHZ-01  Patient cannot access another patient's record (IDOR)
  AUTHZ-02  Patient cannot access the admin panel
  AUTHZ-03  Doctor can access any patient record
  AUTHZ-04  Admin can access the admin panel
  AUTHZ-05  Patient cannot reach admin panel even with direct URL (secure)

We demonstrate that:
  - The INSECURE app FAILS AUTHZ-01 and AUTHZ-02 (those tests are marked xfail)
  - The SECURE app PASSES all checks
"""

import pytest
import requests
from conftest import (
    INSECURE_BASE, SECURE_BASE,
    insecure_alice_session, insecure_bob_session, insecure_admin_session,
    secure_alice_session, secure_bob_session, secure_admin_session,
)

# Patient IDs seeded in init_db():
ALICE_PATIENT_ID = 1
BOB_PATIENT_ID   = 2


# ─── AUTHZ-01  IDOR: patient accessing another's record ───

class TestIDOR:

    @pytest.mark.xfail(
        reason="VULN-07: insecure app has no ownership check — IDOR is present"
    )
    def test_insecure_alice_cannot_read_bob(self, insecure_alice_session):
        """
        DEMONSTRATES THE VULNERABILITY.
        In the insecure app Alice CAN read Bob's record (the test is xfail).
        When you run against the insecure app this 'failure' is expected.
        """
        r = insecure_alice_session.get(
            f"{INSECURE_BASE}/patient/{BOB_PATIENT_ID}",
            allow_redirects=True,
        )
        # This assertion should pass (403/404) but in the insecure app it will
        # return 200 because there is no ownership check.
        assert r.status_code in (403, 404), (
            f"IDOR present — Alice read Bob's record (status {r.status_code})"
        )

    def test_secure_alice_cannot_read_bob(self, secure_alice_session):
        """FIX-07: Secure app blocks cross-patient access."""
        r = secure_alice_session.get(
            f"{SECURE_BASE}/patient/{BOB_PATIENT_ID}",
            allow_redirects=True,
        )
        assert r.status_code == 403, (
            f"Expected 403 Forbidden, got {r.status_code}"
        )

    def test_secure_alice_can_read_own_record(self, secure_alice_session):
        r = secure_alice_session.get(
            f"{SECURE_BASE}/patient/{ALICE_PATIENT_ID}",
            allow_redirects=True,
        )
        assert r.status_code == 200
        assert "Alice" in r.text


# ─── AUTHZ-02  Broken access control: admin panel ─────────

class TestAdminAccess:

    @pytest.mark.xfail(
        reason="VULN-09: insecure app serves admin panel to any authenticated user"
    )
    def test_insecure_patient_cannot_reach_admin(self, insecure_alice_session):
        r = insecure_alice_session.get(
            f"{INSECURE_BASE}/admin", allow_redirects=True
        )
        assert r.status_code in (403, 404), (
            f"Broken access control — patient reached admin panel (status {r.status_code})"
        )

    def test_secure_patient_cannot_reach_admin(self, secure_alice_session):
        """FIX-09: 403 for non-admin roles."""
        r = secure_alice_session.get(
            f"{SECURE_BASE}/admin", allow_redirects=True
        )
        assert r.status_code == 403

    def test_secure_doctor_cannot_reach_admin(self, secure_alice_session):
        """Doctors are not admins — they also get 403."""
        from conftest import DOCTOR_CREDS, make_session
        doctor_s = make_session(SECURE_BASE, DOCTOR_CREDS)
        r = doctor_s.get(f"{SECURE_BASE}/admin", allow_redirects=True)
        assert r.status_code == 403

    def test_secure_admin_can_reach_admin(self, secure_admin_session):
        r = secure_admin_session.get(
            f"{SECURE_BASE}/admin", allow_redirects=True
        )
        assert r.status_code == 200
        assert "Admin Panel" in r.text

    def test_secure_admin_panel_does_not_expose_password_hashes(
        self, secure_admin_session
    ):
        """FIX-03: bcrypt hashes must NOT appear in the admin HTML."""
        r = secure_admin_session.get(
            f"{SECURE_BASE}/admin", allow_redirects=True
        )
        # bcrypt hashes start with $2b$ or $2a$
        assert "$2b$" not in r.text and "$2a$" not in r.text, (
            "Password hashes found in admin page response"
        )
