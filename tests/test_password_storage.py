"""
test_password_storage.py

Security property: passwords are not stored in a form that can be
recovered by an attacker with database access.

Tests:
  PWD-01  Insecure app stores MD5 hashes (expected weak — xfail)
  PWD-02  Secure app stores bcrypt hashes (strong — must pass)
  PWD-03  Secure app hashes are unique even for the same password
  PWD-04  No password hash is present anywhere in secure admin responses

We verify by reading the SQLite database itself rather than an HTTP response —
what this control is about is what gets written to disk. conftest.query_db()
handles both the docker compose workflow and a direct local run; if neither
route is available these tests skip rather than fail.
"""

import hashlib

import pytest

from conftest import SECURE_BASE, ADMIN_CREDS, query_db


# ─── PWD-01  Insecure app uses MD5 ────────────────────────

class TestInsecurePasswordStorage:

    @pytest.mark.xfail(
        reason="VULN-03: insecure app uses MD5 — this confirms the weakness"
    )
    def test_insecure_uses_bcrypt(self):
        """
        We expect the insecure app to store MD5, not bcrypt.
        If bcrypt were used this test would pass; since it uses MD5, xfail.
        """
        output = query_db(
            "hms_insecure",
            "/data/hms_insecure.db",
            "SELECT password FROM users WHERE username='admin';",
        )
        # bcrypt hashes start with $2b$
        assert output.startswith("$2b$"), (
            f"Expected bcrypt, found: {output[:20]!r} (MD5 in use — VULN-03 confirmed)"
        )

    def test_insecure_admin_password_is_md5(self):
        """Confirms the insecure app stores the plain MD5 of the admin password.

        This test PASSES — it asserts the weakness is present and intact. An
        unsalted MD5 of a known plaintext is directly reversible by lookup,
        which is the property VULN-03 exists to demonstrate.
        """
        output = query_db(
            "hms_insecure",
            "/data/hms_insecure.db",
            "SELECT password FROM users WHERE username='admin';",
        )
        expected_md5 = hashlib.md5(
            ADMIN_CREDS["password"].encode()
        ).hexdigest()
        assert output == expected_md5, (
            f"Expected MD5 {expected_md5}, got {output!r}"
        )


# ─── PWD-02  Secure app uses bcrypt ───────────────────────

class TestSecurePasswordStorage:

    def test_secure_uses_bcrypt(self):
        """FIX-03: All passwords must be stored as bcrypt hashes."""
        output = query_db(
            "hms_secure",
            "/data/hms_secure.db",
            "SELECT password FROM users WHERE username='admin';",
        )
        assert output.startswith("$2b$") or output.startswith("$2a$"), (
            f"Expected bcrypt hash, found: {output[:30]!r}"
        )

    def test_secure_bcrypt_cost_factor_is_12(self):
        """FIX-03: cost factor must actually be 12, not merely 'bcrypt'.

        The resume-level claim is the cost factor, so assert the cost factor.
        A bcrypt hash is $2b$<cost>$<salt+digest>; a build that silently fell
        back to the library default would still start with $2b$ and pass the
        test above.
        """
        output = query_db(
            "hms_secure",
            "/data/hms_secure.db",
            "SELECT password FROM users;",
        )
        hashes = [h.strip() for h in output.splitlines() if h.strip()]
        assert hashes, "No password hashes found in the secure database"
        for h in hashes:
            cost = h.split("$")[2]
            assert cost == "12", f"Expected bcrypt cost 12, found {cost} in {h[:20]!r}"

    def test_secure_no_md5_hashes_in_db(self):
        """No 32-char hex string (MD5 pattern) should be a password."""
        output = query_db(
            "hms_secure",
            "/data/hms_secure.db",
            "SELECT password FROM users;",
        )
        for line in output.splitlines():
            line = line.strip()
            # MD5 hashes are exactly 32 hex characters
            is_md5 = len(line) == 32 and all(c in "0123456789abcdef" for c in line)
            assert not is_md5, f"MD5-looking hash found in secure DB: {line!r}"

    def test_secure_hashes_are_unique(self):
        """bcrypt produces a unique hash per call even for identical inputs."""
        output = query_db(
            "hms_secure",
            "/data/hms_secure.db",
            "SELECT password FROM users;",
        )
        hashes = [l.strip() for l in output.splitlines() if l.strip()]
        assert len(hashes) == len(set(hashes)), (
            "Duplicate password hashes found — salting may not be working"
        )

    def test_secure_admin_page_never_shows_password_hash(
        self, secure_admin_session
    ):
        """FIX-03: Even the admin UI must not expose hash strings."""
        r = secure_admin_session.get(f"{SECURE_BASE}/admin",
                                     allow_redirects=True)
        assert r.status_code == 200, (
            f"Admin page unreachable ({r.status_code}) — the admin account "
            f"cannot log in, so this assertion would pass vacuously."
        )
        assert "$2b$" not in r.text
        assert "$2a$" not in r.text
        # And no MD5 of the admin password either.
        admin_md5 = hashlib.md5(ADMIN_CREDS["password"].encode()).hexdigest()
        assert admin_md5 not in r.text
