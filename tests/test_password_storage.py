"""
test_password_storage.py

Security property: passwords are not stored in a form that can be
recovered by an attacker with database access.

Tests:
  PWD-01  Insecure app stores MD5 hashes (expected weak — xfail)
  PWD-02  Secure app stores bcrypt hashes (strong — must pass)
  PWD-03  Secure app hashes are unique even for the same password
  PWD-04  MD5 hash of 'admin' is not present anywhere in secure responses

We verify by reading the SQLite database file directly inside the container
via the Docker exec approach — alternatively the tests inspect admin-page
output as a proxy.
"""

import subprocess
import pytest
import hashlib

from conftest import SECURE_BASE, secure_admin_session, make_session, ADMIN_CREDS


# ─── Helper: query the DB via docker exec ─────────────────

def query_db(container: str, db_path: str, sql: str) -> str:
    """Run a SQLite query inside a Docker container. Returns stdout."""
    result = subprocess.run(
        ["docker", "exec", container, "sqlite3", db_path, sql],
        capture_output=True, text=True, timeout=10,
    )
    return result.stdout.strip()


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
        """Confirms the insecure app stores the known MD5 of 'admin'."""
        output = query_db(
            "hms_insecure",
            "/data/hms_insecure.db",
            "SELECT password FROM users WHERE username='admin';",
        )
        expected_md5 = hashlib.md5(b"admin").hexdigest()
        # This test PASSES — confirming the weak storage is in place
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
        assert "$2b$" not in r.text
        assert "$2a$" not in r.text
        # Also verify no MD5 pattern: admin's MD5 is 21232f297a57a5a743894a0e4a801fc3
        assert "21232f" not in r.text
