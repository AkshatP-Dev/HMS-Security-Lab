"""
conftest.py — pytest fixtures shared across all test modules.

All requests go to localhost — the Docker containers started by
docker-compose.insecure.yml (port 5000) and docker-compose.secure.yml
(port 5001).  No external network access is needed or performed.

Run the tests with:
    # Start both containers first:
    docker compose -f docker-compose.insecure.yml up -d
    docker compose -f docker-compose.secure.yml up -d

    # Then from the repo root:
    cd tests
    pip install -r requirements.txt
    pytest -v
"""

import os
import shutil
import sqlite3
import subprocess

import pytest
import requests


# ── Target URLs ────────────────────────────────────────────

INSECURE_BASE = os.environ.get("HMS_INSECURE_URL", "http://localhost:5000")
SECURE_BASE   = os.environ.get("HMS_SECURE_URL",   "http://localhost:5001")

# Seeded test accounts. These match init_db() in BOTH apps — the two builds
# deliberately share credentials so the only difference a tester can observe
# is how the password is stored and verified, never which password works.
# Every password is >= 6 characters, satisfying the hardened build's own
# LoginForm Length(min=6) validator.
# The login rate limit the target is actually running with. Defaults to the
# shipped production value; the test harness raises it (see TESTING.md) so the
# suite does not throttle itself. test_rate_limiting reads this same value, so
# the limit is verified against whatever the app is genuinely configured with
# rather than against a hardcoded 10.
LOGIN_RATE_LIMIT = os.environ.get("HMS_LOGIN_RATE_LIMIT", "10 per minute")
LOGIN_RATE_LIMIT_COUNT = int(LOGIN_RATE_LIMIT.split()[0])

ADMIN_CREDS   = {"username": "admin",   "password": "admin123"}
DOCTOR_CREDS  = {"username": "drsmith", "password": "password"}
ALICE_CREDS   = {"username": "alice",   "password": "alice123"}  # patient, patient_id=1
BOB_CREDS     = {"username": "bob",     "password": "bobpass"}   # patient, patient_id=2


# ── Database access, for the credential-storage tests ──────
#
# Those tests need the actual stored hash, which means reaching the SQLite
# file rather than any HTTP response. Two strategies, tried in order:
#
#   1. A readable path in HMS_INSECURE_DB / HMS_SECURE_DB — used when the apps
#      run directly (venv, CI) rather than in containers.
#   2. `docker exec <container> sqlite3 <path> <sql>` — the normal docker
#      compose workflow. Both Dockerfiles install the sqlite3 CLI for this.
#
# If neither is available the storage tests skip with an explanatory message
# instead of erroring, so the rest of the suite still runs.

DB_PATHS = {
    "hms_insecure": os.environ.get("HMS_INSECURE_DB"),
    "hms_secure":   os.environ.get("HMS_SECURE_DB"),
}


def pytest_collection_modifyitems(items):
    """Run the rate-limiting tests last.

    Verifying the login limiter necessarily means exhausting it, and the
    limiter's counter is per-process and time-windowed. Any test that logs in
    after that point would get a 429 and fail for a reason that has nothing to
    do with what it is asserting — which is exactly the failure mode this
    ordering exists to prevent. pytest collects files alphabetically, which
    would otherwise place test_rate_limiting.py in the middle of the run.
    """
    rate_limit_items = [i for i in items if "test_rate_limiting" in str(i.fspath)]
    if rate_limit_items:
        others = [i for i in items if i not in rate_limit_items]
        items[:] = others + rate_limit_items


def query_db(container: str, db_path: str, sql: str) -> str:
    """Return the result of `sql` against the named app's database."""
    local_path = DB_PATHS.get(container)

    if local_path and os.path.exists(local_path):
        conn = sqlite3.connect(local_path)
        try:
            rows = conn.execute(sql).fetchall()
        finally:
            conn.close()
        return "\n".join("|".join(str(c) for c in row) for row in rows).strip()

    if shutil.which("docker") is None:
        pytest.skip(
            "No database access: set HMS_INSECURE_DB / HMS_SECURE_DB to the "
            "SQLite files, or run the apps under docker compose."
        )

    result = subprocess.run(
        ["docker", "exec", container, "sqlite3", db_path, sql],
        capture_output=True, text=True, timeout=10,
    )
    if result.returncode != 0:
        pytest.skip(
            f"Could not read {container} database via docker exec: "
            f"{result.stderr.strip() or 'container not running'}"
        )
    return result.stdout.strip()


# ── Session helpers ────────────────────────────────────────

def make_session(base_url: str, creds: dict) -> requests.Session:
    """Return an authenticated requests.Session against base_url."""
    s = requests.Session()
    # For the secure app we need a CSRF token; fetch the login page first
    resp = s.get(f"{base_url}/login")
    resp.raise_for_status()

    # Extract CSRF token if present (secure app embeds it in the form)
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(resp.text, "html.parser")
    csrf_input = soup.find("input", {"name": "csrf_token"})
    post_data = dict(creds)
    if csrf_input:
        post_data["csrf_token"] = csrf_input["value"]

    s.post(f"{base_url}/login", data=post_data, allow_redirects=True)
    return s


# ── Fixtures ───────────────────────────────────────────────

# --- Insecure app sessions ---

@pytest.fixture(scope="session")
def insecure_alice_session():
    return make_session(INSECURE_BASE, ALICE_CREDS)


@pytest.fixture(scope="session")
def insecure_bob_session():
    return make_session(INSECURE_BASE, BOB_CREDS)


@pytest.fixture(scope="session")
def insecure_admin_session():
    return make_session(INSECURE_BASE, ADMIN_CREDS)


# --- Secure app sessions ---

@pytest.fixture(scope="session")
def secure_alice_session():
    return make_session(SECURE_BASE, ALICE_CREDS)


@pytest.fixture(scope="session")
def secure_bob_session():
    return make_session(SECURE_BASE, BOB_CREDS)


@pytest.fixture(scope="session")
def secure_admin_session():
    return make_session(SECURE_BASE, ADMIN_CREDS)
