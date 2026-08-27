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

import pytest
import requests


# ── Target URLs ────────────────────────────────────────────

INSECURE_BASE = "http://localhost:5000"
SECURE_BASE   = "http://localhost:5001"

# Seeded test accounts (matching init_db() in both apps)
ADMIN_CREDS   = {"username": "admin",   "password": "admin"}
DOCTOR_CREDS  = {"username": "drsmith", "password": "password"}
ALICE_CREDS   = {"username": "alice",   "password": "alice123"}  # patient, patient_id=1
BOB_CREDS     = {"username": "bob",     "password": "bobpass"}   # patient, patient_id=2


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
