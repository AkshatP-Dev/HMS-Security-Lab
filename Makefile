# HMS Security Lab — convenience targets
# Usage: make <target>

.PHONY: help up-insecure up-secure up-both test-up down test test-verbose clean logs-insecure logs-secure

# Login rate limit used when running the suite. The production default is
# 10/minute (docker-compose.secure.yml); the suite performs more than ten
# logins a minute, so running it against the production threshold would make
# every test after the first ten fail with 429 for reasons unrelated to what
# they assert. test_rate_limiting reads this same value and overshoots it, so
# the limiter is still verified — against whatever the app is running with.
# See TESTING.md, "Rate limiting and the test suite".
TEST_LOGIN_RATE_LIMIT ?= 20 per minute

help:
	@echo ""
	@echo "HMS Security Lab"
	@echo "────────────────────────────────────────────"
	@echo "  make up-insecure   Start insecure app  → http://localhost:5000"
	@echo "  make up-secure     Start hardened app  → http://localhost:5001"
	@echo "  make up-both       Start both apps"
	@echo "  make down          Stop and remove both containers"
	@echo "  make test          Run the full security regression suite"
	@echo "  make logs-insecure Stream logs from the insecure container"
	@echo "  make logs-secure   Stream logs from the secure container"
	@echo "  make clean         Remove containers, volumes, and images"
	@echo ""

up-insecure:
	docker compose -f docker-compose.insecure.yml up -d --build
	@echo "Insecure app: http://localhost:5000"

up-secure:
	docker compose -f docker-compose.secure.yml up -d --build
	@echo "Hardened app: http://localhost:5001"

up-both: up-insecure up-secure

# Same images, same code — only the rate-limit thresholds differ.
test-up:
	docker compose -f docker-compose.insecure.yml up -d --build
	HMS_LOGIN_RATE_LIMIT="$(TEST_LOGIN_RATE_LIMIT)" \
	  docker compose -f docker-compose.secure.yml up -d --build
	@echo "Both apps up in TEST configuration (login limit: $(TEST_LOGIN_RATE_LIMIT))"
	@echo "Now run: make test"

down:
	docker compose -f docker-compose.insecure.yml down
	docker compose -f docker-compose.secure.yml down

test:
	@echo "Installing test dependencies..."
	pip install -q -r tests/requirements.txt
	@echo "Running security regression suite..."
	cd tests && HMS_LOGIN_RATE_LIMIT="$(TEST_LOGIN_RATE_LIMIT)" pytest -v

test-verbose:
	pip install -q -r tests/requirements.txt
	cd tests && HMS_LOGIN_RATE_LIMIT="$(TEST_LOGIN_RATE_LIMIT)" \
	  pytest -v --tb=long 2>&1 | tee ../RESULTS_raw.txt
	@echo "Output saved to RESULTS_raw.txt"

logs-insecure:
	docker logs -f hms_insecure

logs-secure:
	docker logs -f hms_secure

shell-insecure:
	docker exec -it hms_insecure /bin/bash

shell-secure:
	docker exec -it hms_secure /bin/bash

# Demonstrate SQL injection in the insecure search endpoint
demo-sqli:
	@echo "Demonstrating SQL injection in insecure patient search..."
	@echo "Payload: %' UNION SELECT id,username,password,role,NULL,NULL FROM users--"
	@echo "Log in at http://localhost:5000 as alice/alice123, then paste the payload into the search box."

# Show security headers comparison
demo-headers:
	@echo "=== INSECURE APP (localhost:5000) ==="
	curl -si http://localhost:5000/login | grep -i "content-security\|x-frame\|x-content\|referrer\|strict-transport" || echo "(no security headers)"
	@echo ""
	@echo "=== SECURE APP (localhost:5001) ==="
	curl -si http://localhost:5001/login | grep -i "content-security\|x-frame\|x-content\|referrer\|strict-transport"

clean:
	docker compose -f docker-compose.insecure.yml down -v --rmi local
	docker compose -f docker-compose.secure.yml down -v --rmi local
