# Security Policy

## Scope

This repository contains a **training-only, intentionally vulnerable**
application.  It is not a production system.

The insecure version (`app/insecure/`) is expected to have vulnerabilities.
Reporting findings against it is not meaningful — they are documented in
SECURITY_ASSESSMENT.md by design.

## Reporting Issues in the Lab Infrastructure

If you find a security issue in the **lab infrastructure itself** (Dockerfile,
test runner, Docker Compose configuration — not the intentionally insecure app),
please open a GitHub issue or contact the repository owner directly.

## Usage Warning

The insecure application **must not** be deployed outside the local Docker
environment defined by `docker-compose.insecure.yml`.

Both Compose files bind ports to `127.0.0.1` only.  Do not change the port
binding to `0.0.0.0` — doing so exposes the vulnerable application to the
local network.

## Dependency Updates

Run periodically:
```bash
pip-audit -r app/insecure/requirements.txt
pip-audit -r app/secure/requirements.txt
pip-audit -r tests/requirements.txt
```
