# Changelog

## [Unreleased]

### Added
- Initial implementation of two-state HMS training lab
- Insecure Flask application (`app/insecure/`) with 11 labelled vulnerabilities
- Hardened Flask application (`app/secure/`) with corresponding remediations
- Python/pytest security regression suite (8 test modules)
- Docker Compose configuration for both app states — localhost only
- Full documentation suite: ARCHITECTURE, THREAT_MODEL, SECURITY_ASSESSMENT,
  TESTING, RESULTS, SECURITY, AUTHORIZATION
- Makefile with demo targets for manual vulnerability exploration
- Database reference schema with inline security annotations
- `.env.example` with secret-key generation instructions

### Security notes
- All container ports are bound to `127.0.0.1` only
- No external network access in tests or containers
- Insecure app is intentionally vulnerable for training purposes only
