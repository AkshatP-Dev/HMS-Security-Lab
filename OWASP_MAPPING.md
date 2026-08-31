# OWASP Top 10 (2021) Mapping

Every weakness in this lab, mapped to the OWASP Top 10 category it belongs to
and the CWE that names it precisely.

This file exists because a count of *weaknesses* is not a count of
*categories*, and conflating the two is an easy claim to make and an easy one
to be caught on. Eleven weaknesses map onto **five** OWASP categories — several
weaknesses share a category, and one very common assumption is wrong:
**IDOR and CSRF are both A01**, not two separate categories. CSRF has not been
a standalone Top 10 entry since 2013; the 2021 list folded it into Broken
Access Control.

## Coverage summary

| OWASP category | Weaknesses here | IDs |
|---|---|---|
| **A01:2021 — Broken Access Control** | 3 | VULN-07, VULN-08, VULN-09 |
| **A02:2021 — Cryptographic Failures** | 2 | VULN-01, VULN-03 |
| **A03:2021 — Injection** | 1 | VULN-05 |
| **A05:2021 — Security Misconfiguration** | 4 | VULN-02, VULN-10, VULN-11, and the verbose-error half of VULN-06 |
| **A07:2021 — Identification and Authentication Failures** | 2 | VULN-04, VULN-06 |

Five categories, eleven weaknesses. A02 also touches A04 (Insecure Design) in
spirit, but the concrete defect in each case is a cryptographic one, so it is
mapped where the evidence actually sits rather than where it sounds broadest.

## Full mapping

| ID | Weakness | OWASP 2021 | CWE | Fix |
|---|---|---|---|---|
| VULN-01 | Hardcoded `secret_key` | A02 — Cryptographic Failures | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) Use of Hard-coded Credentials | FIX-01 — key from environment |
| VULN-02 | Session cookie flags disabled | A05 — Security Misconfiguration | [CWE-1004](https://cwe.mitre.org/data/definitions/1004.html) Sensitive Cookie Without HttpOnly | FIX-02 — HttpOnly, SameSite, Secure-when-TLS |
| VULN-03 | Unsalted MD5 password storage | A02 — Cryptographic Failures | [CWE-916](https://cwe.mitre.org/data/definitions/916.html) Password Hash With Insufficient Computational Effort | FIX-03 — bcrypt, cost factor 12 |
| VULN-04 | No login rate limiting | A07 — Identification and Authentication Failures | [CWE-307](https://cwe.mitre.org/data/definitions/307.html) Improper Restriction of Excessive Authentication Attempts | FIX-04 — Flask-Limiter on login POST |
| VULN-05 | SQL injection (3 sites) | A03 — Injection | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) SQL Injection | FIX-05 — parameterised queries |
| VULN-06 | Username enumeration via distinguishable errors | A07 — Identification and Authentication Failures | [CWE-204](https://cwe.mitre.org/data/definitions/204.html) Observable Response Discrepancy | FIX-06 — uniform message, generic error pages |
| VULN-07 | IDOR — no ownership check on patient records | A01 — Broken Access Control | [CWE-639](https://cwe.mitre.org/data/definitions/639.html) Authorization Bypass Through User-Controlled Key | FIX-07 — server-side `user_id` ownership check |
| VULN-08 | No CSRF token on state-changing POST | A01 — Broken Access Control | [CWE-352](https://cwe.mitre.org/data/definitions/352.html) Cross-Site Request Forgery | FIX-08 — Flask-WTF `CSRFProtect` |
| VULN-09 | Admin panel reachable by any role | A01 — Broken Access Control | [CWE-862](https://cwe.mitre.org/data/definitions/862.html) Missing Authorization | FIX-09 — `@roles_required("admin")` |
| VULN-10 | No security response headers | A05 — Security Misconfiguration | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) Protection Mechanism Failure | FIX-10 — Flask-Talisman (CSP, X-Frame-Options, Referrer-Policy) |
| VULN-11 | `debug=True` in production posture | A05 — Security Misconfiguration | [CWE-489](https://cwe.mitre.org/data/definitions/489.html) Active Debug Code | FIX-11 — `FLASK_DEBUG` env, default off |

## What this lab does not cover

Naming the gaps is part of the mapping. The following Top 10 categories have
**no** representation here, and this lab should not be described as covering
them:

- **A04 — Insecure Design.** Threat modelling is documented in
  [THREAT_MODEL.md](THREAT_MODEL.md), but no weakness here is a design flaw as
  distinct from an implementation defect.
- **A06 — Vulnerable and Outdated Components.** Dependencies are pinned but
  there is no SCA scanning, no SBOM, and no deliberately-vulnerable dependency.
- **A08 — Software and Data Integrity Failures.** No CI/CD supply-chain,
  deserialisation, or update-integrity content.
- **A09 — Security Logging and Monitoring Failures.** Neither build logs
  security events. This is the most interesting omission, because the fix is
  not a control on a request path — it is an operational capability. It is
  covered separately in the BlueWatch SOC lab rather than here.
- **A10 — Server-Side Request Forgery.** No outbound request functionality
  exists in the application, so there is nothing to forge.

Cross-site scripting (part of A03 in 2021) is also **not** demonstrated: the
templates escape by default and no unescaped sink was introduced. Asserting
XSS execution properly needs a headless browser, which
[TESTING.md](TESTING.md) records as out of scope for this suite.
