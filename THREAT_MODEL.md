# Threat Model

## Scope

This threat model applies to the HMS training lab running on `localhost` only.
It is written as if the insecure version were a real deployment, to illustrate
what the threat landscape would look like and why each control matters.

---

## Assets

| Asset                   | Sensitivity | Notes                                     |
|-------------------------|-------------|-------------------------------------------|
| Patient medical records | High        | PHI — confidentiality and integrity vital  |
| User credentials        | High        | Compromise enables impersonation           |
| Authentication cookies  | High        | Theft enables session hijacking            |
| Application source code | Medium      | Logic disclosure aids targeted attacks     |
| Database file           | High        | Contains all of the above                 |

---

## Threat Actors

**Unauthenticated external attacker** — has network access to the web port;
no credentials.  Goal: gain unauthorised access or extract data.

**Authenticated patient** — has a valid session; should only see their own
records.  Goal: access other patients' records or escalate to admin.

**Cross-site attacker** — controls a separate webpage the victim visits.
Goal: trick the victim's browser into making authenticated requests to the HMS.

---

## Attack Surface

| Entry point                    | Method     | Trust level        |
|--------------------------------|------------|--------------------|
| `/login` (GET/POST)            | HTTP form  | Unauthenticated    |
| `/patients?name=` (GET)        | URL param  | Authenticated      |
| `/patient/<id>` (GET)          | URL path   | Authenticated      |
| `/patient/<id>/update` (POST)  | HTTP form  | Authenticated      |
| `/admin` (GET)                 | HTTP       | Any authenticated  |
| `/api/search?q=` (GET)         | URL param  | Authenticated      |

---

## Threats and Mitigations

### T-01 — SQL Injection
**Description:** Attacker injects SQL syntax into a search parameter or login
field to bypass authentication, extract data from arbitrary tables, or modify
records.  
**Likelihood (insecure):** High — query construction is string concatenation.  
**Impact:** Critical — full database read access; authentication bypass.  
**Mitigation (secure):** Parameterised queries.  SQL driver handles escaping;
attacker input is always treated as a literal value, never as SQL syntax.

### T-02 — Credential Theft via Hash Cracking
**Description:** Attacker obtains the database file (e.g., via another
vulnerability) and cracks password hashes offline.  
**Likelihood (insecure):** High — MD5 hashes are trivially cracked with
precomputed rainbow tables (billions of MD5 lookups/second on consumer GPU).  
**Impact:** High — all user passwords recovered.  
**Mitigation (secure):** bcrypt with cost factor 12.  bcrypt is designed to be
slow; cost 12 requires ~250 ms per guess on modern hardware.  Each hash
includes a random 128-bit salt, defeating precomputed tables.

### T-03 — Insecure Direct Object Reference
**Description:** Patient Alice changes the URL from `/patient/1` to
`/patient/2` and reads Bob's medical record.  
**Likelihood (insecure):** Trivially exploitable — no check exists.  
**Impact:** High — PHI disclosure, regulatory risk.  
**Mitigation (secure):** Server checks `patient.user_id == session["user_id"]`
before serving the record.  Doctors and admins are exempt from this check.

### T-04 — Cross-Site Request Forgery
**Description:** Victim is logged into HMS. Attacker tricks victim into visiting
`evil.com`, which auto-submits a form to `/patient/1/update` modifying medical
notes.  
**Likelihood (insecure):** High — no token needed; any POST from any origin
succeeds.  
**Impact:** Medium-High — unauthorised record modification.  
**Mitigation (secure):** Flask-WTF issues a per-session CSRF token embedded in
every form.  The server rejects POSTs that lack a matching token.  Because the
attacker's page is on a different origin, same-origin policy prevents it from
reading the token, so the forged request fails.

### T-05 — Session Hijacking via XSS or Network Sniffing
**Description:** Attacker steals the session cookie.  
**Likelihood (insecure):** Elevated — HttpOnly is absent (JS can read the
cookie); SameSite is absent (cookie sent on cross-site requests).  
**Impact:** High — full session takeover without knowing the password.  
**Mitigation (secure):** `HttpOnly` hides the cookie from JavaScript.
`SameSite=Lax` prevents the cookie from being sent in cross-site POST requests.
`Secure` (in TLS deployment) prevents transmission over plaintext HTTP.

### T-06 — Brute-Force / Credential Stuffing
**Description:** Attacker submits thousands of password guesses against the
login endpoint.  
**Likelihood (insecure):** High — no rate limit or lockout.  
**Impact:** High — account takeover.  
**Mitigation (secure):** Flask-Limiter enforces 10 requests/minute per IP on
`/login`.  Exceeding this returns 429; the counter resets after the window.

### T-07 — Clickjacking
**Description:** Attacker frames the HMS login page inside an invisible iframe
and tricks the victim into clicking a button that performs an action in the HMS.  
**Likelihood (insecure):** Medium.  
**Impact:** Medium.  
**Mitigation (secure):** `X-Frame-Options: DENY` and CSP `frame-ancestors 'none'`
prevent the page from being embedded in any iframe.

### T-08 — Privilege Escalation to Admin Panel
**Description:** Patient-role user navigates directly to `/admin`.  
**Likelihood (insecure):** Certain — no role check.  
**Impact:** High — sees all user accounts and password hashes.  
**Mitigation (secure):** `@roles_required("admin")` decorator aborts with 403
for any other role.

---

## Out of Scope

- Vulnerabilities in the Docker engine, host OS, or Flask framework itself.
- Physical access attacks.
- Network-layer attacks (this is an app-layer training lab).
