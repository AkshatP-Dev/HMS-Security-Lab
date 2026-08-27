# Authorization Design

## Role Model

The HMS has three roles stored in `users.role`:

| Role    | Can access                                         | Cannot access              |
|---------|----------------------------------------------------|----------------------------|
| admin   | All patient records, admin panel, all pages        | —                          |
| doctor  | All patient records, patient search                | Admin panel                |
| patient | Own patient record only, own API search results    | Other patients, admin panel|

---

## Enforcement Layers

Authorization is enforced **server-side** at two layers:

### Layer 1 — Route decorators

```python
@login_required           # Blocks unauthenticated access
@roles_required("admin")  # Blocks non-admin roles
```

`@login_required` checks that `session["user_id"]` is set.  If not, the
request is redirected to `/login`.

`@roles_required("admin")` reads `session["role"]`.  If the role is not in
the permitted set, it returns `abort(403)`.

The session is a Flask signed cookie — the client cannot alter its contents
without invalidating the HMAC-SHA256 signature.  Therefore `session["role"]`
is trustworthy.

### Layer 2 — Ownership check (patient records)

For routes that serve per-patient data, a second check is performed after
the route-level auth:

```python
if session["role"] == "patient" and patient["user_id"] != session["user_id"]:
    abort(403)
```

This ensures that even if a patient guesses a valid patient ID, they receive
403 unless the record belongs to them.  Doctors and admins bypass this check
because `session["role"]` will not equal `"patient"`.

---

## Why Client-Side Role Checks Are Insufficient

The insecure app hides the "Admin" nav link for non-admin users:
```html
{% if session.role in ['admin', 'doctor'] %}
<a href="/admin">Admin</a>
{% endif %}
```

This is presentation logic only.  The route itself has no check, so any user
can navigate directly to `/admin` regardless of the nav link.

The secure app retains the presentation-level hide (to avoid confusing users)
but **also** enforces access control at the route level — only the route check
is the security boundary.

---

## Authorization Decision Table

| User      | GET /patient/1 | GET /patient/2 | GET /admin |
|-----------|----------------|----------------|------------|
| alice (patient, owns record 1) | 200 | **403** | **403** |
| bob   (patient, owns record 2) | **403** | 200 | **403** |
| drsmith (doctor)  | 200 | 200 | **403** |
| admin  (admin)    | 200 | 200 | 200 |
| unauthenticated   | **302→/login** | **302→/login** | **302→/login** |

---

## Session Integrity

The role stored in `session["role"]` is set at login time by the server:
```python
session["role"] = user["role"]   # from the database
```

Flask sessions are signed cookies.  The server's secret key (see FIX-01) is
used to compute an HMAC signature over the session payload.  If a client
modifies the role in the cookie, the signature verification fails and Flask
treats the session as invalid (unauthenticated).

This means the client can never elevate their own role — it always reflects
the value in the database at login time.
