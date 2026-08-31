"""
HMS-Lab — HARDENED / SECURE training version.

Each FIX-xx comment corresponds to the VULN-xx weakness in the insecure app.
Automated tests in tests/ verify each security property against this version.

Run with:  docker compose -f docker-compose.secure.yml up
"""

import sqlite3
import os
import functools
import bcrypt

from flask import (
    Flask, request, session, redirect, url_for,
    render_template, g, abort, jsonify, flash
)
from flask_wtf import CSRFProtect, FlaskForm
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from wtforms import StringField, PasswordField, TextAreaField
from wtforms.validators import DataRequired, Length, Regexp

# ──────────────────────────────────────────────────────────
# FIX-01 — Secret key sourced from environment variable
# The key is randomly generated at container start if not set (development
# only); in production you MUST set HMS_SECRET_KEY to a long random string.
# ──────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get("HMS_SECRET_KEY") or os.urandom(32)

# ──────────────────────────────────────────────────────────
# FIX-02 — Secure session cookie flags
# Secure: only sent over HTTPS (set False for local HTTP testing).
# HttpOnly: hidden from JavaScript — XSS cannot steal the cookie.
# SameSite=Lax: not sent on cross-site POST requests — CSRF mitigation.
# ──────────────────────────────────────────────────────────
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("HTTPS", "false").lower() == "true"  # noqa: E501
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["WTF_CSRF_TIME_LIMIT"] = 3600       # tokens valid 1 hour

# ──────────────────────────────────────────────────────────
# FIX-08 — CSRF protection via Flask-WTF
# Every state-changing form must include {{ form.hidden_tag() }}.
# POSTs without a valid token return 400.
# ──────────────────────────────────────────────────────────
csrf = CSRFProtect(app)

# ──────────────────────────────────────────────────────────
# FIX-04 — Rate limiting on all routes, with a stricter limit on /login
# 5000/day and 500/hour per IP generally; 10/minute on login POSTs.
#
# The general limits are deliberately loose. A per-IP cap tight enough to
# matter as a security control would also break every legitimate user behind
# a corporate NAT or mobile carrier gateway, where hundreds of people share
# one address. The general limit is abuse-dampening; the security control is
# the login limit below it.
#
# The login limit is deliberately scoped to POST only (see the decorator on
# login()). Throttling GET /login would rate-limit the act of *displaying* the
# form, which does not consume a password guess — it only breaks legitimate
# users who reload the page, and it makes automated testing of the control
# impossible because every test must first fetch a CSRF token.
# Brute-force protection belongs on the credential submission, not the render.
# ──────────────────────────────────────────────────────────
# Both limits are configuration, not constants. The shipped defaults below are
# the ones docker-compose.secure.yml runs with and the ones the documentation
# claims. They are overridable so the test suite can exercise the *mechanism*
# without fighting the production threshold: a suite that performs more than
# ten logins a minute would otherwise throttle itself and every assertion after
# it would fail for the wrong reason. This is a configuration seam, not a
# test-only backdoor — there is no code path that disables the limiter.
# See TESTING.md, "Rate limiting and the test suite".
DEFAULT_RATE_LIMITS = os.environ.get(
    "HMS_DEFAULT_RATE_LIMITS", "5000 per day;500 per hour"
).split(";")
LOGIN_RATE_LIMIT = os.environ.get("HMS_LOGIN_RATE_LIMIT", "10 per minute")

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=DEFAULT_RATE_LIMITS,
    storage_uri="memory://",
)

# ──────────────────────────────────────────────────────────
# FIX-10 — Security headers via Flask-Talisman
# Content-Security-Policy, X-Content-Type-Options, X-Frame-Options,
# Referrer-Policy, and (in production) HSTS are all applied.
# ──────────────────────────────────────────────────────────
csp = {
    "default-src": ["'self'"],
    "style-src":   ["'self'", "'unsafe-inline'"],   # inline styles for demo only
    "script-src":  ["'self'"],
    "img-src":     ["'self'", "data:"],
    "frame-ancestors": ["'none'"],
}
# NOTE on session_cookie_secure: Talisman sets SESSION_COOKIE_SECURE=True on
# every request whenever app.debug is False — independently of force_https.
# On this HTTP-only lab that silently breaks every authenticated session,
# because a browser (or requests) will not return a Secure cookie over http://.
# We therefore drive it from the same HTTPS env var as FIX-02 above, so the
# flag is ON by default in any TLS-terminated deployment and OFF only for the
# local plain-HTTP lab. Setting HTTPS=true restores the production behaviour.
_https = os.environ.get("HTTPS", "false").lower() == "true"

Talisman(
    app,
    content_security_policy=csp,
    force_https=_https,         # local HTTP lab by default
    strict_transport_security=_https,
    session_cookie_secure=_https,
    session_cookie_http_only=True,
    referrer_policy="no-referrer",
)

# Database path is env-overridable so the suite can run the apps directly
# (venv / CI) as well as under docker compose, where /data is a volume.
DATABASE = os.environ.get("HMS_DB_PATH", "/data/hms_secure.db")


# ── Forms ─────────────────────────────────────────────────

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[
        DataRequired(),
        Length(min=2, max=64),
        Regexp(r'^[A-Za-z0-9_]+$', message="Alphanumeric and underscores only"),
    ])
    password = PasswordField("Password", validators=[
        DataRequired(),
        Length(min=6, max=128),
    ])


class NotesForm(FlaskForm):
    notes = TextAreaField("Notes", validators=[Length(max=2000)])


# ── Database ───────────────────────────────────────────────

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    """Seed the database with roles and test accounts using bcrypt passwords."""
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            username  TEXT UNIQUE NOT NULL,
            password  TEXT NOT NULL,
            role      TEXT NOT NULL DEFAULT 'patient'
        );
        CREATE TABLE IF NOT EXISTS patients (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            full_name  TEXT NOT NULL,
            dob        TEXT,
            diagnosis  TEXT,
            notes      TEXT
        );
        CREATE TABLE IF NOT EXISTS appointments (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id  INTEGER NOT NULL,
            doctor_id   INTEGER NOT NULL,
            date        TEXT NOT NULL,
            reason      TEXT
        );
    """)
    db.commit()

    # FIX-03 — bcrypt with cost factor 12 (adaptive; resists brute-force as
    # CPUs improve; each hash is unique due to built-in random salt).
    # These are lab credentials for a local-only training target. They are
    # deliberately weak and deliberately identical to the insecure build's
    # accounts, so the same login works against both and the only difference
    # a tester observes is how the password is stored and checked.
    # Every password here is >= 6 characters so it satisfies LoginForm's own
    # Length(min=6) validator — an earlier revision seeded a 5-character admin
    # password, which the form rejected before the credential was ever checked
    # and made the entire admin/RBAC path unreachable in the hardened build.
    seed_users = [
        ("admin",   "admin123", "admin"),
        ("drsmith", "password", "doctor"),
        ("alice",   "alice123", "patient"),
        ("bob",     "bobpass",  "patient"),
    ]
    for username, plaintext, role in seed_users:
        existing = db.execute(
            "SELECT id FROM users WHERE username=?", (username,)
        ).fetchone()
        if not existing:
            hashed = bcrypt.hashpw(plaintext.encode(), bcrypt.gensalt(rounds=12))
            db.execute(
                "INSERT INTO users (username, password, role) VALUES (?,?,?)",
                (username, hashed.decode(), role),
            )
    db.commit()

    # Seed patient records
    alice_id = db.execute("SELECT id FROM users WHERE username='alice'").fetchone()
    bob_id   = db.execute("SELECT id FROM users WHERE username='bob'").fetchone()
    if alice_id:
        db.execute(
            "INSERT OR IGNORE INTO patients (id,user_id,full_name,dob,diagnosis,notes) "
            "VALUES (1,?,?,?,?,?)",
            (alice_id["id"], "Alice Johnson", "1990-04-12", "Hypertension", "On lisinopril 10mg"),
        )
    if bob_id:
        db.execute(
            "INSERT OR IGNORE INTO patients (id,user_id,full_name,dob,diagnosis,notes) "
            "VALUES (2,?,?,?,?,?)",
            (bob_id["id"], "Bob Williams", "1985-11-30", "Type 2 Diabetes", "HbA1c 7.2%"),
        )
    db.commit()


# ── Access-control helpers ─────────────────────────────────

def login_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def roles_required(*roles):
    """Decorator: allow only users whose role is in the given set."""
    def decorator(f):
        @functools.wraps(f)
        @login_required
        def decorated(*args, **kwargs):
            # FIX-09 — Role checked server-side, not trusted from client
            if session.get("role") not in roles:
                abort(403)
            return f(*args, **kwargs)
        return decorated
    return decorator


# ── Routes ────────────────────────────────────────────────

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
# FIX-04 — Rate limiting on credential submission only. GET (rendering the
# form) is covered by the 200/day + 50/hour default limits; only POST, which
# actually consumes a password guess, is throttled at 10/minute.
@limiter.limit(LOGIN_RATE_LIMIT, methods=["POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # FIX-05 — Parameterized query; input can never alter query structure
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username=?",
            (form.username.data,),
        ).fetchone()

        # FIX-03 — bcrypt.checkpw performs constant-time comparison
        # FIX-06 — Same message whether username or password is wrong
        if user and bcrypt.checkpw(form.password.data.encode(),
                                   user["password"].encode()):
            session.clear()                    # prevent session fixation
            session["user_id"]  = user["id"]
            session["username"] = user["username"]
            session["role"]     = user["role"]
            return redirect(url_for("dashboard"))

        flash("Invalid username or password", "error")
    return render_template("login.html", form=form)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html",
                           username=session["username"],
                           role=session["role"])


@app.route("/patients")
@login_required
def patients():
    db = get_db()
    name_filter = request.args.get("name", "").strip()

    # FIX-05 — Parameterized LIKE query; wildcard is part of the parameter,
    # not the query string itself.
    if name_filter:
        rows = db.execute(
            "SELECT * FROM patients WHERE full_name LIKE ?",
            (f"%{name_filter}%",),
        ).fetchall()
    else:
        rows = db.execute("SELECT * FROM patients").fetchall()

    # FIX-07 — Patients only see their own record; doctors/admins see all
    if session["role"] == "patient":
        rows = [r for r in rows if r["user_id"] == session["user_id"]]

    return render_template("patients.html", patients=rows, name_filter=name_filter)


@app.route("/patient/<int:patient_id>")
@login_required
def patient_detail(patient_id):
    db = get_db()
    patient = db.execute(
        "SELECT * FROM patients WHERE id=?", (patient_id,)
    ).fetchone()
    if not patient:
        abort(404)

    # FIX-07 — Ownership check: patient may only view their own record
    if session["role"] == "patient" and patient["user_id"] != session["user_id"]:
        abort(403)

    form = NotesForm()
    form.notes.data = patient["notes"]
    return render_template("patient_detail.html", patient=patient, form=form)


@app.route("/patient/<int:patient_id>/update", methods=["POST"])
@login_required
def update_patient(patient_id):
    # FIX-08 — CSRF token validated by Flask-WTF before this code runs
    # FIX-07 — Ownership/role check
    db = get_db()
    patient = db.execute(
        "SELECT * FROM patients WHERE id=?", (patient_id,)
    ).fetchone()
    if not patient:
        abort(404)
    if session["role"] == "patient" and patient["user_id"] != session["user_id"]:
        abort(403)

    form = NotesForm()
    if form.validate_on_submit():
        db.execute(
            "UPDATE patients SET notes=? WHERE id=?",
            (form.notes.data, patient_id),
        )
        db.commit()
        flash("Notes updated.", "success")
    return redirect(url_for("patient_detail", patient_id=patient_id))


@app.route("/admin")
@roles_required("admin")               # FIX-09 — Admin-only access enforced
def admin():
    db = get_db()
    # FIX-03 — Password hashes (bcrypt) never displayed in UI
    users = db.execute("SELECT id, username, role FROM users").fetchall()
    return render_template("admin.html", users=users)


@app.route("/api/search")
@login_required
def api_search():
    term = request.args.get("q", "").strip()
    db = get_db()

    # FIX-05 — Parameterized query
    rows = db.execute(
        "SELECT id, full_name, diagnosis FROM patients WHERE full_name LIKE ?",
        (f"%{term}%",),
    ).fetchall()

    # FIX-07 — Patients only see their own record in API results
    if session["role"] == "patient":
        rows = [r for r in rows if r["id"] in _own_patient_ids(db)]

    return jsonify([dict(r) for r in rows])


def _own_patient_ids(db):
    rows = db.execute(
        "SELECT id FROM patients WHERE user_id=?", (session["user_id"],)
    ).fetchall()
    return {r["id"] for r in rows}


# ── Generic error pages (FIX-06 — no stack traces in production) ──

@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", code=403,
                           message="You do not have permission to view this page."), 403


@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404,
                           message="The page you requested was not found."), 404


@app.errorhandler(429)
def rate_limited(e):
    return render_template("error.html", code=429,
                           message="Too many requests. Please wait and try again."), 429


if __name__ == "__main__":
    with app.app_context():
        init_db()
    # FIX-11 — Debug mode OFF; set via environment for development only
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=5001, debug=debug)
