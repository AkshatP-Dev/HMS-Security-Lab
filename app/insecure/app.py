"""
HMS-Lab — INSECURE training version.

This file is an intentionally vulnerable Flask application created for a
local defensive-security training lab.  It is NEVER to be deployed outside
the Docker environment defined in docker-compose.insecure.yml.

Every weakness is labelled with VULN-xx so the matching secure fix and test
can be cross-referenced quickly.
"""

import sqlite3
import hashlib
import os
from flask import (
    Flask, request, session, redirect, url_for,
    render_template, g, abort, jsonify
)

# ──────────────────────────────────────────────────────────
# VULN-01 — Hardcoded secret key
# A constant secret means any attacker who reads the source can forge
# session cookies for any user without knowing their password.
# ──────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = "supersecret123"

# ──────────────────────────────────────────────────────────
# VULN-02 — Insecure session cookie flags
# Without Secure+HttpOnly+SameSite the cookie is sent over plain HTTP,
# readable by JavaScript, and submitted cross-site.
# ──────────────────────────────────────────────────────────
app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = False
app.config["SESSION_COOKIE_SAMESITE"] = None

# Database path is env-overridable so the suite can run the apps directly
# (venv / CI) as well as under docker compose, where /data is a volume.
DATABASE = os.environ.get("HMS_DB_PATH", "/data/hms_insecure.db")


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
    """Seed the database with roles and test accounts."""
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
        INSERT OR IGNORE INTO users (username, password, role)
            VALUES
            -- VULN-03: passwords stored as unsalted MD5 hashes (trivially crackable)
            -- The plaintexts below are identical to the hardened build's seeded
            -- accounts, so the same credentials work against both targets and the
            -- only observable difference is how the password is stored and checked.
            --   admin   / admin123  -> 0192023a7bbd73250516f069df18b500
            --   drsmith / password  -> 5f4dcc3b5aa765d61d8327deb882cf99
            --   alice   / alice123  -> 7abdccbea8473767e91378e37850d296
            --   bob     / bobpass   -> 6a3c7c6166b4ffcf922329d0e821003b
            -- Every one of these resolves in seconds against a public rainbow
            -- table. That is precisely the point of VULN-03.
            ('admin',   '0192023a7bbd73250516f069df18b500', 'admin'),
            ('drsmith', '5f4dcc3b5aa765d61d8327deb882cf99', 'doctor'),
            ('alice',   '7abdccbea8473767e91378e37850d296', 'patient'),
            ('bob',     '6a3c7c6166b4ffcf922329d0e821003b', 'patient');
        INSERT OR IGNORE INTO patients (user_id, full_name, dob, diagnosis, notes)
            VALUES
            (3, 'Alice Johnson', '1990-04-12', 'Hypertension', 'On lisinopril 10mg'),
            (4, 'Bob Williams',  '1985-11-30', 'Type 2 Diabetes', 'HbA1c 7.2%');
    """)
    db.commit()


# ── ROUTES ────────────────────────────────────────────────


@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    # ──────────────────────────────────────────────────────
    # VULN-04 — No rate limiting on login
    # An attacker can submit unlimited password guesses with no delay or
    # lockout.
    # ──────────────────────────────────────────────────────
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # ──────────────────────────────────────────────────
        # VULN-05 — SQL injection via string concatenation
        #
        # Working bypass:  username = admin'--
        #   SELECT * FROM users WHERE username='admin'--' AND password='...'
        #   Everything after -- is a comment, so the password test is removed
        #   entirely and the query returns the admin row.
        #
        # Also works:      username = ' OR 1=1--
        #
        # Does NOT work:   username = ' OR '1'='1
        #   SELECT * FROM users WHERE username='' OR '1'='1' AND password='...'
        #   AND binds tighter than OR, so SQL reads this as
        #       username='' OR ('1'='1' AND password='<md5>')
        #   and the password condition still has to hold. The injection is real
        #   — the query structure genuinely changed — but the payload does not
        #   authenticate. A payload that alters the query is not automatically a
        #   payload that exploits it; the tests assert both cases explicitly.
        # ──────────────────────────────────────────────────
        # VULN-03 — MD5 is cryptographically broken; rainbow tables exist
        md5pw = hashlib.md5(password.encode()).hexdigest()
        query = (
            "SELECT * FROM users WHERE username='"
            + username
            + "' AND password='"
            + md5pw
            + "'"
        )
        db = get_db()
        user = db.execute(query).fetchone()

        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            return redirect(url_for("dashboard"))
        else:
            # ──────────────────────────────────────────────
            # VULN-06 — Verbose error: reveals whether the username exists
            # when combined with timing side channels.
            # ──────────────────────────────────────────────
            error = "Invalid username or password"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html",
                           username=session["username"],
                           role=session["role"])


@app.route("/patients")
def patients():
    if "user_id" not in session:
        return redirect(url_for("login"))

    db = get_db()
    name_filter = request.args.get("name", "")

    # ──────────────────────────────────────────────────────
    # VULN-05 — SQL injection in search parameter
    # Payload: name=%' UNION SELECT id,username,password,role,NULL,NULL FROM users--
    # (six projected columns, matching the six in `patients` — a mismatch makes
    #  SQLite reject the statement, which reads as a defence that isn't there.)
    # ──────────────────────────────────────────────────────
    if name_filter:
        query = "SELECT * FROM patients WHERE full_name LIKE '%" + name_filter + "%'"
    else:
        query = "SELECT * FROM patients"

    rows = db.execute(query).fetchall()
    return render_template("patients.html", patients=rows, name_filter=name_filter)


@app.route("/patient/<int:patient_id>")
def patient_detail(patient_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    # ──────────────────────────────────────────────────────
    # VULN-07 — Insecure Direct Object Reference (IDOR)
    # Any authenticated user can read any patient record by changing the
    # URL integer — no ownership or role check is performed.
    # ──────────────────────────────────────────────────────
    db = get_db()
    patient = db.execute(
        "SELECT * FROM patients WHERE id=?", (patient_id,)
    ).fetchone()
    if not patient:
        abort(404)
    return render_template("patient_detail.html", patient=patient)


@app.route("/patient/<int:patient_id>/update", methods=["POST"])
def update_patient(patient_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    # ──────────────────────────────────────────────────────
    # VULN-08 — No CSRF protection on state-changing POST
    # A malicious page on another origin can silently submit this form on
    # behalf of an authenticated user.
    # ──────────────────────────────────────────────────────

    # VULN-07 — Still no authorisation check
    notes = request.form.get("notes", "")
    db = get_db()
    db.execute(
        "UPDATE patients SET notes=? WHERE id=?", (notes, patient_id)
    )
    db.commit()
    return redirect(url_for("patient_detail", patient_id=patient_id))


@app.route("/admin")
def admin():
    if "user_id" not in session:
        return redirect(url_for("login"))

    # ──────────────────────────────────────────────────────
    # VULN-09 — Broken access control: any authenticated user
    # (including 'patient' role) reaches the admin panel because the role
    # is never checked.
    # ──────────────────────────────────────────────────────
    db = get_db()
    users = db.execute("SELECT id, username, role, password FROM users").fetchall()
    return render_template("admin.html", users=users)


@app.route("/api/search")
def api_search():
    if "user_id" not in session:
        return jsonify({"error": "unauthorized"}), 401

    term = request.args.get("q", "")
    # VULN-05 — SQL injection in API endpoint as well
    query = "SELECT id, full_name, diagnosis FROM patients WHERE full_name LIKE '%" + term + "%'"
    db = get_db()
    rows = db.execute(query).fetchall()
    return jsonify([dict(r) for r in rows])


# ── No security headers anywhere (VULN-10) ────────────────
# Missing: X-Content-Type-Options, X-Frame-Options,
#          Content-Security-Policy, Referrer-Policy, HSTS


if __name__ == "__main__":
    with app.app_context():
        init_db()
    # VULN-11 — Debug mode enabled in production-like config
    app.run(host="0.0.0.0", port=5000, debug=True)
