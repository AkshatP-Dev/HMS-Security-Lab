-- HMS Security Lab — Reference Schema
-- This file documents the database structure used by both app versions.
-- The actual schema is created at container startup by init_db() in app.py.

-- ─────────────────────────────────────────────────────────────────────────────
-- Users
--
-- The password column holds different content in each app version:
--   insecure: 32-character lowercase hex string (unsalted MD5)  ← VULN-03
--   secure:   bcrypt hash beginning with $2b$12$               ← FIX-03
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    username  TEXT UNIQUE NOT NULL,
    password  TEXT NOT NULL,           -- See note above
    role      TEXT NOT NULL DEFAULT 'patient'
              CHECK (role IN ('admin', 'doctor', 'patient'))
);

-- ─────────────────────────────────────────────────────────────────────────────
-- Patients
--
-- user_id links each patient record to the users table.
-- The insecure app does NOT enforce that only the owning user can read
-- a patient row (VULN-07).  The secure app checks user_id == session.user_id
-- for 'patient' role users (FIX-07).
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS patients (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    full_name  TEXT NOT NULL,
    dob        TEXT,                   -- ISO 8601 date string
    diagnosis  TEXT,
    notes      TEXT
);

-- ─────────────────────────────────────────────────────────────────────────────
-- Appointments (placeholder — not yet exposed in the UI)
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS appointments (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id  INTEGER NOT NULL REFERENCES patients(id),
    doctor_id   INTEGER NOT NULL REFERENCES users(id),
    date        TEXT NOT NULL,
    reason      TEXT
);
