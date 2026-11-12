-- IEM Admission Portal - PostgreSQL 12+ schema (safe to run repeatedly)
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY, name VARCHAR(100) NOT NULL, email VARCHAR(120) UNIQUE NOT NULL, phone VARCHAR(15),
  password TEXT NOT NULL, role VARCHAR(10) NOT NULL DEFAULT 'applicant' CHECK (role IN ('applicant','admin')),
  created_at TIMESTAMP DEFAULT NOW());

CREATE TABLE IF NOT EXISTS programs (
  code VARCHAR(10) PRIMARY KEY, name VARCHAR(120) NOT NULL, intake INT NOT NULL CHECK (intake >= 0),
  description TEXT, eligibility TEXT, duration VARCHAR(20));

CREATE TABLE IF NOT EXISTS applications (
  id SERIAL PRIMARY KEY,
  user_id INT NOT NULL REFERENCES users(id),
  app_no TEXT GENERATED ALWAYS AS ('IEM/UG/26/' || LPAD((10000 + id)::text, 8, '0')) STORED,
  status VARCHAR(12) NOT NULL DEFAULT 'Draft' CHECK (status IN ('Draft','Submitted','Admitted','Waitlisted','Rejected')),
  payment_status VARCHAR(10) NOT NULL DEFAULT 'Pending',
  submitted_at TIMESTAMP, created_at TIMESTAMP DEFAULT NOW(),
  full_name TEXT, program_code VARCHAR(10) REFERENCES programs(code),
  dob TEXT, gender TEXT, aadhaar TEXT, nationality TEXT, category TEXT, religion TEXT, blood_group TEXT,
  mobile TEXT, email TEXT, alt_mobile TEXT, address1 TEXT, address2 TEXT, city TEXT, state TEXT, pin TEXT, country TEXT,
  guardian_name TEXT, relation TEXT, guardian_mobile TEXT, guardian_email TEXT, occupation TEXT, income TEXT,
  board10 TEXT, school10 TEXT, year10 TEXT, roll10 TEXT, board12 TEXT, school12 TEXT, year12 TEXT, roll12 TEXT,
  other_qual TEXT, entrance_rank TEXT, entrance_roll TEXT, domicile TEXT,
  marks10 NUMERIC(5,2) CHECK (marks10 BETWEEN 0 AND 100),
  marks12 NUMERIC(5,2) CHECK (marks12 BETWEEN 0 AND 100),
  merit NUMERIC(6,2) GENERATED ALWAYS AS (ROUND(0.4 * marks10 + 0.6 * marks12, 2)) STORED);
CREATE INDEX IF NOT EXISTS idx_app_prog_merit ON applications(program_code, merit DESC);

CREATE TABLE IF NOT EXISTS documents (
  id SERIAL PRIMARY KEY, application_id INT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  doc_type VARCHAR(20) NOT NULL, filename TEXT, mime TEXT, size INT, data TEXT, uploaded_at TIMESTAMP DEFAULT NOW(),
  UNIQUE (application_id, doc_type));

CREATE TABLE IF NOT EXISTS payments (
  id SERIAL PRIMARY KEY, application_id INT NOT NULL REFERENCES applications(id),
  txn_id TEXT, method TEXT, amount NUMERIC(10,2), status TEXT, paid_at TIMESTAMP DEFAULT NOW());

CREATE TABLE IF NOT EXISTS notifications (
  id SERIAL PRIMARY KEY, user_id INT NOT NULL REFERENCES users(id), message TEXT NOT NULL,
  is_read BOOLEAN DEFAULT FALSE, created_at TIMESTAMP DEFAULT NOW());

CREATE TABLE IF NOT EXISTS password_resets (
  user_id INT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL, expires_at TIMESTAMP NOT NULL);

ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT TRUE;
CREATE TABLE IF NOT EXISTS email_verifications (
  user_id INT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL, expires_at TIMESTAMP NOT NULL, created_at TIMESTAMP NOT NULL DEFAULT NOW());
