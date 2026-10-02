# CampusPortal - Fictional Student Portal for Threat Modeling

> **⚠️ AUTHORIZED LOCAL DEFENSIVE LAB ONLY**  
> This application is strictly designed and configured for local defensive security education, cybersecurity threat-modeling exercises, and application hardening assignments.  
> **Binding:** Strictly binds to `127.0.0.1` (localhost).  
> **Network:** Makes ZERO external API calls, downloads zero third-party CDNs, and does not scan or interact with any external networks.  
> **Data:** Uses 100% synthetic mock student, faculty, and administrative data. No real personal data is ever used.

---

## 1. Project Purpose

**CampusPortal** is a lightweight, realistic academic portal web application developed in Python/Flask and SQLite. It provides students, faculty members, and administrators with role-specific dashboards to view courses, update contact profiles, enter grades, and monitor institutional attendance.

Rather than being an intentionally vulnerable "hacking challenge" full of contrived flaws, CampusPortal implements a solid baseline of defensive controls (password hashing, CSRF tokens, session isolation, input validation, parameterized SQL queries, login rate limiting, security headers, and structured audit logging). This provides a realistic target for:
- STRIDE Threat Modeling
- Architecture and Trust Boundary decomposition
- Risk Assessment and Risk Register compilation
- Defensive Security Hardening and verification

The entire codebase is intentionally clean, modular, and dependency-light so that instructors and cybersecurity students can inspect and comprehend the entire system in **45–60 minutes**.

---

## 2. Tech Stack & Dependencies

- **Backend:** Python 3 (standard library) + Flask 3.x
- **Authentication & Security:** Werkzeug (`generate_password_hash`, `check_password_hash`, secure token generation)
- **Database:** SQLite 3 (built into Python standard library, parameterized queries, foreign keys enabled)
- **Frontend:** Server-side rendered Jinja2 templates, vanilla HTML5, CSS3, and JavaScript (100% offline, zero external font or script CDN dependencies)
- **Host Binding:** `127.0.0.1:5000` (strictly localhost)

---

## 3. Quickstart & Local Setup

### Prerequisites
- Python 3.9+ installed
- Flask (`pip install flask`)

### Step 1: Clone or Navigate to Directory
```bash
cd /home/ritzz-07/Downloads/internship1
```

### Step 2: Initialize Database with Synthetic Data
The database automatically initializes upon first run, or you can explicitly trigger seeding:
```bash
python3 database.py
```
This generates `campus_portal.db` seeded with synthetic student records, courses, grades, attendance, and audit logs.

### Step 3: Run the Application (Strictly Localhost)
```bash
python3 app.py
```
Output:
```text
==================================================================
 ⚠️  CAMPUSPORTAL - LOCAL DEFENSIVE CYBERSECURITY LAB
 Strict Localhost Binding: http://127.0.0.1:5000
 No external network connections. Synthetic demo data only.
==================================================================
 * Running on http://127.0.0.1:5000
```

Open your browser to: **`http://127.0.0.1:5000`**

---

## 4. Synthetic Demo Accounts

The login interface (`/login`) includes interactive quick-fill buttons for instant testing. All accounts are synthetic:

| Role | Username | Password | Identity / ID Code | Department | Key Permissions |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Student** | `alice_student` | `StudentPass123!` | Alice Vance (`STU-2024-001`) | Computer Science | View grades, attendance, edit non-sensitive profile (email, phone) |
| **Student** | `bob_student` | `StudentPass123!` | Bob Martinez (`STU-2024-002`) | Cybersecurity | View enrolled courses, grades, attendance |
| **Faculty** | `prof_smith` | `FacultyPass123!` | Prof. Arthur Smith (`FAC-2021-010`) | Computer Science | Manage assigned courses (CS101, CS305), enter & update student marks |
| **Faculty** | `prof_chen` | `FacultyPass123!` | Dr. Maya Chen (`FAC-2022-015`) | Cybersecurity | Manage assigned courses (SEC201), update grades |
| **Administrator** | `admin_user` | `AdminPass123!` | Dr. Evelyn Reed (`ADM-2020-001`) | IT Administration | Provision users, activate/deactivate accounts, inspect tamper-evident audit logs |

---

## 5. Core Application Routes

| URL Endpoint | Method | Role Required | Description |
| :--- | :--- | :--- | :--- |
| `/login` | `GET`, `POST` | Public | Authenticates credentials with rate-limiting & CSRF protection |
| `/logout` | `POST` | Authenticated | Terminates session, clears cookies, writes audit record |
| `/student/dashboard` | `GET` | Student | Academic overview, course summary, attendance %, announcements |
| `/student/profile` | `GET`, `POST` | Student | View student credentials; edit non-sensitive email, phone, semester |
| `/student/grades` | `GET` | Student | Course-by-course transcript of midterm, final, and total marks |
| `/student/attendance`| `GET` | Student | Attendance rate per course against 75% examination threshold |
| `/faculty/dashboard` | `GET` | Faculty | Assigned course sections and enrolled student count |
| `/faculty/grades` | `GET` | Faculty | Course selection & student marks roster |
| `/faculty/update-grade`| `POST` | Faculty | Update marks for assigned course with authorization check & audit log |
| `/admin/dashboard` | `GET` | Admin | Administrative statistics and quick audit snapshot |
| `/admin/users` | `GET` | Admin | Roster of all system principals and account states |
| `/admin/create-user` | `POST` | Admin | Provision new synthetic student or faculty account |
| `/admin/toggle-user-status`| `POST`| Admin | Deactivate/activate user accounts (with self-lockout guard) |
| `/admin/audit` | `GET` | Admin | Filterable security audit trail explorer |

---

## 6. Baseline Defensive Security Controls

1. **Cryptographic Password Hashing**: Passwords are never stored in plaintext. Hashed using Werkzeug `scrypt`/`pbkdf2:sha256` with unique salts.
2. **Session Hardening**: Flask session cookies configured with `HttpOnly=True` (blocks XSS credential extraction), `SameSite='Lax'` (mitigates CSRF), and 30-minute idle expiration.
3. **Role-Based Access Control (RBAC)**: Enforced via the `@roles_required(*roles)` decorator. Any attempt by a lower-privilege role to access unauthorized endpoints immediately triggers a `403 Forbidden` response and an `ACCESS_DENIED` audit log.
4. **IDOR & Ownership Validation**: Faculty members can only modify grades for courses assigned to them; cross-faculty grade tampering is blocked at the business logic layer.
5. **CSRF Protection**: Synchronizer token pattern with cryptographically secure tokens (`secrets.token_hex`) required on all state-altering `POST` requests.
6. **Input Validation**: Strict type, length, regex, and boundary checks (e.g. scores capped at 50.0; semester constrained to 1–8; allowed department whitelist).
7. **Parameterized Database Queries**: All SQLite interactions utilize parameterized queries (`?` placeholders) with strict separation of code and data, eliminating SQL injection.
8. **In-Memory Login Rate Limiting**: Throttles brute-force attempts (maximum 5 failed attempts per 60 seconds per IP/account), issuing HTTP `429 Too Many Requests`.
9. **Tamper-Evident Audit Logging**: Logs security-relevant lifecycle events (`LOGIN_SUCCESS`, `LOGIN_FAILURE`, `LOGOUT`, `PROFILE_UPDATE`, `GRADE_UPDATE`, `USER_CREATED`, `ACCESS_DENIED`). Sensitive credentials/passwords are strictly excluded.
10. **Information Disclosure Prevention**: Custom error handlers (400, 403, 404, 500) suppress Python stack traces and server debug internals.
11. **Security Headers**: Injected via `@app.after_request` (`Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy`).

---

## 7. Running the Automated Test Suite

A complete verification test suite is included in `tests/test_app.py`:
```bash
python3 -m unittest discover -s tests -p "test_*.py" -v
```

This verifies:
- Password encryption & synthetic seed data
- Student, Faculty, and Admin authentication
- Login rate-limiting thresholds
- RBAC enforcement (blocking students from faculty/admin pages)
- CSRF token validation on POST endpoints
- Student profile input validation
- Faculty grade editing and cross-course tampering defenses
- Admin account provisioning and deactivation guards
- Security headers presence and stack trace suppression
- Localhost network binding configuration

---

## 8. Threat-Modeling Assignment Documents

This repository includes a complete suite of cybersecurity threat-modeling deliverables:
- [`ARCHITECTURE.md`](file:///home/ritzz-07/Downloads/internship1/ARCHITECTURE.md) - System architecture, trust boundaries, components, and data flows.
- [`THREAT-MODEL.md`](file:///home/ritzz-07/Downloads/internship1/THREAT-MODEL.md) - Full STRIDE threat modeling analysis.
- [`RISK-REGISTER.md`](file:///home/ritzz-07/Downloads/internship1/RISK-REGISTER.md) - Tabular risk register with impact, likelihood, and mitigation mapping.
- [`HARDENING-CHECKLIST.md`](file:///home/ritzz-07/Downloads/internship1/HARDENING-CHECKLIST.md) - Prioritized P0–P3 defensive security roadmap.
- [`EVIDENCE.md`](file:///home/ritzz-07/Downloads/internship1/EVIDENCE.md) - Guide for collecting screenshot and log evidence for lab submission.
