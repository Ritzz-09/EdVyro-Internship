# Task 01: CampusPortal — Threat-Modeling & Defensive Web App

> **Author:** Ritzz (`@Ritzz-09`)  
> **Internship Track:** EdVyro Cybersecurity Internship  
> **Environment:** Strictly Localhost Isolated Lab (`127.0.0.1:5000`) &bull; **Data:** 100% Synthetic Demo Records  
> **Methodology:** Microsoft STRIDE Threat Modeling & Risk Assessment

---

## 1. Project Statement & Objectives

For this cybersecurity internship task, I designed and built **CampusPortal**—a realistic, lightweight Student Information System (SIS) engineered in Python, Flask, and SQLite. 

Rather than creating an intentionally broken "vulnerable lab" filled with contrived bugs, my goal was to construct a **realistic application with solid baseline defenses** (cryptographic password hashing, server-side RBAC, CSRF synchronizer tokens, parameterized queries, and login rate limiting). 

By building a defensively sound baseline first, I was able to perform a genuine **STRIDE Threat Model** to identify real-world residual architectural risks (such as single-factor admin access, in-memory rate-limiting limitations, and local log co-location) that persist even in modern, well-written web applications.

---

## 2. Key Architecture & Design Decisions

### Why I Chose This Minimalist Architecture:
1. **Zero External Dependencies & Offline Safety:**  
   I eliminated all external CDN links (no Bootstrap CDN, no remote Google Fonts, no external JS trackers). All CSS and JavaScript are vanilla and stored locally in `static/`. This guarantees the lab is 100% air-gapped and produces **zero outbound network traffic**.
2. **45-to-60 Minute Comprehension Time:**  
   To make this codebase easy for mentors and evaluators to inspect, I avoided heavy frameworks or complex ORMs. The entire core logic fits into 4 well-structured Python modules:
   - `app.py`: Flask routes, error handlers, and security headers.
   - `config.py`: Localhost binding (`127.0.0.1`) and session cookie configurations.
   - `database.py`: Relational SQLite schema (9 tables) and synthetic seed data.
   - `security.py`: Custom RBAC decorators, sliding-window rate limiter, and audit logger.
3. **Database Parameterization:**  
   I strictly used SQLite parameterized queries (`?` placeholders) throughout the application to eliminate SQL Injection (SQLi) vulnerabilities entirely.

---

## 3. Implemented Defensive Security Controls

Here is a summary of the security controls I implemented and verified:

- **Cryptographic Password Hashing:** Passwords are never stored in plaintext. Hashed using Werkzeug `scrypt`/`pbkdf2:sha256` with unique per-user salts.
- **Session Hardening:** Configured session cookies with `HttpOnly=True` (blocks XSS cookie harvesting) and `SameSite='Lax'` (mitigates cross-site request forgery).
- **Role-Based Access Control (RBAC):** Created a custom `@roles_required` decorator that validates both session claims and active database account status on every request.
- **Brute-Force Rate Limiting:** Implemented a sliding-window tracker that blocks IPs/accounts after 5 failed attempts within 60 seconds with an HTTP 429 response.
- **CSRF Token Protection:** Embedded unique cryptographic synchronizer tokens (`secrets.token_hex`) verified on every state-altering POST request.
- **Course Ownership (IDOR Defense):** Verified in the database that faculty members can only modify grades for course sections they are officially assigned to teach.
- **Account Deactivation & Session Revocation:** Allowed administrators to deactivate compromised user accounts; deactivation immediately revokes active sessions and blocks subsequent logins.
- **Forensic Audit Logging:** Built a dedicated `audit_logs` subsystem logging security events (`LOGIN_SUCCESS`, `ACCESS_DENIED`, `GRADE_UPDATE`, `USER_STATUS_TOGGLED`) while strictly scrubbing plaintext passwords from log entries.
- **Defensive HTTP Headers:** Enforced `Content-Security-Policy: default-src 'self'`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and `Referrer-Policy` via `@app.after_request`.

---

## 4. Synthetic Demo Credentials

To make testing easy, I included one-click demo login buttons directly on the `/login` page:

| Role | Username | Password | Full Name / Institutional ID | Primary Privileges |
|:---|:---|:---|:---|:---|
| **Student** | `alice_student` | `StudentPass123!` | Alice Vance (`STU-2024-001`) | View grades, attendance; update non-sensitive profile (email, phone, semester). |
| **Student** | `bob_student` | `StudentPass123!` | Bob Martinez (`STU-2024-002`) | View enrolled courses, marks, and attendance standing. |
| **Faculty** | `prof_smith` | `FacultyPass123!` | Prof. Arthur Smith (`FAC-2021-010`) | Manage assigned courses (`CS101`, `CS305`), view rosters, enter/update marks. |
| **Faculty** | `prof_chen` | `FacultyPass123!` | Dr. Maya Chen (`FAC-2022-015`) | Manage assigned courses (`SEC201`), enter/update marks. |
| **Admin** | `admin_user` | `AdminPass123!` | Dr. Evelyn Reed (`ADM-2020-001`) | Provision synthetic users, deactivate accounts, inspect defensive audit trail. |

---

## 5. How to Run & Verify My Lab Locally

### Step 1: Start the Local Flask Server
```bash
cd Task-01-CampusPortal
python3 app.py
```
Open your browser to: **`http://127.0.0.1:5000`**

### Step 2: Run My Automated Unit Test Suite
I wrote 18 automated unit tests covering all authorization checks, input validation, and security headers:
```bash
python3 -m unittest discover -s tests -p "test_*.py" -v
```
*(All 18 tests pass with 100% OK).*

---

## 6. Detailed Project Deliverables in This Folder

I have structured my analysis into dedicated cybersecurity deliverables:

- 📐 [`ARCHITECTURE.md`](ARCHITECTURE.md) — My decomposition of system components, 3 trust boundaries, ER model, and data flow diagrams.
- 🎯 [`THREAT-MODEL.md`](THREAT-MODEL.md) — My comprehensive STRIDE analysis covering 10 realistic threat scenarios (assets, preconditions, mitigations, and verification steps).
- 📊 [`RISK-REGISTER.md`](RISK-REGISTER.md) — My ranked qualitative risk matrix evaluating likelihood vs. impact.
- 🛡️ [`HARDENING-CHECKLIST.md`](HARDENING-CHECKLIST.md) — Prioritized P0 (Critical) to P3 (Low) defensive hardening roadmap.
- 📸 [`EVIDENCE.md`](EVIDENCE.md) — My personal verification log with all 9 screenshots embedded and annotated.

---

## 7. Lessons Learned & Key Takeaways

1. **Defense-in-Depth is Essential:** Implementing parameterized queries prevents SQL injection, but without server-side ownership checks (IDOR defenses), a malicious faculty member could still modify grades in courses they do not teach.
2. **Threat Modeling Beyond Common Vulnerabilities:** Even with zero OWASP Top 10 vulnerabilities present, architectural weaknesses—such as single-factor authentication on admin accounts and in-memory rate limiting—still expose the system to serious risks.
3. **Audit Logging & Accountability:** Real-time audit trails provide essential accountability and forensic telemetry for sensitive operations (such as grade modifications and account deactivations), though cryptographic immutability or strong non-repudiation requires external append-only storage or hash chaining.
