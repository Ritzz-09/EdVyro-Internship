# 🛡️ EdVyro Internship — Cybersecurity & Defensive Security Portfolio

This repository contains the practical security engineering projects, threat-modeling assessments, and defensive laboratory applications completed as part of the **EdVyro Cybersecurity Internship**.

Each task is structured into its own self-contained directory containing the source code, security controls, threat models, risk registers, automated tests, and photographic evidence.

---

## 📂 Repository Index of Tasks

| Task # | Lab / Project Title | Focus Area | Key Deliverables | Status |
|:---:|:---|:---|:---|:---:|
| **Task 01** | **[CampusPortal — Threat-Modeling & Defensive SIS Lab](./Task-01-CampusPortal/)** | Application Security & Threat Modeling | STRIDE Threat Model, Risk Register, Hardening Roadmap, 18 Automated Unit Tests, 9 Screenshot Evidences | ✅ **Completed** |
| **Task 02** | *Upcoming Internship Task* | Network / Cloud / PenTesting | Documentation, Exploits/Defenses, Evidence | ⏳ Planned |
| **Task 03** | *Upcoming Internship Task* | Vulnerability Assessment | Technical Report, Remediations | ⏳ Planned |

---

## 🔬 Task 01 Overview: CampusPortal Local Defensive SIS Lab

**Directory:** [`./Task-01-CampusPortal/`](./Task-01-CampusPortal/)

### 🎯 Objective
Design, implement, and threat-model a realistic institutional Student Information System (SIS) web application bound strictly to `127.0.0.1` (localhost) using synthetic mock data. The application serves as a defensive baseline to evaluate using the Microsoft STRIDE methodology.

### 🛠️ Tech Stack & Constraints
- **Runtime:** Python 3 + Flask (monolithic server-side rendered)
- **Database:** SQLite 3 with enforced foreign keys and 100% parameterized queries
- **Frontend:** Vanilla HTML5, CSS3, JavaScript (zero external CDNs or remote APIs)
- **Isolation:** Bound strictly to `127.0.0.1:5000` (offline defensive lab)

### 🛡️ Implemented Defensive Security Controls
1. **Authentication & Password Security:** Werkzeug adaptive password hashing (`scrypt`/`pbkdf2:sha256`) with unique salts.
2. **Session Hardening:** `HttpOnly=True`, `SameSite='Lax'`, 30-minute expiration, and session re-generation on login.
3. **Role-Based Access Control (RBAC):** Strict `@roles_required` decorator enforcing Student, Faculty, and Admin separation; blocks privilege escalation with HTTP 403.
4. **Brute-Force Rate Limiting:** Sliding-window in-memory rate limiter dropping attempts exceeding 5 failures per 60 seconds with HTTP 429.
5. **CSRF Protection:** Cryptographic synchronizer tokens required on all state-altering POST requests.
6. **Data Integrity & IDOR Defense:** Course-instructor ownership verification preventing cross-faculty grade tampering.
7. **User Lifecycle Management:** Administrative account deactivation with instant session invalidation and login blocking.
8. **Tamper-Evident Audit Logging:** Real-time event telemetry (`audit_logs`) tracking security events while strictly excluding plaintext secrets.
9. **Defense-in-Depth Headers:** `Content-Security-Policy: default-src 'self'`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`.

---

## 📑 Task 01 Documentation & Evidence Deliverables

Inside [`./Task-01-CampusPortal/`](./Task-01-CampusPortal/):

- 📘 [`README.md`](./Task-01-CampusPortal/README.md) — Complete setup instructions, demo credentials, and route breakdown.
- 📐 [`ARCHITECTURE.md`](./Task-01-CampusPortal/ARCHITECTURE.md) — System architecture, 3 trust boundaries, ER diagram, and authentication/grade data flows.
- 🎯 [`THREAT-MODEL.md`](./Task-01-CampusPortal/THREAT-MODEL.md) — Complete STRIDE threat analysis across 10 realistic threat scenarios.
- 📊 [`RISK-REGISTER.md`](./Task-01-CampusPortal/RISK-REGISTER.md) — Ranked qualitative risk matrix with likelihood, impact, and existing mitigations.
- 🛡️ [`HARDENING-CHECKLIST.md`](./Task-01-CampusPortal/HARDENING-CHECKLIST.md) — Prioritized P0 (Critical) to P3 (Low) defensive hardening roadmap.
- 📸 [`EVIDENCE.md`](./Task-01-CampusPortal/EVIDENCE.md) — Annotated evidence collection guide embedding all 9 captured screenshots from [`documentation/`](./Task-01-CampusPortal/documentation/).

---

## 🚀 Quickstart: Running Task 01 Locally

```bash
# Navigate to Task 01 directory
cd Task-01-CampusPortal

# Run the 18 automated security unit tests
python3 -m unittest discover -s tests -p "test_*.py" -v

# Start the application locally
python3 app.py
```

Open your browser to: **`http://127.0.0.1:5000`**

### Demo Accounts for Testing:
- **Student:** `alice_student` / `StudentPass123!` or `bob_student` / `StudentPass123!`
- **Faculty:** `prof_smith` / `FacultyPass123!` or `prof_chen` / `FacultyPass123!`
- **Admin:** `admin_user` / `AdminPass123!`
