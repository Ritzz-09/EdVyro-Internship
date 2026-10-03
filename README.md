# 🛡️ EdVyro Cybersecurity Internship Portfolio

> **Intern:** RITHISH S P (`@Ritzz-09`)  
> **Repository:** [https://github.com/Ritzz-09/EdVyro-Internship](https://github.com/Ritzz-09/EdVyro-Internship)  
> **Track:** Cybersecurity & Defensive Security Engineering  

Welcome to my cybersecurity internship portfolio repository! This repository documents the practical security engineering tasks, threat-modeling assessments, and defensive laboratory applications I developed during my internship at **EdVyro**.

Each task is organized into a dedicated, self-contained folder containing full source code, security architecture documentation, threat models, risk registers, automated tests, and photographic evidence.

---

## 📂 Index of Internship Tasks

| Task # | Lab / Project Title | Security Domain | Core Deliverables | Status |
|:---:|:---|:---|:---|:---:|
| **Task 01** | **[CampusPortal — Threat-Modeling & Defensive SIS Lab](./Task-01-CampusPortal/)** | Application Security & Threat Modeling | STRIDE Threat Model, Risk Register, Hardening Roadmap, 18 Automated Unit Tests, 9 Screenshot Evidences | ✅ **Completed** |
| **Task 02** | **[SecureAuth — Secure Authentication Lab Service](./Task-02-SecureAuth/)** | Authentication & Defensive Application Security | Bcrypt Hashing, Session Hardening, Rate Limiting, Generic Auth Errors, 21 Automated Unit Tests | ✅ **Completed** |
| **Task 03** | *Upcoming Internship Task* | Vulnerability Assessment | Remediation Analysis, Tool Output | ⏳ Planned |

---

## 🔬 Task 01 Highlight: CampusPortal Defensive SIS Lab

**Direct Directory Link:** [`./Task-01-CampusPortal/`](./Task-01-CampusPortal/)

### 🎯 My Objective
I was tasked with building and analyzing **CampusPortal**, a fictional Student Information System (SIS) web application. The core challenge was to build an application with solid baseline defenses, run it strictly on `127.0.0.1` (localhost), and conduct a comprehensive **STRIDE Threat Model** to identify and rank residual architectural risks.

### 🛠️ Tech Stack & Constraints
- **Backend:** Python 3 + Flask (monolithic server-side rendered architecture)
- **Database:** SQLite 3 with enforced foreign-key constraints and 100% parameterized queries
- **Frontend:** Server-side Jinja2 templates, local vanilla HTML5, CSS3, and JavaScript (100% offline, zero external CDNs)
- **Lab Scope:** Bound strictly to `127.0.0.1:5000` with 100% synthetic mock data

### 🛡️ Defensive Security Controls I Built
1. **Cryptographic Password Hashing:** Salted adaptive hashing (`scrypt`/`pbkdf2:sha256`) via Werkzeug; zero plaintext storage.
2. **Session Hardening:** Isolated session cookies (`HttpOnly=True`, `SameSite='Lax'`, 30-minute idle expiration).
3. **Role-Based Access Control (RBAC):** Custom `@roles_required` decorator enforcing Student, Faculty, and Admin separation; blocks privilege escalation with HTTP 403.
4. **Brute-Force Rate Limiting:** Sliding-window in-memory tracker that issues an HTTP 429 response after 5 failed attempts per 60 seconds.
5. **CSRF Protection:** Cryptographic synchronizer tokens required on all state-altering POST requests.
6. **Data Integrity & IDOR Defense:** Course-instructor ownership checks preventing cross-faculty grade tampering.
7. **User Lifecycle & Session Revocation:** Administrative account deactivation with instant session invalidation and login blocking.
8. **Tamper-Evident Audit Logging:** Real-time event telemetry (`audit_logs`) tracking security events while strictly excluding plaintext secrets.
9. **Defense-in-Depth Headers:** `Content-Security-Policy: default-src 'self'`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`.

---

## 📑 Task 01 Documentation & Evidence Deliverables

Inside [`./Task-01-CampusPortal/`](./Task-01-CampusPortal/):

- 📘 [`README.md`](./Task-01-CampusPortal/README.md) — My project statement, architecture decisions, and setup instructions.
- 📐 [`ARCHITECTURE.md`](./Task-01-CampusPortal/ARCHITECTURE.md) — Architectural decomposition, 3 trust boundaries, ER model, and data flows.
- 🎯 [`THREAT-MODEL.md`](./Task-01-CampusPortal/THREAT-MODEL.md) — My STRIDE threat model evaluating 10 realistic threat scenarios.
- 📊 [`RISK-REGISTER.md`](./Task-01-CampusPortal/RISK-REGISTER.md) — Ranked qualitative risk matrix evaluating likelihood vs. impact.
- 🛡️ [`HARDENING-CHECKLIST.md`](./Task-01-CampusPortal/HARDENING-CHECKLIST.md) — Prioritized P0 (Critical) to P3 (Low) defensive hardening roadmap.
- 📸 [`EVIDENCE.md`](./Task-01-CampusPortal/EVIDENCE.md) — My step-by-step verification log embedding all 9 captured screenshots from [`documentation/`](./Task-01-CampusPortal/documentation/).

---

## 🚀 How to Run Task 01 Locally

```bash
# Clone the repository
git clone https://github.com/Ritzz-09/EdVyro-Internship.git
cd EdVyro-Internship/Task-01-CampusPortal

# Run my 18 automated security unit tests
python3 -m unittest discover -s tests -p "test_*.py" -v

# Start the application on localhost
python3 app.py
```

Open your browser to: **`http://127.0.0.1:5000`**

### Demo Accounts for Testing:
- **Student:** `alice_student` / `StudentPass123!` or `bob_student` / `StudentPass123!`
- **Faculty:** `prof_smith` / `FacultyPass123!` or `prof_chen` / `FacultyPass123!`
- **Admin:** `admin_user` / `AdminPass123!`

---

## 🔒 Task 02 Highlight: Secure Authentication Lab

**Direct Directory Link:** [`./Task-02-SecureAuth/`](./Task-02-SecureAuth/)

### 🎯 My Objective
I was tasked with engineering **SecureAuth**, a robust local authentication microservice built with **Node.js** and **Express**. The objective was to design defense-in-depth authentication controls that neutralize credential stuffing, brute-force password guessing, user enumeration, session theft, and denial-of-service attacks.

### 🛡️ Defensive Controls Built
1. **Adaptive Cryptographic Hashing:** Salted `bcryptjs` hashing with work factor 10 ($2^{10} = 1024$ rounds); zero plaintext storage and zero password hash leakage across all APIs.
2. **Server-Side Input Validation & DoS Prevention:** Strict regex whitelisting (`/^[a-zA-Z0-9_]+$/`) and length limits (3–30 chars for usernames; 8–128 chars for passwords) to defeat injection and CPU-exhaustion DoS against bcrypt.
3. **Session Hardening:** Signed server-side sessions with `HttpOnly` (XSS mitigation), `SameSite=Lax` (CSRF mitigation), dynamic `Secure` cookies for production HTTPS, and 15-minute idle expiration TTL.
4. **Session Fixation Defense:** Instant session regeneration (`req.session.regenerate()`) upon successful authentication.
5. **Session Invalidation:** Explicit server-side session destruction (`req.session.destroy()`) and client cookie wipe on logout.
6. **Generic Error Messages & Timing Neutralization:** Uniform HTTP 401 `"Invalid username or password."` response paired with constant-time dummy hash verification to eliminate user enumeration.
7. **Authentication Rate Limiting:** IP-based sliding window rate limiter restricting login attempts to 5 per 15 minutes, returning HTTP 429.

### 📑 Task 02 Documentation Deliverables
Inside [`./Task-02-SecureAuth/`](./Task-02-SecureAuth/):
- 📘 [`README.md`](./Task-02-SecureAuth/README.md) — Comprehensive technical architecture, setup guide, and security controls breakdown.
- 📐 [`ARCHITECTURE.md`](./Task-02-SecureAuth/ARCHITECTURE.md) — Architectural decomposition, 3 trust boundaries, sequence diagrams, and request lifecycles.
- 🎯 [`THREAT-MODEL.md`](./Task-02-SecureAuth/THREAT-MODEL.md) — STRIDE threat model evaluating 11 realistic threat scenarios with risk scores.
- 📊 [`RISK-REGISTER.md`](./Task-02-SecureAuth/RISK-REGISTER.md) — Qualitative risk matrix evaluating pre- and post-mitigation risk ratings.
- 🛡️ [`HARDENING-CHECKLIST.md`](./Task-02-SecureAuth/HARDENING-CHECKLIST.md) — Prioritized P0 to P3 defensive hardening checklist and production guidelines.
- 📝 [`docs/security-note.md`](./Task-02-SecureAuth/docs/security-note.md) — Threat model matrix, defensive control mechanisms, and verification mapping.
- 📸 [`EVIDENCE.md`](./Task-02-SecureAuth/EVIDENCE.md) — Step-by-step verification log embedding captured screenshots from [`documentation/`](./Task-02-SecureAuth/documentation/).
- 🧪 [`tests/auth.test.js`](./Task-02-SecureAuth/tests/auth.test.js) — 21 automated unit and integration security tests passing with 100% success.

### 🚀 How to Run Task 02 Locally
```bash
cd Task-02-SecureAuth

# Install dependencies
npm install

# Run the 21 automated security tests
npm test

# Start the local demonstration server
npm start
```

Open your browser to: **`http://127.0.0.1:3000`**

