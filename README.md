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
| **Task 03** | **[Security Log Investigation — Forensic DFIR & Threat Analysis](./Task-03-SecurityLogInvestigation/)** | Digital Forensics & Incident Response (DFIR) | Normalized RFC 5737 Logs, Detection Rules (Sigma/SPL), Evidence vs Assumptions Timeline, Incident Report PDF, 7 Automated Tests | ✅ **Completed** |

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

---

## 🔍 Task 03 Highlight: Security Log Investigation & DFIR Analysis

**Direct Directory Link:** [`./Task-03-SecurityLogInvestigation/`](./Task-03-SecurityLogInvestigation/)

### 🎯 My Objective
I was tasked with conducting a digital forensics and incident response (DFIR) investigation on a synthetic student portal authentication log (`authentication-log-sample.csv`) containing 12 events. The objective was to turn raw event records into **defensible detection findings**, reconstruct a verifiable **incident timeline** strictly separating empirical evidence from analytical assumptions, define production-ready **SIEM detection rules**, and compile a publication-grade executive **Incident Report PDF**.

### 🛡️ Key Forensic Findings
1. **Targeted Vertical Brute Force (`T1110.001`):** External host `198.51.100.27` (Windows) executed 3 consecutive failed logins against account `stu-117` in 34 seconds (pacing: 17s delta), triggering an automated account lockout at 09:05:03Z.
2. **Horizontal Password Spraying (`T1110.003`):** Hostile proxy IP `203.0.113.42` targeted 4 distinct accounts (`stu-209`, `stu-311`, `stu-415`, `stu-502`) in 12 seconds with missing/generic User-Agent (`unknown`), triggering an edge rate-limiting block at 09:22:01Z.
3. **Post-Spray Access Anomaly (`T1078`):** Sprayed user `stu-311` authenticated successfully 145 minutes post-spray from internal campus network `192.0.2.99` on an `iOS` device. Differentiated benign student arrival hypothesis from credential compromise, recommending immediate out-of-band identity verification and token revocation.

### 📑 Task 03 Documentation & Code Deliverables
Inside [`./Task-03-SecurityLogInvestigation/`](./Task-03-SecurityLogInvestigation/):
- 🎥 [`documentation/demo-task3.mp4`](./Task-03-SecurityLogInvestigation/documentation/demo-task3.mp4) — Live demonstration video walkthrough (1080p Full HD, 01:38.5 duration).
- 📸 [`EVIDENCE.md`](./Task-03-SecurityLogInvestigation/EVIDENCE.md) — Step-by-step verification log embedding 10 screenshots from [`documentation/`](./Task-03-SecurityLogInvestigation/documentation/).
- 📘 [`INCIDENT-REPORT.pdf`](./Task-03-SecurityLogInvestigation/INCIDENT-REPORT.pdf) — Complete 6-page executive report rendered via WeasyPrint with timeline charts and threat model.
- 📓 [`notebooks/security_investigation.ipynb`](./Task-03-SecurityLogInvestigation/notebooks/security_investigation.ipynb) — Interactive Jupyter investigation notebook with dataframes, detection algorithms, and plots.
- ⏱️ [`TIMELINE.md`](./Task-03-SecurityLogInvestigation/TIMELINE.md) — 12-event forensic reconstruction strictly separating empirical evidence from analytical assumptions.
- 🎯 [`THREAT-MODEL.md`](./Task-03-SecurityLogInvestigation/THREAT-MODEL.md) — 6-part defensive lab threat model (Asset, Boundary, Scenario, Existing Control, Risk Rating, Mitigation).
- 🚨 [`rules/sigma_rules.yml`](./Task-03-SecurityLogInvestigation/rules/sigma_rules.yml) & [`rules/siem_queries.spl`](./Task-03-SecurityLogInvestigation/rules/siem_queries.spl) — Production-ready Sigma rules and Splunk SPL hunting queries.
- 🔒 [`HARDENING-AND-CONTAINMENT.md`](./Task-03-SecurityLogInvestigation/HARDENING-AND-CONTAINMENT.md) — Tactical containment playbooks, multi-tier rate limiting, and JA3/JA4 TLS logging upgrades.
- 🧪 [`tests/test_detection_engine.py`](./Task-03-SecurityLogInvestigation/tests/test_detection_engine.py) — 7 automated unit tests passing with 100% success.
- ✅ [`CHECKLIST.md`](./Task-03-SecurityLogInvestigation/CHECKLIST.md) — Passing checklist verification log.

### 🚀 How to Run Task 03 Locally

```bash
cd Task-03-SecurityLogInvestigation

# Run 7 automated security unit tests
python3 -m unittest discover -s tests -p "test_*.py" -v

# Run log normalizer and detection engine
python3 src/normalizer.py
python3 src/detection_engine.py

# Re-generate the executive PDF report
python3 src/generate_report_pdf.py

# Start the interactive SOC investigation dashboard
python3 app.py
```

Open your browser to: **`http://127.0.0.1:8080`**

