# CampusPortal - Security Hardening Checklist

> **Defensive Prioritization:** P0 (Critical) &bull; P1 (High) &bull; P2 (Medium) &bull; P3 (Low)  
> **Target:** CampusPortal Local Defensive Lab & Production Readiness Roadmap

---

## Priority P0: Critical (Foundational Security Controls)

*These controls mitigate existential threats such as authentication bypass, full database takeover, and total system compromise.*

| # | Security Control | Why It Matters | Implementation Status | Verification Method |
| :---: | :--- | :--- | :---: | :--- |
| **P0-1** | **Strict Localhost Network Binding** | Prevents unintended network exposure and external probing of defensive lab software. | **Implemented** | Inspect `config.py` and `app.py`; verify host is hardcoded to `127.0.0.1` and `debug=False`. Run `netstat -tlpn` or unit test. |
| **P0-2** | **Parameterized SQL Queries (SQLi Prevention)** | Raw string concatenation in SQL queries allows attackers to bypass authentication and dump tables. | **Implemented** | Code review confirms 100% of SQLite database queries use parameterized `?` placeholders. Unit test suite passes. |
| **P0-3** | **Cryptographic Password Hashing** | Storing plaintext or weakly hashed passwords exposes all user credentials upon database disclosure. | **Implemented** | Passwords hashed using Werkzeug (`scrypt`/`pbkdf2:sha256`) with unique per-user salts. Verified in `test_synthetic_seed_data_and_password_hashing`. |
| **P0-4** | **Server-Side Role-Based Access Control (RBAC)** | Lower-tier users (students) must never access administrative or faculty functionality. | **Implemented** | Enforced via `@roles_required` decorator on all controller endpoints; verifies both session role and active database state. |
| **P0-5** | **Zero External Network Dependencies** | External CDNs, APIs, or fonts introduce supply-chain risks and violate air-gapped lab isolation. | **Implemented** | All CSS and JS assets are local vanilla files. Zero outgoing network calls made by Flask runtime. |

---

## Priority P1: High (Access Control & Session Hardening)

*These controls protect active user sessions, prevent authorization tampering, and block brute-force abuse.*

| # | Security Control | Why It Matters | Implementation Status | Verification Method |
| :---: | :--- | :--- | :---: | :--- |
| **P1-1** | **Session Cookie Isolation (`HttpOnly`, `SameSite`)** | `HttpOnly` stops XSS token theft; `SameSite=Lax` stops cross-origin session riding. | **Implemented** | Verified via response headers in `test_security_headers_present`. `HttpOnly=True` and `SameSite=Lax` confirmed. |
| **P1-2** | **Session Fixation Prevention** | Reusing session identifiers across authentication boundaries allows session hijacking. | **Implemented** | `session.clear()` and CSRF token regeneration executed on successful login before populating authenticated session keys. |
| **P1-3** | **Course Ownership / IDOR Authorization** | Faculty must only be able to modify grades for courses assigned to them, not other instructors. | **Implemented** | Server-side query verifies `courses.faculty_id == session.faculty_id`. Verified in `test_faculty_cross_course_grade_tampering_blocked`. |
| **P1-4** | **Cross-Site Request Forgery (CSRF) Tokens** | Attackers could otherwise trick authenticated users into submitting unauthorized POST requests. | **Implemented** | Cryptographic synchronizer tokens generated per session and validated on all POST routes. Tested via `test_post_without_csrf_token_rejected`. |
| **P1-5** | **Login Rate Limiting** | Automated credential stuffing and brute-force guessing against user accounts. | **Implemented** | Sliding-window tracker throttles after 5 failed attempts per 60s per IP/username, returning HTTP 429. Tested in `test_login_rate_limiting`. |

---

## Priority P2: Medium (Integrity, Defense-in-Depth & Accountability)

*These controls ensure system state integrity, provide forensic logging, and reduce attack surface.*

| # | Security Control | Why It Matters | Implementation Status | Verification Method |
| :---: | :--- | :--- | :---: | :--- |
| **P2-1** | **Security Audit Logging** | Application security events are recorded in the local `audit_logs` SQLite table. The logging mechanism supports accountability and forensic review by recording relevant administrative and security actions.<br><br>**Limitation:** The local SQLite audit log is not cryptographically tamper-evident or externally immutable. Stronger tamper resistance can be achieved through external append-only/WORM storage, hash chaining, or a remote SIEM. | **Implemented** | System lifecycle events (`LOGIN_SUCCESS`, `LOGIN_FAILURE`, `ACCESS_DENIED`, `GRADE_UPDATE`, `USER_CREATED`, `USER_STATUS_TOGGLED`) written to `audit_logs`. |
| **P2-2** | **Sensitive Credential Exclusion from Logs** | Logging raw passwords or secret tokens in logs creates a secondary data leakage vector. | **Implemented** | Audit logger explicitly accepts only event metadata and status; passwords and tokens are never passed or stored. |
| **P2-3** | **Security Headers (CSP, Frame-Options, Content-Type)** | Defense-in-depth against UI redressing (clickjacking), MIME sniffing, and script injection. | **Implemented** | Headers injected via `@app.after_request`: `CSP`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`. |
| **P2-4** | **Strict Server-Side Input Validation** | Client-side controls can be bypassed by sending arbitrary HTTP requests via curl or proxies. | **Implemented** | Whitelist validation on email format, phone format, semester (1–8), departments, and score ranges (0.0–50.0). |
| **P2-5** | **Administrative Self-Deactivation Guard** | Administrators accidentally or maliciously deactivating themselves locks down system administration. | **Implemented** | Server logic rejects deactivation when `target_user_id == session.user_id`. Verified in `test_admin_cannot_self_deactivate`. |

---

## Priority P3: Low (Hardening for Future Production Environments)

*Operational enhancements for enterprise production deployments outside of the local lab.*

| # | Security Control | Why It Matters | Implementation Status | Verification Method |
| :---: | :--- | :--- | :---: | :--- |
| **P3-1** | **Enforce HTTPS / TLS (`SESSION_COOKIE_SECURE`)** | Protects data in transit from eavesdropping on public or local networks. | **Roadmap** *(Disabled for localhost HTTP)* | Toggle `SESSION_COOKIE_SECURE = True` in `config.py` and deploy behind reverse proxy with valid TLS certificate. |
| **P3-2** | **Multi-Factor Authentication (MFA / TOTP)** | Mitigates credential compromise for high-privilege administrative and faculty accounts. | **Roadmap** | Implement RFC 6238 TOTP using `pyotp` with QR code provisioning during onboarding. |
| **P3-3** | **Remote Centralized Syslog / SIEM Forwarding** | Prevents local log tampering even if the local database file is compromised. | **Roadmap** | Configure Python `logging.handlers.SysLogHandler` to forward JSON log records to a remote SIEM. |
| **P3-4** | **Account Lockout & CAPTCHA on Repeated Failures** | Adds friction against distributed credential-stuffing attacks across botnets. | **Roadmap** | Implement progressive delays and temporary lockout timers after consecutive failed rate-limit events. |
| **P3-5** | **Automated Database Backup with Integrity Verification** | Protects institutional academic records from catastrophic corruption or ransomware. | **Roadmap** | Scheduled SQLite VACUUM INTO snapshots with SHA-256 integrity hash verification. |
