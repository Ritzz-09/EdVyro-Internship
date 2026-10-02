# CampusPortal - Preliminary STRIDE Threat Model

> **Threat-Modeling Methodology:** Microsoft STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)  
> **Target Application:** CampusPortal (Local Defensive Lab SIS)  
> **Evaluation Scope:** Authentication, Session State, Role-Based Access Control, Grade Modifications, Profile Edits, and Audit Logging

---

## 1. System Assets & Security Objectives

| Asset ID | Asset Name | Description | Confidentiality | Integrity | Availability |
| :--- | :--- | :--- | :---: | :---: | :---: |
| **A-1** | User Credentials | Passwords and session cookies for students, faculty, and admins | **High** | **High** | Medium |
| **A-2** | Student Academic Records | Midterm, final, total scores, and computed letter grades | Medium | **High** | Medium |
| **A-3** | Student Demographics (PII) | Names, emails, phone numbers, department, and semester | **High** | Medium | Low |
| **A-4** | Defensive Audit Trail | Historical event logs (`audit_logs`) tracking security actions | Medium | **High** | **High** |
| **A-5** | Service Availability | Responsiveness of Flask HTTP endpoints on 127.0.0.1 | Low | Low | **High** |
| **A-6** | Role & Identity State | Active/inactive flags and role assignments in database | **High** | **High** | Medium |

---

## 2. Comprehensive STRIDE Threat Analysis

### Threat TM-01: Credential Spoofing via Online Password Guessing
- **Asset:** A-1 (User Credentials)
- **STRIDE Category:** **Spoofing**
- **Threat Scenario:** An attacker on the local interface conducts automated dictionary or brute-force attacks against student or faculty accounts to gain unauthorized access.
- **Preconditions:** Attacker has network reachability to `127.0.0.1:5000` and possesses a list of usernames.
- **Existing Control:** In-memory sliding-window rate limiter restricting failed attempts to 5 per 60 seconds per IP/account; failed attempts return HTTP 429 and log `LOGIN_RATE_LIMITED`.
- **Likelihood:** Medium
- **Impact:** High
- **Risk Level:** **High (P1)**
- **Recommended Mitigation:**
  - Implement progressive backoff delays (e.g. exponential timeouts after 5 failures).
  - Add account lockout or temporary CAPTCHA if exposed in multi-user test environments.
  - Require minimum password complexity rules (length >= 10, uppercase, digit, symbol).
- **Verification Step:** Run automated script submitting 6 consecutive incorrect passwords. Verify that the 6th attempt is rejected with HTTP 429 and an audit entry is created.

---

### Threat TM-02: Session Hijacking via Insecure Cookie Transport or XSS
- **Asset:** A-1 (User Credentials / Session State)
- **STRIDE Category:** **Spoofing**
- **Threat Scenario:** An attacker steals a valid student or administrator session cookie via malicious JavaScript injection (XSS) or eavesdropping.
- **Preconditions:** Script execution vulnerability in browser or access to unencrypted HTTP network stream.
- **Existing Control:**
  - `SESSION_COOKIE_HTTPONLY = True`: Blocks JavaScript access to session cookies via `document.cookie`.
  - `SESSION_COOKIE_SAMESITE = 'Lax'`: Prevents cross-site cookie transmission.
  - Strict `Content-Security-Policy`: Blocks inline external scripts.
  - Session regeneration upon login: Prevents session fixation attacks.
- **Likelihood:** Low
- **Impact:** High
- **Risk Level:** **Medium (P2)**
- **Recommended Mitigation:**
  - Enable `SESSION_COOKIE_SECURE = True` whenever deployed behind HTTPS/TLS in production.
  - Implement per-session client-fingerprint binding (e.g. hashing User-Agent and subnet).
- **Verification Step:** Inspect response headers on `/login` to confirm `HttpOnly` and `SameSite=Lax` attributes on the `Set-Cookie` header.

---

### Threat TM-03: Unauthorized Grade Modification via IDOR / Cross-Faculty Tampering
- **Asset:** A-2 (Student Academic Records)
- **STRIDE Category:** **Tampering**
- **Threat Scenario:** A rogue faculty member or an authenticated attacker alters the `grade_id` parameter in a `POST /faculty/update-grade` request to tamper with student grades in a course taught by another instructor.
- **Preconditions:** Attacker is authenticated with the `faculty` role and intercepts/modifies HTTP POST request payloads.
- **Existing Control:** Server-side ownership validation query joins `grades` -> `enrollments` -> `courses` and strictly verifies `courses.faculty_id == session.faculty_id`. Rejects mismatches with `403 Forbidden` and logs `ACCESS_DENIED`.
- **Likelihood:** Low
- **Impact:** High
- **Risk Level:** **Medium (P2)**
- **Recommended Mitigation:**
  - Implement cryptographic HMAC signing or nonces for editable grade IDs.
  - Require second-faculty or department head approval for grade revisions beyond a set grace period.
- **Verification Step:** Execute unit test `test_faculty_cross_course_grade_tampering_blocked` to confirm that submitting a `grade_id` for another course triggers an immediate HTTP 403.

---

### Threat TM-04: Student Profile Parameter Tampering
- **Asset:** A-3 (Student Demographics) & A-6 (Role State)
- **STRIDE Category:** **Tampering**
- **Threat Scenario:** A student intercepts the `POST /student/profile` request and injects additional fields such as `role=admin`, `is_active=1`, or modifies their `student_id_code`.
- **Preconditions:** Attacker has an active student session.
- **Existing Control:** Server-side parameterized query explicitly updates only `email`, `phone`, `department`, and `semester`. System fields (`role`, `username`, `student_id_code`) are not read from the form payload. Strict regex and range validation applied.
- **Likelihood:** Low
- **Impact:** Medium
- **Risk Level:** **Low (P3)**
- **Recommended Mitigation:**
  - Formalize request schema parsing using a declarative validator (e.g. Marshmallow or Pydantic) to strictly reject extraneous form fields.
- **Verification Step:** Submit an HTTP POST request containing `role=admin` and `student_id_code=HACK-001` to `/student/profile`. Inspect the database to verify those fields remained untouched.

---

### Threat TM-05: Repudiation of Grade Adjustments or Administrative Actions
- **Asset:** A-4 (Defensive Audit Trail) & A-2 (Grades)
- **STRIDE Category:** **Repudiation**
- **Threat Scenario:** An instructor maliciously alters a student's grade or an administrator deactivates an account, and later denies having performed the action.
- **Preconditions:** Attacker holds valid faculty or administrator credentials.
- **Existing Control:** Application-level append-oriented audit logging to the `audit_logs` table capturing `timestamp` (UTC ISO), `event_type`, `user_id`, `username`, `ip_address`, and before/after details.
- **Likelihood:** Low
- **Impact:** Medium
- **Risk Level:** **Low (P3)**
- **Recommended Mitigation:**
  - The application audit log provides accountability and forensic evidence for recorded actions. It should not be treated as cryptographically immutable or as providing strong non-repudiation. Stronger guarantees would require external append-only/WORM storage, hash chaining, or equivalent tamper-evident controls.
- **Verification Step:** Trigger a grade update via `/faculty/update-grade`. Query `SELECT * FROM audit_logs WHERE event_type = 'GRADE_UPDATE'` and confirm username and timestamp are populated.

---

### Threat TM-06: Student Data Disclosure via Direct Endpoint Crawling (Broken Object Level Authorization)
- **Asset:** A-3 (Student Demographics) & A-2 (Grades)
- **STRIDE Category:** **Information Disclosure**
- **Threat Scenario:** An unauthenticated user or student crawls endpoints such as `/student/grades`, `/student/attendance`, or `/admin/users` to harvest private student records.
- **Preconditions:** Attacker attempts unauthorized HTTP GET requests.
- **Existing Control:**
  - `@roles_required` decorator validates session existence, active account status, and role privileges before controller execution.
  - Queries scope records strictly to `WHERE e.student_id = ?` using the authenticated user's session ID.
- **Likelihood:** Low
- **Impact:** High
- **Risk Level:** **Medium (P2)**
- **Recommended Mitigation:**
  - Ensure zero cache headers on all authenticated pages (`Cache-Control: no-store`).
  - Introduce token-bucket request throttling across all student endpoints.
- **Verification Step:** Run `test_unauthenticated_access_redirects_to_login` and `test_student_cannot_access_faculty_or_admin_pages`. Confirm redirect to login or 403 Forbidden.

---

### Threat TM-07: Information Disclosure via Python Stack Traces
- **Asset:** Application Internals / Source Paths
- **STRIDE Category:** **Information Disclosure**
- **Threat Scenario:** An attacker sends malformed HTTP parameters to cause uncaught runtime exceptions, viewing database structure and internal paths in debug tracebacks.
- **Preconditions:** Application encounters an unhandled exception or malformed input.
- **Existing Control:** Custom error handlers for 400, 403, 404, and 500 render sanitized, user-friendly HTML pages with zero debug tracebacks. `app.config['DEBUG'] = False`.
- **Likelihood:** Low
- **Impact:** Medium
- **Risk Level:** **Low (P3)**
- **Recommended Mitigation:**
  - Implement centralized structured JSON logging to stderr for operations teams while displaying generic reference IDs to users.
- **Verification Step:** Request a non-existent URL or submit malformed data. Verify response contains no strings matching `Traceback (most recent call last)`.

---

### Threat TM-08: Application Denial of Service via Authentication Flooding
- **Asset:** A-5 (Service Availability)
- **STRIDE Category:** **Denial of Service**
- **Threat Scenario:** An attacker sends hundreds of concurrent login requests to exhaust server worker threads and consume CPU cycles through password hashing functions (`scrypt`/`pbkdf2`).
- **Preconditions:** Attacker has network access to port 5000.
- **Existing Control:** In-memory rate limiting rejects requests exceeding 5 attempts per minute with HTTP 429 before expensive hash calculations are performed for throttled IPs.
- **Likelihood:** Medium
- **Impact:** Medium
- **Risk Level:** **Medium (P2)**
- **Recommended Mitigation:**
  - Deploy a reverse proxy (e.g. NGINX or Caddy) with `limit_req_zone` before application workers.
  - Use Redis-backed rate limiting to support distributed scaling.
- **Verification Step:** Run automated load simulation of 20 rapid login attempts. Verify responses 6 through 20 return HTTP 429 within 2ms without consuming CPU for hashing.

---

### Threat TM-09: Vertical Privilege Escalation to Administrator Role
- **Asset:** A-6 (Role & Identity State)
- **STRIDE Category:** **Elevation of Privilege**
- **Threat Scenario:** A student or faculty user attempts to navigate directly to `/admin/dashboard`, `/admin/users`, or trigger `/admin/create-user` to elevate privileges.
- **Preconditions:** Attacker possesses a valid non-admin user session.
- **Existing Control:**
  - `@roles_required('admin')` validates both the session role and checks the underlying database `users.role` column on every protected request.
  - All unauthorized attempts trigger `abort(403)` and log `ACCESS_DENIED` with client IP and username.
- **Likelihood:** Low
- **Impact:** Critical
- **Risk Level:** **High (P1)**
- **Recommended Mitigation:**
  - Implement Multi-Factor Authentication (MFA/TOTP) for all Level 3 (Admin) user accounts.
  - Require re-authentication before sensitive administrative actions.
- **Verification Step:** Execute unit test `test_student_cannot_access_faculty_or_admin_pages` and `test_faculty_cannot_access_admin_pages`. Confirm 403 status code and audit entry.

---

### Threat TM-10: Audit Log Tampering or Deletion
- **Asset:** A-4 (Defensive Audit Trail)
- **STRIDE Category:** **Tampering**
- **Threat Scenario:** A compromised admin or attacker uses the web interface or database access to delete or alter historical audit logs.
- **Preconditions:** Administrative session compromised or physical access to `campus_portal.db`.
- **Existing Control:** Web interface only exposes read-only audit log views (`SELECT * FROM audit_logs`). There are no UI endpoints or routes that execute `UPDATE` or `DELETE` on the `audit_logs` table.
- **Likelihood:** Low
- **Impact:** High
- **Risk Level:** **Medium (P2)**
- **Recommended Mitigation:**
  - Set SQLite database file system permissions to least-privilege.
  - Stream logs to an external write-only append service.
- **Verification Step:** Review `app.py` and confirm zero routes perform `UPDATE` or `DELETE` operations on `audit_logs`.
