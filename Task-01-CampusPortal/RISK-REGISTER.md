# CampusPortal - Risk Register

> **Defensive Cybersecurity Lab Risk Register**  
> **Evaluation Framework:** STRIDE Categorization with Qualitative Risk Matrix (Likelihood × Impact)  
> **Risk Scoring:** Low, Medium, High, Critical

---

## 1. Risk Evaluation Matrix

| Likelihood \ Impact | Low Impact | Medium Impact | High Impact | Critical Impact |
| :--- | :---: | :---: | :---: | :---: |
| **High Likelihood** | Medium | High | Critical | Critical |
| **Medium Likelihood**| Low | Medium | **High** | Critical |
| **Low Likelihood** | Low | Low | **Medium** | **High** |

---

## 2. Risk Register Table

| ID | Asset | Threat Description | STRIDE | Likelihood | Impact | Overall Risk | Existing Control | Recommended Mitigation | Verification Method |
| :---: | :--- | :--- | :---: | :---: | :---: | :---: | :--- | :--- | :--- |
| **RR-01** | User Credentials | Online password brute-force or dictionary guessing against login | Spoofing | Medium | High | **High** | In-memory rate limiting (max 5 failed attempts per 60s per IP/username); logs `LOGIN_RATE_LIMITED`. | Progressive exponential backoff delays, account lockouts, password complexity rules. | Automated script sending 6 failed logins; assert 6th returns HTTP 429. |
| **RR-02** | User Sessions | Session hijacking or credential sniffing over insecure transport | Spoofing | Low | High | **Medium** | `HttpOnly=True`, `SameSite='Lax'`, 30-min expiration, session cleared upon login. | Enable `SESSION_COOKIE_SECURE=True` under TLS/HTTPS; bind session to browser fingerprint. | Inspect HTTP response headers on `/login` for `HttpOnly` and `SameSite`. |
| **RR-03** | Academic Records | Cross-faculty grade tampering / IDOR parameter manipulation | Tampering | Low | High | **Medium** | Server-side course-faculty ownership verification; rejects mismatch with HTTP 403. | Cryptographic HMAC signing of grade record IDs; require dual-faculty approval. | Run unit test `test_faculty_cross_course_grade_tampering_blocked`. |
| **RR-04** | Student Profile | Profile parameter tampering (injecting `role=admin` or altering Student ID) | Tampering | Low | Medium | **Low** | Parameterized SQL updating strictly whitelist fields (`email`, `phone`, `dept`, `semester`). | Formal schema validator (Pydantic/Marshmallow) to reject extra payload keys. | Submit POST with `role=admin` to `/student/profile`; verify DB role is unchanged. |
| **RR-05** | Audit Trail & Grades | Repudiation of grade adjustments or user deactivations | Repudiation | Low | Medium | **Low** | Application-level append-oriented audit logging to the `audit_logs` table with ISO timestamp, IP, username. | The application audit log provides accountability and forensic evidence for recorded actions. It should not be treated as cryptographically immutable or as providing strong non-repudiation. Stronger guarantees would require external append-only/WORM storage, hash chaining, or equivalent tamper-evident controls. | Query `audit_logs` table after grade modification to verify user attribution. |
| **RR-06** | Student Records | Information disclosure via direct endpoint crawling or BOLA | Information Disclosure | Low | High | **Medium** | `@roles_required` decorator checks session and role; query filters by student ID. | Cache-Control: `no-store` on all authenticated endpoints; rate limit API queries. | Run test suite unauthenticated access checks; assert 302 redirect to `/login`. |
| **RR-07** | Application Internals | Information leakage via uncaught runtime exception stack traces | Information Disclosure | Low | Medium | **Low** | Custom error handlers for 400, 403, 404, 500 rendering generic templates; `DEBUG=False`. | Centralized JSON logging to stderr for ops while displaying sanitized UI errors. | Request non-existent or malformed URL; verify no Python traceback is visible. |
| **RR-08** | Portal Service | Denial of service via login password hashing CPU exhaustion | Denial of Service | Medium | Medium | **Medium** | Sliding-window rate limiter drops excessive requests before executing hash functions. | Reverse proxy (NGINX) with rate limiting; Redis-backed distributed limiter. | Load-test 20 rapid login attempts; verify requests 6–20 drop instantly with 429. |
| **RR-09** | Role State | Vertical privilege escalation (Student accessing Admin endpoints) | Elevation of Privilege | Low | Critical | **High** | `@roles_required('admin')` validates session and re-checks database active status. | Multi-Factor Authentication (MFA/TOTP) for all administrator accounts. | Run `test_student_cannot_access_faculty_or_admin_pages`; assert 403. |
| **RR-10** | Database Records | SQL Injection leading to complete database compromise | Tampering / Info Disclosure | Low | Critical | **High** | 100% parameterized SQLite queries using `?` placeholders; zero string formatting in SQL. | Static analysis security testing (SAST) in CI pipeline; SQLite read-only replicas. | Code inspection of all `cursor.execute` calls; automated test suite verification. |
| **RR-11** | User Sessions | Cross-Site Request Forgery (CSRF) on state-altering actions | Tampering | Low | High | **Medium** | Synchronizer token pattern (`_csrf_token` checked on all POSTs); `SameSite='Lax'`. | Double-submit cookie validation; custom header validation (`X-Requested-With`). | Run `test_post_without_csrf_token_rejected`; assert HTTP 400. |
| **RR-12** | Audit Logs | In-situ audit log modification or tampering by rogue admin | Tampering | Low | High | **Medium** | Application code exposes only `SELECT` queries on `audit_logs`; no UI update/delete. | Restrict OS-level write access to database file; export to external SIEM. | Code review confirming zero `UPDATE` or `DELETE` statements on `audit_logs`. |
