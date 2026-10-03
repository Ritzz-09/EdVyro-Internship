# 🛡️ Defensive Security Note: Threat Analysis & Control Verification

> **Intern:** Ritzz (`@Ritzz-09`)  
> **Internship Track:** EdVyro Cybersecurity Internship  
> **Lab Focus:** Task 02 — Secure Authentication Service  
> **Target Scope:** Strictly Localhost Isolation (`http://127.0.0.1:3000`)  
> **Format:** Hybrid Architectural Narrative & Empirical Verification Matrix

---

## 1. Executive Security Statement

Authentication services represent the primary gatekeeper for application security. In modern threat environments, authentication pipelines face diverse, automated, and distributed attacks ranging from credential stuffing and dictionary guessing to algorithmic Denial of Service (DoS) and subtle timing side-channels.

For **Task 02: Secure Authentication Lab**, I engineered a local authentication microservice built on **Node.js** and **Express** that implements layered defensive security controls (**Defense-in-Depth**). Every security control is enforced strictly on the server side, assuming that client-side forms and user-supplied parameters are untrusted and potentially hostile.

---

## 2. High-Level Architectural Threat Analysis & Defense Theory

### 2.1 Threat Vector 1: Credential Guessing & Automated Brute-Force
* **Attack Scenario:** Attackers deploy automated tooling (e.g. Hydra, Burp Intruder) to spray thousands of dictionary passwords against user accounts.
* **Defense Architecture:** Built with `express-rate-limit` as dedicated middleware applied directly to `/api/login`. It establishes an IP-based sliding window restricting attempts to 5 per 15-minute window. When breached, the service returns **HTTP 429 (Too Many Requests)** with RFC-compliant `RateLimit-*` telemetry headers and refuses to execute CPU-intensive password verification.

### 2.2 Threat Vector 2: User Enumeration & Side-Channel Timing Attacks
* **Attack Scenario:** Attackers differentiate valid usernames from invalid ones by observing discrepancies in error messages (e.g., *"User not found"* vs *"Incorrect password"*) or by timing server latency. Because password hashing takes ~70ms, a server that immediately returns for a non-existent user creates a measurable timing delta.
* **Defense Architecture:** 
  1. *Uniform Error Messages:* Both invalid passwords and non-existent usernames yield an identical status: `HTTP 401 Unauthorized` with `{"error": "Invalid username or password."}`.
  2. *Constant-Time Dummy Computation:* If a user does not exist in the database, the server runs a dummy comparison against a static constant hash (`DUMMY_HASH`). This equalizes response time across all failure conditions, eliminating timing side-channels.

### 2.3 Threat Vector 3: Database Compromise & Credential Exposure
* **Attack Scenario:** An attacker obtains access to the database file or disk backups and recovers plaintext credentials or fast-crackable MD5/SHA-1 hashes.
* **Defense Architecture:** Utilizes `bcryptjs` with an adaptive work factor of 10 ($2^{10} = 1024$ key expansion rounds). Each password receives a unique, cryptographically random 128-bit salt. Plaintext passwords are never saved to disk or retained in application memory. Furthermore, all JSON response serializers across registration, login, and profile explicitly sanitize user objects to ensure password hashes are never leaked over the wire.

### 2.4 Threat Vector 4: Session Hijacking & Cross-Site Scripting (XSS)
* **Attack Scenario:** A malicious script injected via an XSS vulnerability attempts to read session credentials through `document.cookie`.
* **Defense Architecture:** The server-side session cookie (`connect.sid`) is configured with `HttpOnly: true`. Modern browsers completely restrict JavaScript access to this cookie, eliminating token theft via DOM inspection.

### 2.5 Threat Vector 5: Cross-Site Request Forgery (CSRF)
* **Attack Scenario:** A malicious third-party site tricks a victim's browser into dispatching unauthorized requests to the authenticated service.
* **Defense Architecture:** The session cookie enforces `SameSite: 'lax'`. Browsers will not attach the cookie to cross-site state-altering requests (e.g., POST/PUT), protecting authenticated endpoints against CSRF.

### 2.6 Threat Vector 6: Session Fixation & Post-Logout Replay
* **Attack Scenario:** An attacker presets a session identifier for a victim prior to login, then inherits the authenticated privileges post-login. Alternatively, an attacker replays a session token after the user has logged out.
* **Defense Architecture:**
  1. *Session Regeneration:* Upon credential validation, the server executes `req.session.regenerate()`, discarding the pre-authentication session ID and issuing a fresh identifier.
  2. *Explicit Server Invalidation:* Calling `POST /api/logout` invokes `req.session.destroy()` on the server and `res.clearCookie('connect.sid')`, instantly invalidating the session store record.

### 2.7 Threat Vector 7: Bcrypt Algorithmic CPU-Exhaustion DoS
* **Attack Scenario:** Attackers transmit multi-megabyte password strings. Because bcrypt processes input through repeated expansion loops, excessively large inputs consume CPU threads and starve the server.
* **Defense Architecture:** Enforced in `src/validation.js`: passwords are constrained to a maximum of 128 characters prior to hashing. Malformed or oversized inputs are rejected instantly at the parsing layer with HTTP 400 Bad Request.

---

## 3. Empirical Verification Matrix

Every defensive control detailed above has been verified via the **21 automated security tests** in [`tests/auth.test.js`](../tests/auth.test.js):

| Threat Domain | Specific Defensive Control | Implementation File | Automated Verification Test Case | Result |
|:---|:---|:---|:---|:---:|
| **Password Storage** | Salted adaptive bcrypt hashing (Cost 10) | `src/app.js` (`bcrypt.hash`) | `stores passwords strictly as strong bcrypt hashes (never plaintext)` | ✅ **PASS** |
| **Data Protection** | Sanitized JSON responses (zero hash leakage) | `src/app.js` (`/api/register`, `/api/profile`) | `successfully registers a new user with valid credentials` | ✅ **PASS** |
| **Data Integrity** | Username collision rejection (HTTP 409) | `src/app.js` (`db.findUserByUsername`) | `rejects registration when username already exists` | ✅ **PASS** |
| **Input Validation** | Missing parameter rejection (HTTP 400) | `src/validation.js` | `rejects registration when username or password are missing` | ✅ **PASS** |
| **Input Validation** | Non-string type injection rejection | `src/validation.js` | `rejects registration when fields are of non-string types` | ✅ **PASS** |
| **Input Validation** | Username length boundary enforcement (3–30 chars) | `src/validation.js` | `rejects username shorter than 3 characters or longer than 30 characters` | ✅ **PASS** |
| **Input Validation** | Character whitelisting (`/^[a-zA-Z0-9_]+$/`) | `src/validation.js` | `rejects username containing non-whitelisted characters (XSS/injection defense)` | ✅ **PASS** |
| **Input Validation** | Password minimum entropy enforcement (min 8 chars) | `src/validation.js` | `rejects password shorter than 8 characters` | ✅ **PASS** |
| **DoS Defense** | Bcrypt CPU-exhaustion capping (max 128 chars) | `src/validation.js` | `rejects password exceeding 128 characters (Bcrypt CPU DoS prevention)` | ✅ **PASS** |
| **Input Validation** | Empty/malformed login request rejection | `src/validation.js` | `rejects malformed or empty login requests` | ✅ **PASS** |
| **Authentication** | Valid credential login & session cookie issuance | `src/app.js` (`/api/login`) | `successfully logs in with valid credentials and sets session cookie` | ✅ **PASS** |
| **Anti-Enumeration** | Uniform HTTP 401 error on bad password | `src/app.js` (`/api/login`) | `returns generic error "Invalid username or password." for incorrect password` | ✅ **PASS** |
| **Anti-Enumeration** | Uniform HTTP 401 error on non-existent user | `src/app.js` (`/api/login`) | `returns identical generic error for non-existent username (prevents user enumeration)` | ✅ **PASS** |
| **Cookie Security** | `HttpOnly`, `SameSite=Lax`, and Max-Age attributes | `src/app.js` (`express-session`) | `sets HttpOnly, SameSite=Lax, and session expiration on session cookie` | ✅ **PASS** |
| **Cookie Security** | Dynamic `Secure: true` flag in production HTTPS | `src/app.js` (`cookie.secure`) | `applies Secure flag over HTTPS / trusted reverse proxy in production` | ✅ **PASS** |
| **Access Control** | Protected route access with valid session cookie | `src/app.js` (`requireAuth`) | `grants access to protected route with valid session cookie` | ✅ **PASS** |
| **Access Control** | Unauthenticated access rejection (HTTP 401) | `src/app.js` (`requireAuth`) | `denies access to protected route when unauthenticated (no cookie)` | ✅ **PASS** |
| **Access Control** | Forged / invalid session cookie rejection | `src/app.js` (`requireAuth`) | `denies access with forged or invalid session cookie` | ✅ **PASS** |
| **Session Invalidation**| Server session destruction & cookie clearance on logout | `src/app.js` (`req.session.destroy`) | `invalidates server-side session and clears cookie upon logout` | ✅ **PASS** |
| **Session Invalidation**| Idle session expiration rejection (TTL) | `src/app.js` (`cookie.maxAge`) | `rejects access after session expiration TTL` | ✅ **PASS** |
| **Rate Limiting** | HTTP 429 throttling on brute-force attempts | `src/middleware/rateLimiter.js` | `triggers HTTP 429 after exceeding failed login rate limit` | ✅ **PASS** |

---

## 4. Conclusion & Audit Summary

The combination of strict server-side schema validation, salted adaptive cryptographic password hashing, timing-resistant generic authentication errors, signed cookie flags, and IP rate limiting establishes a secure baseline suitable for production authentication microservices. All 21 automated verification tests pass with 0 failures, ensuring complete alignment with the internship laboratory requirements.
