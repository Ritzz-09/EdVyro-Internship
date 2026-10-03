# 🛡️ Task 02: Secure Authentication Lab

> **Intern:** Ritzz (`@Ritzz-09`)  
> **Repository:** [https://github.com/Ritzz-09/EdVyro-Internship](https://github.com/Ritzz-09/EdVyro-Internship)  
> **Track:** Cybersecurity & Defensive Security Engineering  
> **Service:** Local Defensive Authentication Microservice  
> **Target Scope:** Strictly Localhost Isolation (`http://127.0.0.1:3000`)

---

## 📌 1. Executive Summary & Engineering Scope

As part of my cybersecurity engineering internship at **EdVyro**, I was tasked with architecting and building **SecureAuth**, a robust local authentication microservice developed with **Node.js** and **Express**. 

The goal of this project is to implement defense-in-depth security controls that neutralize the most common attack vectors targeting modern authentication pipelines:
- Automated credential stuffing and brute-force dictionary guessing.
- Targeted user enumeration via error message and timing discrepancies.
- Session hijacking, cookie theft via XSS, and Cross-Site Request Forgery (CSRF).
- Session fixation and post-logout session replay attacks.
- Algorithmic Denial of Service (DoS) targeting CPU-intensive password hashing functions.

The entire service runs strictly on `127.0.0.1:3000` with 100% synthetic local data, zero external cloud dependencies, and zero third-party CDN scripts.

---

## 🧠 2. Intern's Engineering Journey & Challenges Overcome

During the implementation of SecureAuth, I focused on avoiding superficial security controls and instead engineered defenses against realistic, nuanced attack vectors:

### Challenge 1: The Bcrypt CPU-Exhaustion DoS Vector
* **The Vulnerability:** Bcrypt's key expansion algorithm is intentionally CPU-intensive. An attacker can exploit this by submitting massive password payloads (e.g. 1MB strings) across concurrent threads, driving server CPU utilization to 100% and starving legitimate traffic.
* **My Defense:** In [`src/validation.js`](./src/validation.js), I enforced a strict server-side maximum length cap of 128 characters on all password inputs prior to cryptographic hashing. Malformed or oversized inputs are rejected instantly at the parsing layer with HTTP 400.

### Challenge 2: Side-Channel Timing Attacks in User Enumeration
* **The Vulnerability:** If a server hashes a password only when a username exists in the database, requests for valid accounts take ~70ms (due to bcrypt computation), while requests for non-existent accounts return in <2ms. Attackers use this timing delta to enumerate valid registered users.
* **My Defense:** In [`src/app.js`](./src/app.js), when a requested username is not found in the database, the server executes a dummy comparison against a static constant hash (`DUMMY_HASH`). This ensures uniform processing time regardless of account existence.

### Challenge 3: Balancing Local HTTP Testing with Production HTTPS Cookie Security
* **The Vulnerability:** Marking session cookies with `Secure: true` causes browsers to drop cookies when testing locally over plain HTTP (`http://127.0.0.1:3000`), breaking local development. Conversely, leaving `Secure: false` exposes production environments to cookie sniffing.
* **My Defense:** I implemented dynamic cookie flags: `secure: process.env.NODE_ENV === 'production'` paired with `app.set('trust proxy', 1)`. This allows seamless local development over HTTP while strictly requiring HTTPS in production deployments behind reverse proxies.

### Challenge 4: Session Fixation Defense via Instant Session Regeneration
* **The Vulnerability:** Attackers can trick a victim into using a known session identifier, then hijack the session after the victim successfully authenticates.
* **My Defense:** Upon successful password verification, the server invokes `req.session.regenerate()`, discarding the pre-authentication session ID and issuing a cryptographically fresh token before writing the user's state.

---

## 🛠️ 3. Technical Specifications & Architecture

| Component | Technology | Version | Purpose & Defensive Justification |
|:---|:---|:---|:---|
| **Runtime** | Node.js | v24.x | Fast asynchronous I/O and native test runner (`node:test`). |
| **Framework** | Express | v5.x | Minimalist HTTP request pipeline and middleware engine. |
| **Password Hashing** | `bcryptjs` | v3.x | Salted adaptive key-derivation function with work factor 10 ($2^{10} = 1024$ rounds). |
| **Session Engine** | `express-session` | v1.x | Server-side state store issuing cryptographically signed cookies. |
| **Rate Limiter** | `express-rate-limit` | v8.x | Sliding window IP rate-limiter issuing HTTP 429 against brute-force attacks. |
| **Testing** | `node:test` + `supertest` | Built-in / v7.x | 21 automated integration and security unit tests. |
| **Database** | Local JSON File Store | Custom (`src/db.js`) | Atomic synchronous file replacement (`fs.renameSync`) with zero external daemon overhead. |
| **Frontend UI** | HTML5 / CSS3 / Vanilla JS | N/A | 100% offline local dashboard with zero CDN dependencies. |

---

## 🛡️ 4. Defensive Security Controls Breakdown

### 1. Cryptographic Password Hashing
- **Salt Generation:** Bcrypt generates a unique 128-bit pseudo-random salt for every user.
- **Zero Plaintext Storage:** Neither in-memory structures nor the disk storage (`data/users.json`) ever stores or logs plaintext passwords.
- **Zero Credential Exposure:** Registration, login, and profile APIs explicitly strip `password` and `passwordHash` from all JSON responses.

### 2. Strict Server-Side Input Validation
- **Type Checking:** All inputs must be strictly of type `string` (rejects arrays, objects, numbers).
- **Username Whitelist:** Enforces 3–30 characters matching `/^[a-zA-Z0-9_]+$/` to eliminate script tags and control characters.
- **Password Length Boundaries:** Minimum 8 characters for baseline entropy; maximum 128 characters to block algorithmic DoS.

### 3. Hardened Session Cookies
- **`HttpOnly: true`:** Blocks client-side JavaScript access via `document.cookie`, defeating Cross-Site Scripting (XSS) session theft.
- **`SameSite: 'lax'`:** Restricts cookie transmission on cross-site requests, mitigating Cross-Site Request Forgery (CSRF).
- **Idle Expiration TTL:** Sessions expire automatically after 15 minutes of inactivity (`maxAge: 15 * 60 * 1000`).

### 4. Authentication Rate Limiting
- **Throttling Threshold:** 5 failed attempts per 15-minute sliding window per client IP on `/api/login`.
- **Response:** Issues HTTP 429 (Too Many Requests) with RFC-compliant `RateLimit-*` telemetry headers.

### 5. Generic Authentication Error Messages
- **Uniform Response:** Both incorrect passwords and non-existent usernames return identical HTTP 401 status and JSON body:
  ```json
  { "error": "Invalid username or password." }
  ```

### 6. Explicit Session Invalidation (Logout)
- **Revocation:** `POST /api/logout` invokes `req.session.destroy()` on the server and `res.clearCookie('connect.sid')` on the client, neutralizing replay attacks.

---

## 🎥 5. Live Demonstration Video & Verification Evidence

- 📹 **Demo Video:** [`documentation/demo-task2.mp4`](./documentation/demo-task2.mp4) *(Full HD 1080p, 01:58 duration, optimized to 2.4 MB)*
- 📑 **Comprehensive Evidence Log:** [`EVIDENCE.md`](./EVIDENCE.md)

### Video Timestamp Breakdown:
- **`0:00 – 0:15`**: Interface & Defensive Telemetry panel overview.
- **`0:15 – 0:35`**: User registration of `sec_cadet` with salted password hashing.
- **`0:35 – 0:55`**: Successful login and active session cookie establishment.
- **`0:55 – 1:15`**: Authorized dashboard access showing User ID with credentials hidden.
- **`1:15 – 1:35`**: Generic authentication error demonstration (HTTP 401).
- **`1:35 – 1:50`**: Repeated failed login attempts triggering HTTP 429 Rate Limiting.
- **`1:50 – 1:58`**: Session logout, destruction, and locking of the protected route.

---

## 🧪 6. Automated Security Test Suite (21 Tests)

Run the automated test suite with:
```bash
npm test
```

```text
▶ Task 02: Secure Authentication Lab Test Suite
  ▶ User Registration & Safe Password Storage
    ✔ successfully registers a new user with valid credentials
    ✔ stores passwords strictly as strong bcrypt hashes (never plaintext)
    ✔ rejects registration when username already exists
  ✔ User Registration & Safe Password Storage
  ▶ Server-Side Input Validation
    ✔ rejects registration when username or password are missing
    ✔ rejects registration when fields are of non-string types
    ✔ rejects username shorter than 3 characters or longer than 30 characters
    ✔ rejects username containing non-whitelisted characters (XSS/injection defense)
    ✔ rejects password shorter than 8 characters
    ✔ rejects password exceeding 128 characters (Bcrypt CPU DoS prevention)
    ✔ rejects malformed or empty login requests
  ✔ Server-Side Input Validation
  ▶ Login & Generic Authentication Errors
    ✔ successfully logs in with valid credentials and sets session cookie
    ✔ returns generic error "Invalid username or password." for incorrect password
    ✔ returns identical generic error for non-existent username (prevents user enumeration)
  ✔ Login & Generic Authentication Errors
  ▶ Session Security & Cookie Flags
    ✔ sets HttpOnly, SameSite=Lax, and session expiration on session cookie
    ✔ applies Secure flag over HTTPS / trusted reverse proxy in production
  ✔ Session Security & Cookie Flags
  ▶ Protected Route Access & Access Control
    ✔ grants access to protected route with valid session cookie
    ✔ denies access to protected route when unauthenticated (no cookie)
    ✔ denies access with forged or invalid session cookie
  ✔ Protected Route Access & Access Control
  ▶ Logout & Session Expiration
    ✔ invalidates server-side session and clears cookie upon logout
    ✔ rejects access after session expiration TTL
  ✔ Logout & Session Expiration
  ▶ Authentication Rate Limiting
    ✔ triggers HTTP 429 after exceeding failed login rate limit
  ✔ Authentication Rate Limiting
✔ Task 02: Secure Authentication Lab Test Suite (21 tests, 0 failures)
```

---

## 📑 7. Task 02 Documentation Deliverables

Inside [`./Task-02-SecureAuth/`](./):

- 📘 [`README.md`](./README.md) — Technical project overview, engineering journey, and setup instructions.
- 📐 [`ARCHITECTURE.md`](./ARCHITECTURE.md) — Architectural decomposition, 3 trust boundaries, sequence diagrams, and request lifecycles.
- 🎯 [`THREAT-MODEL.md`](./THREAT-MODEL.md) — STRIDE threat model evaluating 11 realistic threat scenarios with risk scores.
- 📊 [`RISK-REGISTER.md`](./RISK-REGISTER.md) — Qualitative risk matrix evaluating pre- and post-mitigation risk ratings.
- 🛡️ [`HARDENING-CHECKLIST.md`](./HARDENING-CHECKLIST.md) — Prioritized P0 to P3 defensive hardening checklist and production guidelines.
- 📝 [`docs/security-note.md`](./docs/security-note.md) — Detailed defensive security note and verification mapping.
- 📸 [`EVIDENCE.md`](./EVIDENCE.md) — Video walkthrough timestamp table and clip snapshots from [`documentation/`](./documentation/).

---

## 🚀 8. How to Run Locally

```bash
# 1. Enter the task directory
cd Task-02-SecureAuth

# 2. Install dependencies
npm install

# 3. Execute all 21 automated security tests
npm test

# 4. Launch the local application
npm start
```

Open your browser to: **`http://127.0.0.1:3000`**
