# 🎯 Task 02: STRIDE Threat Model & Security Assessment

> **Intern:** Ritzz (`@Ritzz-09`)  
> **Internship Track:** EdVyro Cybersecurity Internship  
> **Application:** SecureAuth (Node.js/Express Defensive Authentication Service)  
> **Framework:** Microsoft STRIDE Threat Modeling Framework & OWASP Top 10  
> **Format:** Hybrid Threat Analysis Narrative & STRIDE Risk Assessment Matrix

---

## 1. Intern's Threat Modeling Philosophy: Attacker vs. Defender Mindset

During my cybersecurity internship at EdVyro, I learned that building an authentication service requires adopting an **adversarial mindset**:
- Where a developer sees a registration form, an attacker sees an input vector for cross-site scripting (XSS) or database poisoning.
- Where a developer sees a password hashing function, an attacker sees a CPU-exhaustion target for Denial of Service (DoS).
- Where a developer sees distinct error messages (*"Username does not exist"*), an attacker sees an oracle for user enumeration.

To systematically evaluate SecureAuth, I applied the **Microsoft STRIDE** framework across every system boundary.

---

## 2. STRIDE Threat Assessment Matrix

| Threat ID | STRIDE Category | Threat Description & Attack Scenario | Inherent Risk | Defensive Countermeasure Implemented | Residual Risk | Status |
|:---:|:---|:---|:---:|:---|:---:|:---:|
| **TM-01** | **Spoofing** | **Automated Brute-Force & Credential Stuffing:** Attacker uses dictionary lists to guess passwords for known accounts. | **High** | IP-based sliding-window rate limiting (`express-rate-limit`) issuing HTTP 429 after 5 failed attempts per 15 minutes. | **Low** | ✅ Mitigated |
| **TM-02** | **Spoofing** | **Session Hijacking via Stolen Cookies:** Attacker intercepts or extracts active session cookie from client. | **Critical** | `HttpOnly=true` flag prevents XSS theft; `SameSite=Lax` restricts cross-site transmission; short 15-minute idle TTL. | **Low** | ✅ Mitigated |
| **TM-03** | **Tampering** | **Session ID Forgery / Token Tampering:** Attacker crafts or modifies session cookie payload to impersonate another user. | **Critical** | Cryptographic session signing using a server-side HMAC secret (`express-session`); forged cookies fail signature verification and return HTTP 401. | **Negligible** | ✅ Mitigated |
| **TM-04** | **Tampering** | **Payload Injection & Parameter Tampering:** Attacker submits scripts or control characters in username to achieve stored XSS or corrupt DB. | **Medium** | Server-side regex whitelisting (`/^[a-zA-Z0-9_]+$/`) and strict string type enforcement rejecting non-conforming input with HTTP 400. | **Negligible** | ✅ Mitigated |
| **TM-05** | **Repudiation** | **Unauthenticated State Manipulation:** Attacker claims session was reused after logout or actions occurred without authorization. | **Medium** | Explicit server-side session destruction (`req.session.destroy()`) and client cookie clearance (`res.clearCookie`) ensuring immediate state invalidation. | **Low** | ✅ Mitigated |
| **TM-06** | **Information Disclosure** | **User Enumeration via Discriminative Errors:** Attacker determines whether an account exists based on error message differences ("User not found" vs "Wrong password"). | **Medium** | Generic authentication error message (`"Invalid username or password."`) returned uniformly across all failure conditions. | **Negligible** | ✅ Mitigated |
| **TM-07** | **Information Disclosure** | **Side-Channel Timing Attacks:** Attacker times response latency to distinguish existing usernames from non-existent usernames. | **Medium** | Constant-time dummy hash verification (`bcrypt.compare(password, DUMMY_HASH)`) when username is missing from DB, maintaining uniform latency. | **Low** | ✅ Mitigated |
| **TM-08** | **Information Disclosure** | **Credential Leakage in API Responses:** Registration, login, or profile routes inadvertently expose `passwordHash` or plaintext secrets. | **High** | Sanitized response schema builder explicitly strips credentials; verified by automated unit tests inspecting JSON response keys. | **Negligible** | ✅ Mitigated |
| **TM-09** | **Denial of Service** | **Bcrypt Algorithmic CPU-Exhaustion DoS:** Attacker transmits megabyte-scale password payloads to consume server CPU threads during key expansion. | **High** | Strict server-side payload boundary checks enforcing a maximum password length of 128 characters prior to bcrypt hashing. | **Negligible** | ✅ Mitigated |
| **TM-10** | **Elevation of Privilege** | **Session Fixation:** Attacker forces a pre-set session ID onto victim before login to hijack authenticated privileges post-login. | **High** | Mandatory session regeneration (`req.session.regenerate()`) upon valid credential authentication, creating a fresh identifier. | **Negligible** | ✅ Mitigated |
| **TM-11** | **Elevation of Privilege** | **Unauthenticated Access to Protected Routes:** Attacker bypasses authentication to access `/api/profile` directly. | **High** | Server-side `requireAuth` middleware enforcing session presence before handler execution; blocks unauthenticated access with HTTP 401. | **Negligible** | ✅ Mitigated |

---

## 3. Qualitative Risk Scoring Grid

```text
       LIKELIHOOD
       High    |   [TM-01]  [TM-06]  |            |
       Medium  |   [TM-04]  [TM-07]  |   [TM-09]  |
       Low     |   [TM-05]  [TM-08]  |   [TM-10]  |  [TM-02]  [TM-03]  [TM-11]
               +---------------------+------------+---------------------------
                       Low                 Medium              High / Critical
                                           IMPACT
```

All 11 evaluated threat scenarios have verified mitigations built into the codebase and are validated by the 21 automated security tests in `tests/auth.test.js`.
