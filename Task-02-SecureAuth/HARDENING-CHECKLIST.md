# 🛡️ Task 02: Defensive Hardening Checklist

> **Intern:** Ritzz (`@Ritzz-09`)  
> **Internship Track:** EdVyro Cybersecurity Internship  
> **Application:** SecureAuth (Node.js/Express Defensive Authentication Service)  
> **Standards Alignment:** OWASP ASVS (Application Security Verification Standard) v4.0  
> **Format:** Hybrid Defensive Engineering Roadmap & Prioritized Implementation Checklist

---

## 1. Intern's Production Transition Guide: Moving Beyond Localhost

While SecureAuth achieves complete defensive security within its authorized local testing boundary (`127.0.0.1:3000`), a production cloud or Kubernetes deployment introduces distributed failure modes:
1. **From Single-Node Memory to Distributed Stores:** The local in-memory session engine must be migrated to an encrypted Redis cluster or relational PostgreSQL store to support horizontal pod autoscaling.
2. **Edge TLS & Header Sanitization:** In production behind AWS ALB, Cloudflare, or Nginx, reverse proxies must terminate TLS and sanitize client IP headers (`X-Forwarded-For`) to prevent rate-limit spoofing.
3. **Secret Key Vaults:** Hardcoded development fallback secrets must be replaced with dynamic runtime injection via HashiCorp Vault or AWS Secrets Manager.

---

## 2. Defensive Hardening Checklist

| Priority | Hardening Category | Defensive Action / Rule | Implementation File | Verification Test | Status |
|:---:|:---|:---|:---|:---|:---:|
| **P0** | **Credential Security** | Salted adaptive bcrypt hashing (Cost 10); zero plaintext storage. | `src/app.js` | `stores passwords strictly as strong bcrypt hashes` | ✅ Completed |
| **P0** | **Data Exposure** | Omit passwords and password hashes from all JSON API responses. | `src/app.js` | `successfully registers a new user with valid credentials` | ✅ Completed |
| **P0** | **Access Control** | Enforce authentication middleware (`requireAuth`) on protected routes. | `src/app.js` | `denies access to protected route when unauthenticated` | ✅ Completed |
| **P1** | **Input Validation** | Server-side regex whitelisting (`/^[a-zA-Z0-9_]+$/`) and type checks. | `src/validation.js` | `rejects username containing non-whitelisted characters` | ✅ Completed |
| **P1** | **DoS Prevention** | Bound password lengths (max 128 chars) to prevent Bcrypt CPU DoS. | `src/validation.js` | `rejects password exceeding 128 characters` | ✅ Completed |
| **P1** | **Session Security** | Set `HttpOnly: true` and `SameSite: 'lax'` on session cookies. | `src/app.js` | `sets HttpOnly, SameSite=Lax, and session expiration` | ✅ Completed |
| **P1** | **Anti-Fixation** | Regenerate session token (`req.session.regenerate`) upon login. | `src/app.js` | `successfully logs in with valid credentials` | ✅ Completed |
| **P1** | **Session Termination** | Invalidate server session (`destroy()`) and wipe client cookie on logout. | `src/app.js` | `invalidates server-side session and clears cookie upon logout` | ✅ Completed |
| **P2** | **Brute-Force Defense** | Apply IP-based sliding rate limiter (5 req / 15 min) returning HTTP 429. | `src/middleware/rateLimiter.js` | `triggers HTTP 429 after exceeding failed login rate limit` | ✅ Completed |
| **P2** | **Anti-Enumeration** | Uniform HTTP 401 error message and constant-time dummy hash verification. | `src/app.js` | `returns identical generic error for non-existent username` | ✅ Completed |
| **P2** | **Session Expiry** | 15-minute idle expiration TTL (`maxAge: 15 * 60 * 1000`). | `src/app.js` | `rejects access after session expiration TTL` | ✅ Completed |
| **P3** | **Transport Security** | Dynamic `Secure: true` flag in production environments with TLS. | `src/app.js` | `applies Secure flag over HTTPS / trusted reverse proxy in production` | ✅ Completed |

---

## 3. Production Deployment Hardening Recommendations

When deploying to production internet environments:
1. **Distributed Session Storage:** Migrate `express-session` to `connect-redis` backed by an encrypted Redis cluster.
2. **Reverse Proxy TLS Enforcement:** Enforce HTTPS at the edge with HSTS headers (`Strict-Transport-Security: max-age=31536000; includeSubDomains`).
3. **Database Migration:** Connect to an ACID-compliant database (PostgreSQL) using TLS encryption and least-privilege connection credentials.
4. **Secret Management:** Inject `SESSION_SECRET` via cloud secret managers rather than default configuration files.
