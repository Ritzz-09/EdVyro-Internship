# 📐 Task 02: Secure Authentication Lab — Architecture & System Design

> **Intern:** Ritzz (`@Ritzz-09`)  
> **Internship Track:** EdVyro Cybersecurity Internship  
> **Target Lab:** SecureAuth (Defensive Local Authentication Service)  
> **Format:** Hybrid Architectural Narrative & Mermaid Diagram Decomposition

---

## 1. Architectural Philosophy & Design Principles

When designing **SecureAuth**, I operated under the core defensive engineering principle: **Assume Breach & Enforce Defense-in-Depth**. Rather than relying on a single security perimeter, defenses are distributed across every layer of the request lifecycle—from network transport and payload parsing to cryptographic derivation and session lifecycle termination.

### 1.1 Why Node.js & Express for this Microservice?
- **Asynchronous Non-Blocking I/O:** Ideal for lightweight authentication routing where I/O operations (reading databases, validating session stores) must not block concurrent client connections.
- **Pure JavaScript Cryptography (`bcryptjs`):** Avoids native C++ compilation bindings that frequently break across varied evaluation environments, while providing standard salted adaptive hashing.
- **Middleware Modularity:** Express enables a strictly ordered defensive middleware chain where input parsing, rate limiting, and defensive response headers execute *before* any business logic or cryptographic functions are invoked.

### 1.2 Storage Architecture & Atomic File Synchronization
- **Selection:** A custom abstraction layer [`src/db.js`](./src/db.js) managing local JSON persistence (`data/users.json`).
- **Resilience Trade-Off:** Traditional database engines (PostgreSQL, MySQL) introduce external service dependencies that can fail during local evaluation. SQLite requires native binary drivers. 
- **Atomic Write Mechanism:** To prevent file corruption during sudden server crashes or concurrent registration attempts, `db.createUser()` writes new user records to a temporary file (`users.json.<timestamp>.tmp`) and performs an atomic filesystem swap via `fs.renameSync()`.

---

## 2. High-Level System Architecture & Trust Boundaries

The system enforces three distinct trust boundaries, treating all data originating outside the Express runtime as untrusted:

```mermaid
graph TD
    Client["Client Browser / Evaluator<br/>(Vanilla JS / Offline UI)"]
    
    subgraph TrustBoundary1["Trust Boundary 1: Network & Transport"]
        HTTP["HTTP Loopback (127.0.0.1:3000)<br/>Localhost Scope Enforcement"]
    end
    
    subgraph TrustBoundary2["Trust Boundary 2: Express Defensive Pipeline"]
        Headers["Security Headers Middleware<br/>(nosniff, DENY)"]
        Parser["Body Parser & Payload Boundary<br/>(JSON limit: 10KB)"]
        RateLimiter["Authentication Rate Limiter<br/>(5 attempts / 15 mins, HTTP 429)"]
        Validation["Input Validation & Whitelisting<br/>(Regex /^[a-zA-Z0-9_]+$/, Len: 8-128)"]
        Crypto["Cryptographic Engine<br/>(Bcrypt Work Factor 10, Salted)"]
        SessionMgr["Session Management<br/>(HttpOnly, SameSite=Lax, TTL)"]
    end
    
    subgraph TrustBoundary3["Trust Boundary 3: Persistent Storage"]
        DB["Local Database (db.js)<br/>(data/users.json - Atomic Write Swaps)"]
    end
    
    Client -->|Untrusted JSON / Cookie| HTTP
    HTTP --> Headers
    Headers --> Parser
    Parser --> RateLimiter
    RateLimiter --> Validation
    Validation --> Crypto
    Crypto --> SessionMgr
    SessionMgr --> DB
```

---

## 3. Sequence Flows & Request Lifecycles

### 3.1 Registration Sequence Flow (`POST /api/register`)

```mermaid
sequenceDiagram
    autonumber
    actor User as Client / Evaluator
    participant Route as Express Router
    participant Val as validation.js
    participant DB as db.js
    participant Bcrypt as bcryptjs (Cost 10)

    User->>Route: POST /api/register (username, password)
    Route->>Val: validateRegistrationInput(payload)
    alt Invalid Input (bad types, non-whitelisted chars, length < 8 or > 128)
        Val-->>Route: Validation Error
        Route-->>User: HTTP 400 Bad Request
    else Valid Input
        Val-->>Route: Valid
        Route->>DB: findUserByUsername(username)
        alt Username Exists
            DB-->>Route: Existing User Record
            Route-->>User: HTTP 409 Conflict ("Username is already taken.")
        else Unique Username
            DB-->>Route: null
            Route->>Bcrypt: hash(password, 10)
            Bcrypt-->>Route: Salted Hash ($2b$10$...)
            Route->>DB: createUser({ username, passwordHash })
            DB-->>Route: New User Record
            Route-->>User: HTTP 201 Created (Sanitized user object, ZERO hashes)
        end
    end
```

---

### 3.2 Login & Session Establishment (`POST /api/login`)

```mermaid
sequenceDiagram
    autonumber
    actor User as Client / Evaluator
    participant Limiter as rateLimiter.js
    participant Route as Express Router
    participant DB as db.js
    participant Bcrypt as bcryptjs
    participant Session as express-session

    User->>Limiter: POST /api/login (username, password)
    alt IP Exceeds 5 attempts / 15 mins
        Limiter-->>User: HTTP 429 Too Many Requests ("Rate limit exceeded")
    else Within Allowed Threshold
        Limiter->>Route: Forward Request
        Route->>DB: findUserByUsername(username)
        alt User Not Found
            Route->>Bcrypt: compare(password, DUMMY_HASH)
            Note over Route,Bcrypt: Constant-time comparison mitigates timing side-channels
            Route-->>User: HTTP 401 Unauthorized ("Invalid username or password.")
        else User Exists
            Route->>Bcrypt: compare(password, user.passwordHash)
            alt Password Mismatch
                Route-->>User: HTTP 401 Unauthorized ("Invalid username or password.")
            else Password Matches
                Route->>Session: req.session.regenerate()
                Note over Route,Session: Session Fixation Defense
                Session-->>Route: Fresh Session Established (userId, username)
                Route-->>User: HTTP 200 OK + Set-Cookie (HttpOnly, SameSite=Lax)
            end
        end
    end
```

---

### 3.3 Protected Route Access (`GET /api/profile`)

```mermaid
sequenceDiagram
    autonumber
    actor User as Client / Evaluator
    participant AuthMW as requireAuth Middleware
    participant Route as Express Router
    participant DB as db.js

    User->>AuthMW: GET /api/profile (Cookie: connect.sid)
    alt Missing, Expired, or Forged Cookie
        AuthMW-->>User: HTTP 401 Unauthorized ("Authentication required.")
    else Valid Active Session
        AuthMW->>Route: Forward Authenticated Request
        Route->>DB: findUserById(session.userId)
        DB-->>Route: User Profile
        Route-->>User: HTTP 200 OK (id, username, createdAt - ZERO hashes)
    end
```

---

## 4. Session Security Architecture

| Security Property | Implementation Configuration | Defensive Objective |
|:---|:---|:---|
| **Cookie Name** | `connect.sid` | Standard identifier without leaking framework internals. |
| **HttpOnly** | `httpOnly: true` | Prohibits client-side JavaScript execution (`document.cookie`) from reading session tokens (XSS defense). |
| **SameSite Policy** | `sameSite: 'lax'` | Restricts cross-site dispatching, defending against Cross-Site Request Forgery (CSRF). |
| **Transport Security** | `secure: process.env.NODE_ENV === 'production'` | Dynamically enables HTTPS-only transmission in production while supporting functional localhost testing. |
| **Session Lifetime** | `maxAge: 15 * 60 * 1000` (15 minutes) | Automatic idle invalidation preventing zombie sessions on unattended workstations. |
| **Anti-Fixation** | `req.session.regenerate()` | Discards pre-login session IDs and generates a new token upon successful authentication. |
| **Explicit Revocation** | `req.session.destroy()` + `res.clearCookie()` | Completely purges server-side session state upon user logout. |
