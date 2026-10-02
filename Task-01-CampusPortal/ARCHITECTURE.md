# CampusPortal - System Architecture & Trust Boundaries

> **Authorized Local Defensive Lab**  
> **Environment:** Localhost Isolated Environment (`127.0.0.1:5000`)  
> **Target:** Defensive Cybersecurity Threat-Modeling & Architecture Review

---

## 1. System Overview

**CampusPortal** is a monolithic server-side rendered (SSR) web application engineered in Python 3 using the Flask micro-framework and an embedded SQLite 3 database. It simulates an institutional student information system (SIS) enabling role-based management of academic records, grades, attendance, and administrative user provisioning.

The entire architecture is intentionally compact and self-contained to facilitate rigorous threat modeling and security inspection within a 45–60 minute window.

```mermaid
flowchart TD
    classDef boundary fill:#fef3c7,stroke:#d97706,stroke-width:2px,stroke-dasharray: 5 5;
    classDef untrusted fill:#fee2e2,stroke:#ef4444,stroke-width:1.5px;
    classDef trusted fill:#dbeafe,stroke:#3b82f6,stroke-width:1.5px;
    classDef storage fill:#dcfce7,stroke:#22c55e,stroke-width:1.5px;

    subgraph ClientZone ["Untrusted Network Zone"]
        Browser["User Browser (HTML5 / CSS3 / Vanilla JS)<br/><i>Strict Localhost (127.0.0.1:5000 Only) — No External CDNs</i>"]:::untrusted
    end

    subgraph TB1 ["== Trust Boundary 1: Untrusted Network / Client-Server Boundary =="]
        subgraph ServerZone ["Flask Application Runtime (Trusted Boundary)"]
            direction TB
            MW["Security Middleware & Filters<br/>• CSP, X-Frame-Options, nosniff, Referrer-Policy<br/>• Sliding-Window Login Rate Limiter (5 per 60s)<br/>• Session Cookie Manager (HttpOnly, SameSite=Lax)"]:::trusted
            Controller["Controller & Authorization Layer (RBAC)<br/>• @roles_required('student' | 'faculty' | 'admin')<br/>• CSRF Synchronizer Token Validator<br/>• Course-Ownership / IDOR Validator<br/>• Server-Side Input Bounds & Type Validation"]:::trusted
            Audit["Defensive Audit Subsystem<br/>• Event Logger (audit_logs table)<br/>• Strict Exclusion of Passwords / Raw Secrets"]:::trusted

            MW --> Controller
            Controller --> Audit
        end
    end

    subgraph TB2 ["== Trust Boundary 2: Controller <---> Data Persistence Boundary =="]
        subgraph StorageZone ["Data Storage Layer"]
            DB[("SQLite 3 Database Engine<br/>(campus_portal.db)<br/>9 Relational Tables • Foreign Keys Enforced")]:::storage
        end
    end

    Browser -->|"HTTP/1.1 (Cookie: session, X-CSRF-Token, Form Data)"| MW
    Controller -->|"Parameterized SQL Queries (sqlite3 driver with ? bindings)"| DB
```

---

## 2. Core Components & Subsystems

### 2.1 User Principals & Roles

| Principal | Role Identifier | Privilege Level | Permitted Operations |
| :--- | :--- | :--- | :--- |
| **Student** | `student` | Level 1 (Least Privilege) | View personal dashboard, courses, grades, attendance, announcements; edit non-sensitive profile attributes (email, phone, department, semester). |
| **Faculty** | `faculty` | Level 2 (Academic Staff) | View assigned course sections, view rosters of enrolled students, enter and update numerical scores (midterm, final) for assigned courses only. |
| **Administrator** | `admin` | Level 3 (Superuser) | Provision synthetic student/faculty accounts, activate/deactivate accounts, view all system accounts, inspect complete defensive audit trail. |

### 2.2 Web Application & Routing Layer (`app.py`)

- **Routing Dispatcher:** Maps HTTP endpoints (`/student/*`, `/faculty/*`, `/admin/*`) to controller handlers.
- **Template Engine:** Jinja2 renders HTML with strict context-variable autoescaping enabled by default, mitigating cross-site scripting (XSS).
- **Security Headers Filter (`@app.after_request`):** Enforces defence-in-depth headers on every HTTP response:
  - `Content-Security-Policy`: Restricts scripts, styles, and assets strictly to `'self'`.
  - `X-Frame-Options: DENY`: Prevents UI redressing and clickjacking.
  - `X-Content-Type-Options: nosniff`: Prevents MIME-confusion attacks.
  - `Referrer-Policy: strict-origin-when-cross-origin`: Minimizes referrer leakage.
  - `Cache-Control: no-store, no-cache, private`: Ensures authenticated records are not cached by intermediate proxies or browser history.
- **Generic Error Handlers:** Traps HTTP 400, 403, 404, and 500 errors to prevent Python traceback disclosure.

### 2.3 Authentication & Session Subsystem (`security.py`, `config.py`)

- **Password Storage:** Uses Werkzeug's implementation of salted adaptive cryptographic hashing (`scrypt` / `pbkdf2:sha256`). Plaintext passwords never persist.
- **Session State:** Managed through cryptographically signed client cookies (`flask.session`).
  - `HttpOnly = True`: Cookie cannot be read or exfiltrated via JavaScript `document.cookie`.
  - `SameSite = 'Lax'`: Cookie is withheld on cross-site requests, defending against cross-site request forgery.
  - `Lifetime = 1800s`: Sessions expire after 30 minutes of inactivity.
  - `Session Regeneration`: The session dictionary is explicitly cleared and re-keyed upon successful login, eliminating session fixation vulnerabilities.
- **Brute-Force Throttling:** An in-memory sliding window tracks failed authentication attempts per `(client_ip, username)`. If 5 failures occur within 60 seconds, further attempts receive HTTP `429 Too Many Requests`.

### 2.4 Data Persistence & Schema (`database.py`)

The application interfaces directly with SQLite 3 using parameterized SQL statements (`?` parameters). Foreign key constraints (`PRAGMA foreign_keys = ON`) are enforced.

```mermaid
erDiagram
    users ||--o| students : "has profile"
    users ||--o| faculty : "has profile"
    faculty ||--o{ courses : "instructs"
    students ||--o{ enrollments : "enrolled in"
    courses ||--o{ enrollments : "contains"
    enrollments ||--|| grades : "evaluated by"
    enrollments ||--|| attendance : "tracked by"
    users ||--o{ audit_logs : "triggers"
```

1. **`users`**: Base credentials table (`id`, `username`, `password_hash`, `role`, `is_active`, `created_at`, `last_login`).
2. **`students`**: Student demographics (`id`, `user_id`, `student_id_code`, `full_name`, `email`, `phone`, `department`, `semester`).
3. **`faculty`**: Instructor demographics (`id`, `user_id`, `faculty_id_code`, `full_name`, `email`, `phone`, `department`).
4. **`courses`**: Course catalog (`id`, `course_code`, `title`, `department`, `credits`, `faculty_id`).
5. **`enrollments`**: Junction table (`id`, `student_id`, `course_id`, `enrollment_date`).
6. **`grades`**: Academic marks (`id`, `enrollment_id`, `midterm_score`, `final_score`, `total_score`, `letter_grade`, `updated_by_faculty_id`, `updated_at`).
7. **`attendance`**: Class participation (`id`, `enrollment_id`, `total_classes`, `attended_classes`, `percentage`, `updated_at`).
8. **`announcements`**: System bulletins (`id`, `title`, `content`, `author_role`, `created_at`).
9. **`audit_logs`**: Security telemetry (`id`, `timestamp`, `event_type`, `user_id`, `username`, `ip_address`, `status`, `details`).

---

## 3. Trust Boundaries

### Trust Boundary 1: Client Web Browser <---> Flask Application Server
- **Boundary Location:** HTTP interface (`127.0.0.1:5000`).
- **Threat Vector:** Malicious HTTP requests, tampered form parameters, stolen session tokens, CSRF attempts, XSS payloads.
- **Defensive Mechanism:** Session signatures, CSRF synchronizer tokens, CSP headers, rate-limiting, and server-side input validation.

### Trust Boundary 2: Flask Application Server <---> SQLite Database File
- **Boundary Location:** Python database driver interface.
- **Threat Vector:** SQL injection (SQLi) resulting in authentication bypass, data exfiltration, or table dropping.
- **Defensive Mechanism:** 100% parameterized queries. No dynamic string concatenation or f-strings in SQL execution.

### Trust Boundary 3: Role Separation & Horizontal Authorization Boundaries
- **Boundary Location:** Controller dispatch points.
- **Threat Vector:**
  - *Vertical Escalation:* A student accessing `/admin/users` or `/faculty/grades`.
  - *Horizontal Escalation (IDOR):* Student A viewing/editing Student B's grades, or Faculty A modifying marks in Faculty B's assigned course.
- **Defensive Mechanism:** `@roles_required` decorator checks active DB role, and course-ownership SQL checks verify `courses.faculty_id == session.faculty_id`.

---

## 4. Key Data Flows

### 4.1 Authentication & Session Initiation Flow

```mermaid
sequenceDiagram
    autonumber
    actor User as User Browser (127.0.0.1)
    participant Flask as Flask Controller
    participant Limiter as In-Memory Rate Limiter
    participant DB as SQLite 3 (campus_portal.db)
    participant Audit as Defensive Audit Subsystem

    User->>Flask: POST /login (username, password, csrf_token)
    Flask->>Limiter: Check failed attempts for (client_ip, username)
    alt Rate Limit Exceeded (>= 5 failed attempts in 60s)
        Limiter-->>Flask: Throttled (Locked)
        Flask->>Audit: Record LOGIN_RATE_LIMITED
        Flask-->>User: HTTP 429 Too Many Requests (Wait 60s)
    else Within Rate Limits
        Limiter-->>Flask: Allowed (< 5 attempts)
        Flask->>DB: Query user hash: SELECT * FROM users WHERE username = ?
        DB-->>Flask: Return user record & salted password hash
        Flask->>Flask: Verify password hash (scrypt / pbkdf2)
        alt Authentication Failed (Incorrect Password)
            Flask->>Limiter: Increment failed attempt counter (+1)
            Flask->>Audit: Record LOGIN_FAILURE (username, client_ip)
            Flask-->>User: HTTP 401 Unauthorized ("Invalid username or password")
        else Authentication Successful & Account Active
            Flask->>Limiter: Reset failed attempt counter
            Flask->>Audit: Record LOGIN_SUCCESS (user_id, username, client_ip)
            Flask-->>User: HTTP 302 Redirect + Set Session Cookie (HttpOnly=True, SameSite=Lax)
        end
    end
```

### 4.2 Faculty Grade Modification Flow (IDOR Defense)

```mermaid
sequenceDiagram
    autonumber
    actor Faculty as Faculty Browser
    participant Flask as Flask Controller
    participant DB as SQLite 3 (campus_portal.db)
    participant Audit as Defensive Audit Subsystem

    Faculty->>Flask: POST /faculty/update-grade (csrf_token, grade_id, midterm, final)
    Flask->>Flask: Validate CSRF Synchronizer Token
    Flask->>Flask: Enforce RBAC (@roles_required('faculty'))
    Flask->>DB: Verify Ownership: courses.faculty_id == session.faculty_id
    alt Ownership Check Fails (Horizontal Tampering / IDOR Attempt)
        DB-->>Flask: Mismatch: Course taught by another instructor
        Flask->>Audit: Record ACCESS_DENIED (unauthorized grade tampering attempt)
        Flask-->>Faculty: HTTP 403 Forbidden ("Access Denied: Course ownership mismatch")
    else Ownership Confirmed (Authorized Instructor)
        DB-->>Flask: Authorized instructor confirmed
        Flask->>Flask: Validate numerical bounds (0.0 <= score <= 50.0)
        Flask->>DB: Parameterized UPDATE grades SET midterm=?, final=?, letter_grade=?
        Flask->>Audit: Record GRADE_UPDATE (student_id, course_id, old_marks, new_marks)
        Flask-->>Faculty: HTTP 302 Redirect + Flash Success Message
    end
```

---

## 5. External Dependencies Review

In accordance with strict cybersecurity lab isolation requirements:
- **External Network Calls:** **ZERO**. The application makes no outbound HTTP, DNS, or socket calls.
- **Third-Party CDNs:** **ZERO**. Bootstrap, Tailwind, FontAwesome, Google Fonts, and external JS libraries have been completely omitted in favor of self-contained local CSS and vanilla JS.
- **Package Footprint:** Dependent exclusively on Python 3 standard library and `flask` / `werkzeug`.
