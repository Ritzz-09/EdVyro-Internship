"""
CampusPortal - Security Controls and Defensive Utilities
Authorized Local Defensive Lab - 127.0.0.1 only.
"""

import time
import re
import secrets
from functools import wraps
from datetime import datetime, timezone
from flask import session, request, redirect, url_for, abort, flash
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config
from database import get_db_connection

# In-memory rate limiting store: key -> list of timestamp floats
# Key is tuple: (ip_address, normalized_username)
_login_failed_attempts = {}

# Allowed departments for input validation
ALLOWED_DEPARTMENTS = [
    "Computer Science",
    "Cybersecurity",
    "Information Technology",
    "Software Engineering",
    "Data Science",
]

def hash_password(password: str) -> str:
    """Hashes a password using Werkzeug's secure defaults (scrypt or pbkdf2)."""
    return generate_password_hash(password)

def verify_password(password: str, password_hash: str) -> bool:
    """Safely compares a plaintext password against a stored hash."""
    return check_password_hash(password_hash, password)

def generate_csrf_token() -> str:
    """Generates or retrieves a per-session CSRF token."""
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(24)
    return session["_csrf_token"]

def validate_csrf_token(token: str) -> bool:
    """Validates the incoming CSRF token against the session token."""
    session_token = session.get("_csrf_token")
    if not session_token or not token:
        return False
    # Constant-time comparison
    return secrets.compare_digest(session_token, token)

def is_login_rate_limited(ip_address: str, username: str) -> bool:
    """
    Checks if a given IP + username has exceeded the allowed failed login attempts
    within the configured rate limit window.
    """
    now = time.time()
    key = (ip_address, (username or "").strip().lower())
    attempts = _login_failed_attempts.get(key, [])

    # Filter out attempts older than the window
    window = Config.LOGIN_RATE_LIMIT_WINDOW_SECONDS
    active_attempts = [t for t in attempts if now - t < window]
    _login_failed_attempts[key] = active_attempts

    return len(active_attempts) >= Config.LOGIN_RATE_LIMIT_ATTEMPTS

def record_login_failure(ip_address: str, username: str):
    """Records a timestamped failed login attempt for rate limiting."""
    now = time.time()
    key = (ip_address, (username or "").strip().lower())
    attempts = _login_failed_attempts.get(key, [])
    attempts.append(now)
    _login_failed_attempts[key] = attempts

def clear_login_failures(ip_address: str, username: str):
    """Resets failed login tracker upon successful authentication."""
    key = (ip_address, (username or "").strip().lower())
    if key in _login_failed_attempts:
        del _login_failed_attempts[key]

def log_audit_event(event_type: str, username: str, status: str, details: str, user_id=None, ip_address=None):
    """
    Inserts an audit record into the audit_logs SQLite table.
    Crucially: NEVER accepts or stores passwords, tokens, or raw credentials in details.
    """
    if not ip_address:
        ip_address = request.remote_addr if request else "127.0.0.1"

    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO audit_logs (timestamp, event_type, user_id, username, ip_address, status, details)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (now_iso, event_type, user_id, username, ip_address, status, details)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        # Avoid crashing application if audit write encounters an issue, but print to stderr
        print(f"[SECURITY AUDIT LOG ERROR] Failed to record event {event_type}: {e}")

def roles_required(*allowed_roles):
    """
    Decorator for route endpoints enforcing Role-Based Access Control (RBAC).
    Verifies:
      1. User session exists.
      2. User account is active in the database.
      3. User's role is in allowed_roles.
    Logs ACCESS_DENIED on authorization failure and renders 403 Forbidden.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_id = session.get("user_id")
            role = session.get("role")
            username = session.get("username")

            if not user_id or not role:
                flash("Please log in to access this page.", "warning")
                return redirect(url_for("login", next=request.path))

            # Database check: verify account is still active
            conn = get_db_connection()
            user = conn.execute(
                "SELECT id, is_active, role FROM users WHERE id = ?", (user_id,)
            ).fetchone()
            conn.close()

            if not user or user["is_active"] != 1:
                session.clear()
                flash("Your account has been deactivated or does not exist. Please contact an administrator.", "danger")
                log_audit_event(
                    "AUTH_REJECTED",
                    username,
                    "FAILURE",
                    "Attempted access with deactivated or deleted account.",
                    user_id=user_id
                )
                return redirect(url_for("login"))

            # Role verification
            if user["role"] not in allowed_roles:
                log_audit_event(
                    "ACCESS_DENIED",
                    username,
                    "FAILURE",
                    f"User with role '{user['role']}' attempted unauthorized access to '{request.path}' requiring {allowed_roles}.",
                    user_id=user_id
                )
                abort(403)

            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Input Validation Utilities
EMAIL_REGEX = re.compile(r"^[\w\.-]+@[\w\.-]+\.\w+$")
PHONE_REGEX = re.compile(r"^[\d\+\-\(\)\s]{7,20}$")

def validate_email(email: str) -> bool:
    """Validates email format."""
    if not email or len(email) > 120:
        return False
    return bool(EMAIL_REGEX.match(email.strip()))

def validate_phone(phone: str) -> bool:
    """Validates phone number format."""
    if not phone or len(phone) > 25:
        return False
    return bool(PHONE_REGEX.match(phone.strip()))

def validate_semester(sem_val) -> (bool, int):
    """Validates that semester is an integer between 1 and 8."""
    try:
        sem_int = int(sem_val)
        if 1 <= sem_int <= 8:
            return True, sem_int
        return False, 0
    except (ValueError, TypeError):
        return False, 0

def validate_department(dept: str) -> bool:
    """Checks if department is within permitted catalog list."""
    return dept in ALLOWED_DEPARTMENTS

def validate_score(score_val, max_score=50.0) -> (bool, float):
    """Validates that a grade score is a float within [0.0, max_score]."""
    try:
        val = float(score_val)
        if 0.0 <= val <= max_score:
            return True, round(val, 2)
        return False, 0.0
    except (ValueError, TypeError):
        return False, 0.0
