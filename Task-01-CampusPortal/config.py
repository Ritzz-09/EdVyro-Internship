"""
CampusPortal - Application Configuration
Authorized Local Defensive Lab - 127.0.0.1 only.
"""

import os
import secrets

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    # Security: Secret key for session management and CSRF tokens
    # Generates a persistent random secret per process or loads from environment
    SECRET_KEY = os.environ.get("CAMPUS_PORTAL_SECRET_KEY") or secrets.token_hex(32)

    # Database file path (SQLite)
    DATABASE_PATH = os.path.join(BASE_DIR, "campus_portal.db")

    # Local-only network configuration
    HOST = "127.0.0.1"
    PORT = 5000
    DEBUG = False

    # Session cookie security baseline
    # Note: SESSION_COOKIE_SECURE is False here to allow local HTTP testing on 127.0.0.1.
    # In production with TLS/HTTPS, this MUST be set to True.
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = False
    PERMANENT_SESSION_LIFETIME = 1800  # 30 minutes session expiry

    # Rate limiting configuration (in-memory)
    LOGIN_RATE_LIMIT_ATTEMPTS = 5
    LOGIN_RATE_LIMIT_WINDOW_SECONDS = 60
