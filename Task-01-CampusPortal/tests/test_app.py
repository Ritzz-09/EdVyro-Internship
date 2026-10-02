"""
CampusPortal - Automated Security & Functional Verification Test Suite
Authorized Local Defensive Lab - 127.0.0.1 only.
"""

import os
import tempfile
import unittest
from app import create_app
from config import Config
from database import get_db_connection, init_db
from security import verify_password, _login_failed_attempts

class CampusPortalSecurityTestCase(unittest.TestCase):
    def setUp(self):
        # Create a temporary database for test isolation
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        self.app = create_app({
            "TESTING": True,
            "DATABASE_PATH": self.db_path,
            "SECRET_KEY": "test-defensive-secret-key-12345",
        })
        self.client = self.app.test_client()
        # Clear rate limiting store between tests
        _login_failed_attempts.clear()

    def tearDown(self):
        os.close(self.db_fd)
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
        _login_failed_attempts.clear()

    def get_csrf_token(self, response_data=None):
        """Helper to extract or establish a valid CSRF token via session."""
        with self.client.session_transaction() as sess:
            if "_csrf_token" not in sess:
                sess["_csrf_token"] = "test-csrf-token-abc"
            return sess["_csrf_token"]

    def login_as(self, username, password):
        """Helper to perform standard login with CSRF token."""
        token = self.get_csrf_token()
        return self.client.post("/login", data={
            "username": username,
            "password": password,
            "csrf_token": token
        }, follow_redirects=True)

    # ---------------------------------------------------------
    # 1. Database & Seed Data Verification
    # ---------------------------------------------------------

    def test_synthetic_seed_data_and_password_hashing(self):
        """Verify that synthetic accounts are seeded and passwords are encrypted, not plaintext."""
        conn = get_db_connection(self.db_path)
        users = conn.execute("SELECT username, password_hash, role FROM users").fetchall()
        conn.close()

        usernames = [u["username"] for u in users]
        self.assertIn("alice_student", usernames)
        self.assertIn("bob_student", usernames)
        self.assertIn("prof_smith", usernames)
        self.assertIn("admin_user", usernames)

        # Ensure passwords are NOT stored in plaintext
        for u in users:
            self.assertNotEqual(u["password_hash"], "StudentPass123!")
            self.assertNotEqual(u["password_hash"], "FacultyPass123!")
            self.assertNotEqual(u["password_hash"], "AdminPass123!")
            # Password hashes must start with scrypt: or pbkdf2:
            self.assertTrue(
                u["password_hash"].startswith("scrypt:") or u["password_hash"].startswith("pbkdf2:")
            )

    # ---------------------------------------------------------
    # 2. Authentication & Rate Limiting Tests
    # ---------------------------------------------------------

    def test_successful_student_login(self):
        """Verify valid student login creates session and redirects to student dashboard."""
        resp = self.login_as("alice_student", "StudentPass123!")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Welcome back, Alice Vance", resp.data)
        self.assertIn(b"LOCAL DEFENSIVE LAB", resp.data)

        # Check audit log for LOGIN_SUCCESS
        conn = get_db_connection(self.db_path)
        log = conn.execute(
            "SELECT * FROM audit_logs WHERE event_type = 'LOGIN_SUCCESS' AND username = 'alice_student'"
        ).fetchone()
        conn.close()
        self.assertIsNotNone(log)
        self.assertEqual(log["status"], "SUCCESS")

    def test_failed_login_and_audit_logging(self):
        """Verify incorrect password returns 401 and logs failure."""
        token = self.get_csrf_token()
        resp = self.client.post("/login", data={
            "username": "alice_student",
            "password": "WrongPassword!",
            "csrf_token": token
        })
        self.assertEqual(resp.status_code, 401)
        self.assertIn(b"Invalid username or password", resp.data)

        # Check audit log for LOGIN_FAILURE
        conn = get_db_connection(self.db_path)
        log = conn.execute(
            "SELECT * FROM audit_logs WHERE event_type = 'LOGIN_FAILURE' AND username = 'alice_student'"
        ).fetchone()
        conn.close()
        self.assertIsNotNone(log)
        self.assertEqual(log["status"], "FAILURE")
        # Passwords must NEVER be present in audit details
        self.assertNotIn("WrongPassword!", log["details"])

    def test_login_rate_limiting(self):
        """Verify exceeding 5 failed attempts locks the login and returns 429."""
        token = self.get_csrf_token()
        for i in range(Config.LOGIN_RATE_LIMIT_ATTEMPTS):
            resp = self.client.post("/login", data={
                "username": "alice_student",
                "password": f"Wrong_{i}",
                "csrf_token": token
            })
            self.assertEqual(resp.status_code, 401)

        # 6th attempt should be rate limited
        resp_limited = self.client.post("/login", data={
            "username": "alice_student",
            "password": "StudentPass123!",
            "csrf_token": token
        })
        self.assertEqual(resp_limited.status_code, 429)
        self.assertIn(b"Too many failed login attempts", resp_limited.data)

    # ---------------------------------------------------------
    # 3. Role-Based Access Control (RBAC) Tests
    # ---------------------------------------------------------

    def test_unauthenticated_access_redirects_to_login(self):
        """Unauthenticated requests to protected dashboards must redirect to /login."""
        for path in ["/student/dashboard", "/faculty/dashboard", "/admin/dashboard", "/admin/users"]:
            resp = self.client.get(path)
            self.assertEqual(resp.status_code, 302)
            self.assertIn("/login", resp.headers["Location"])

    def test_student_cannot_access_faculty_or_admin_pages(self):
        """A student accessing faculty or admin routes must be blocked with 403 Forbidden."""
        self.login_as("alice_student", "StudentPass123!")

        # Attempt to access faculty dashboard
        resp_faculty = self.client.get("/faculty/dashboard")
        self.assertEqual(resp_faculty.status_code, 403)
        self.assertIn(b"Access Denied / Forbidden", resp_faculty.data)

        # Attempt to access admin dashboard
        resp_admin = self.client.get("/admin/dashboard")
        self.assertEqual(resp_admin.status_code, 403)

        # Attempt to access admin users
        resp_admin_users = self.client.get("/admin/users")
        self.assertEqual(resp_admin_users.status_code, 403)

        # Verify ACCESS_DENIED is recorded in audit logs
        conn = get_db_connection(self.db_path)
        log = conn.execute(
            "SELECT * FROM audit_logs WHERE event_type = 'ACCESS_DENIED' AND username = 'alice_student'"
        ).fetchone()
        conn.close()
        self.assertIsNotNone(log)

    def test_faculty_cannot_access_admin_pages(self):
        """Faculty accessing admin console must be denied with 403."""
        self.login_as("prof_smith", "FacultyPass123!")
        resp = self.client.get("/admin/dashboard")
        self.assertEqual(resp.status_code, 403)

        resp_audit = self.client.get("/admin/audit")
        self.assertEqual(resp_audit.status_code, 403)

    # ---------------------------------------------------------
    # 4. CSRF Protection Tests
    # ---------------------------------------------------------

    def test_post_without_csrf_token_rejected(self):
        """POST requests missing CSRF token must be rejected with 400 Bad Request."""
        self.login_as("alice_student", "StudentPass123!")

        # Post profile change without token
        resp = self.client.post("/student/profile", data={
            "email": "tampered@hack.local",
            "phone": "555-0999",
            "department": "Computer Science",
            "semester": "4"
        })
        self.assertEqual(resp.status_code, 400)
        self.assertIn(b"Invalid CSRF token", resp.data)

    # ---------------------------------------------------------
    # 5. Student Profile Modification & Input Validation
    # ---------------------------------------------------------

    def test_student_valid_profile_update(self):
        """Student can successfully update permitted non-sensitive fields."""
        self.login_as("alice_student", "StudentPass123!")
        token = self.get_csrf_token()

        resp = self.client.post("/student/profile", data={
            "csrf_token": token,
            "email": "alice.updated@campus.local",
            "phone": "555-0199",
            "department": "Cybersecurity",
            "semester": "5"
        }, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Profile updated successfully", resp.data)

        # Verify database update
        conn = get_db_connection(self.db_path)
        student = conn.execute("SELECT * FROM students WHERE student_id_code = 'STU-2024-001'").fetchone()
        conn.close()
        self.assertEqual(student["email"], "alice.updated@campus.local")
        self.assertEqual(student["department"], "Cybersecurity")
        self.assertEqual(student["semester"], 5)

    def test_student_invalid_profile_input_rejected(self):
        """Invalid email or invalid semester values must be rejected."""
        self.login_as("alice_student", "StudentPass123!")
        token = self.get_csrf_token()

        resp = self.client.post("/student/profile", data={
            "csrf_token": token,
            "email": "not-an-email",
            "phone": "555-0101",
            "department": "Computer Science",
            "semester": "99"  # Outside 1-8
        })
        self.assertEqual(resp.status_code, 400)
        self.assertIn(b"Invalid email address format", resp.data)

    # ---------------------------------------------------------
    # 6. Faculty Grade Management & IDOR Defense
    # ---------------------------------------------------------

    def test_faculty_grade_update_and_audit(self):
        """Faculty can update marks for courses they instruct."""
        self.login_as("prof_smith", "FacultyPass123!")
        token = self.get_csrf_token()

        # prof_smith teaches CS101 (grade_id = 1 for Alice Vance)
        resp = self.client.post("/faculty/update-grade", data={
            "csrf_token": token,
            "grade_id": 1,
            "course_id": 1,
            "midterm_score": "45.0",
            "final_score": "48.0"
        }, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)

        # Verify in DB
        conn = get_db_connection(self.db_path)
        grade = conn.execute("SELECT * FROM grades WHERE id = 1").fetchone()
        self.assertEqual(grade["midterm_score"], 45.0)
        self.assertEqual(grade["final_score"], 48.0)
        self.assertEqual(grade["total_score"], 93.0)
        self.assertEqual(grade["letter_grade"], "A+")

        # Check GRADE_UPDATE in audit log
        log = conn.execute(
            "SELECT * FROM audit_logs WHERE event_type = 'GRADE_UPDATE' AND username = 'prof_smith'"
        ).fetchone()
        conn.close()
        self.assertIsNotNone(log)
        self.assertIn("STU-2024-001", log["details"])

    def test_faculty_cross_course_grade_tampering_blocked(self):
        """Faculty attempting to modify grades in another professor's course must be blocked with 403."""
        self.login_as("prof_smith", "FacultyPass123!")
        token = self.get_csrf_token()

        # grade_id = 2 is SEC201, taught by prof_chen, NOT prof_smith
        resp = self.client.post("/faculty/update-grade", data={
            "csrf_token": token,
            "grade_id": 2,
            "course_id": 2,
            "midterm_score": "50.0",
            "final_score": "50.0"
        })
        self.assertEqual(resp.status_code, 403)

    # ---------------------------------------------------------
    # 7. Admin User Provisioning and Account Deactivation
    # ---------------------------------------------------------

    def test_admin_create_synthetic_user(self):
        """Admin can provision a new synthetic user."""
        self.login_as("admin_user", "AdminPass123!")
        token = self.get_csrf_token()

        resp = self.client.post("/admin/create-user", data={
            "csrf_token": token,
            "username": "david_student",
            "password": "DavidPass123!",
            "role": "student",
            "full_name": "David Miller",
            "id_code": "STU-2024-005",
            "email": "david.miller@campus.local",
            "phone": "555-0105",
            "department": "Computer Science",
            "semester": "2"
        }, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Successfully provisioned synthetic student account", resp.data)

        # Verify user can log in
        self.client.post("/logout", data={"csrf_token": self.get_csrf_token()})
        resp_login = self.login_as("david_student", "DavidPass123!")
        self.assertEqual(resp_login.status_code, 200)
        self.assertIn(b"Welcome back, David Miller", resp_login.data)

    def test_admin_deactivate_user(self):
        """Admin deactivating a user prevents subsequent logins and invalidates access."""
        self.login_as("admin_user", "AdminPass123!")
        token = self.get_csrf_token()

        # Deactivate bob_student (user_id = 5)
        resp = self.client.post("/admin/toggle-user-status", data={
            "csrf_token": token,
            "user_id": 5
        }, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)

        # Now attempt login as bob_student
        self.client.post("/logout", data={"csrf_token": self.get_csrf_token()})
        token = self.get_csrf_token()
        resp_bob = self.client.post("/login", data={
            "username": "bob_student",
            "password": "StudentPass123!",
            "csrf_token": token
        })
        self.assertEqual(resp_bob.status_code, 403)
        self.assertIn(b"Your account has been deactivated", resp_bob.data)

    def test_admin_cannot_self_deactivate(self):
        """Defensive guard prevents admin from deactivating their own account."""
        self.login_as("admin_user", "AdminPass123!")
        token = self.get_csrf_token()

        resp = self.client.post("/admin/toggle-user-status", data={
            "csrf_token": token,
            "user_id": 1  # admin_user id
        }, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"You cannot deactivate your own administrative account", resp.data)

    # ---------------------------------------------------------
    # 8. Security Headers and Error Pages
    # ---------------------------------------------------------

    def test_security_headers_present(self):
        """Verify baseline defensive HTTP headers on responses."""
        resp = self.client.get("/login")
        self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertIn("default-src 'self'", resp.headers.get("Content-Security-Policy", ""))
        self.assertEqual(resp.headers.get("Referrer-Policy"), "strict-origin-when-cross-origin")

    def test_error_pages_suppress_stack_traces(self):
        """Verify 404 and 403 pages return clean user templates without stack traces."""
        resp_404 = self.client.get("/non-existent-page")
        self.assertEqual(resp_404.status_code, 404)
        self.assertIn(b"Resource Not Found", resp_404.data)
        self.assertNotIn(b"Traceback (most recent call last)", resp_404.data)

    # ---------------------------------------------------------
    # 9. Localhost Network Isolation
    # ---------------------------------------------------------

    def test_localhost_only_binding_configured(self):
        """Verify that server host is set exclusively to 127.0.0.1."""
        self.assertEqual(Config.HOST, "127.0.0.1")
        self.assertNotEqual(Config.HOST, "0.0.0.0")

if __name__ == "__main__":
    unittest.main()
