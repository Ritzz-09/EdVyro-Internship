"""
CampusPortal - Flask Web Application
Authorized Local Defensive Lab - 127.0.0.1 only.
"""

import os
from datetime import datetime, timezone
from flask import (
    Flask, render_template, request, redirect, url_for, session,
    flash, abort, jsonify
)
from config import Config
from database import (
    init_db, get_db_connection, compute_letter_grade
)
from security import (
    hash_password, verify_password, generate_csrf_token, validate_csrf_token,
    is_login_rate_limited, record_login_failure, clear_login_failures,
    log_audit_event, roles_required, validate_email, validate_phone,
    validate_semester, validate_department, validate_score, ALLOWED_DEPARTMENTS
)

def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_object(Config)

    if test_config:
        app.config.update(test_config)

    # Initialize database tables and seed data if not present
    with app.app_context():
        init_db(app.config["DATABASE_PATH"])

    # Template context processor to make csrf_token accessible in all templates
    @app.context_processor
    def inject_csrf_token():
        return dict(csrf_token=generate_csrf_token)

    # Security Headers Hook
    @app.after_request
    def set_security_headers(response):
        # Strict local-first Content Security Policy - zero external CDN sources allowed
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "object-src 'none'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )
        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"
        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        # Referrer Policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        # Permissions Policy
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        # Cache control for authenticated sessions
        if "user_id" in session:
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            response.headers["Pragma"] = "no-cache"
        return response

    # Error Handlers
    @app.errorhandler(400)
    def bad_request_error(e):
        return render_template("errors/400.html"), 400

    @app.errorhandler(403)
    def forbidden_error(e):
        return render_template("errors/403.html"), 403

    @app.errorhandler(404)
    def not_found_error(e):
        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def internal_error(e):
        # Suppress stack traces to prevent defensive information disclosure
        return render_template("errors/500.html"), 500

    # -------------------------------------------------------------
    # Authentication Routes
    # -------------------------------------------------------------

    @app.route("/")
    def index():
        if "user_id" in session:
            role = session.get("role")
            if role == "student":
                return redirect(url_for("student_dashboard"))
            elif role == "faculty":
                return redirect(url_for("faculty_dashboard"))
            elif role == "admin":
                return redirect(url_for("admin_dashboard"))
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            # CSRF Verification
            submitted_token = request.form.get("csrf_token")
            if not validate_csrf_token(submitted_token):
                flash("Invalid or missing CSRF security token.", "danger")
                return render_template("login.html"), 400

            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            client_ip = request.remote_addr or "127.0.0.1"

            # 1. Rate Limiting Check
            if is_login_rate_limited(client_ip, username):
                log_audit_event(
                    "LOGIN_RATE_LIMITED",
                    username,
                    "FAILURE",
                    f"Authentication throttled due to exceeding rate limit threshold ({Config.LOGIN_RATE_LIMIT_ATTEMPTS} attempts).",
                    ip_address=client_ip
                )
                flash(f"Too many failed login attempts. Please wait {Config.LOGIN_RATE_LIMIT_WINDOW_SECONDS} seconds before trying again.", "danger")
                return render_template("login.html"), 429

            # 2. Query user with parameterized query
            conn = get_db_connection(app.config["DATABASE_PATH"])
            user = conn.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()

            if not user or not verify_password(password, user["password_hash"]):
                # Record failed attempt
                record_login_failure(client_ip, username)
                log_audit_event(
                    "LOGIN_FAILURE",
                    username,
                    "FAILURE",
                    "Invalid username or password credentials supplied.",
                    user_id=user["id"] if user else None,
                    ip_address=client_ip
                )
                conn.close()
                flash("Invalid username or password.", "danger")
                return render_template("login.html"), 401

            # Check account active status
            if user["is_active"] != 1:
                log_audit_event(
                    "LOGIN_FAILURE",
                    username,
                    "FAILURE",
                    "Attempted login to deactivated account.",
                    user_id=user["id"],
                    ip_address=client_ip
                )
                conn.close()
                flash("Your account has been deactivated. Contact an administrator.", "danger")
                return render_template("login.html"), 403

            # 3. Successful Authentication
            clear_login_failures(client_ip, username)

            # Update last_login timestamp
            now_iso = datetime.now(timezone.utc).isoformat()
            conn.execute(
                "UPDATE users SET last_login = ? WHERE id = ?", (now_iso, user["id"])
            )
            conn.commit()
            conn.close()

            # Session regeneration to prevent session fixation
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            # Generate new CSRF token for the new session
            generate_csrf_token()

            log_audit_event(
                "LOGIN_SUCCESS",
                username,
                "SUCCESS",
                f"User logged in successfully with role '{user['role']}'.",
                user_id=user["id"],
                ip_address=client_ip
            )

            flash(f"Welcome back, {user['username']}!", "success")

            next_url = request.args.get("next")
            if next_url and next_url.startswith("/"):
                return redirect(next_url)

            if user["role"] == "student":
                return redirect(url_for("student_dashboard"))
            elif user["role"] == "faculty":
                return redirect(url_for("faculty_dashboard"))
            elif user["role"] == "admin":
                return redirect(url_for("admin_dashboard"))

        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    def logout():
        submitted_token = request.form.get("csrf_token")
        if not validate_csrf_token(submitted_token):
            flash("Invalid security token.", "danger")
            return redirect(url_for("index"))

        username = session.get("username", "Unknown")
        user_id = session.get("user_id")

        log_audit_event(
            "LOGOUT",
            username,
            "SUCCESS",
            "User initiated session termination (logout).",
            user_id=user_id
        )

        session.clear()
        flash("You have been signed out successfully.", "info")
        return redirect(url_for("login"))

    # -------------------------------------------------------------
    # Student Routes
    # -------------------------------------------------------------

    @app.route("/student/dashboard")
    @roles_required("student")
    def student_dashboard():
        user_id = session["user_id"]
        conn = get_db_connection(app.config["DATABASE_PATH"])

        student = conn.execute(
            "SELECT * FROM students WHERE user_id = ?", (user_id,)
        ).fetchone()

        if not student:
            conn.close()
            abort(404)

        # Enrolled courses with faculty name, grades, and attendance
        courses_summary = conn.execute("""
            SELECT c.course_code, c.title, c.credits, f.full_name AS faculty_name,
                   COALESCE(g.total_score, 0.0) AS total_score,
                   COALESCE(g.letter_grade, 'N/A') AS letter_grade,
                   COALESCE(a.percentage, 0.0) AS attendance_pct
            FROM enrollments e
            JOIN courses c ON e.course_id = c.id
            LEFT JOIN faculty f ON c.faculty_id = f.id
            LEFT JOIN grades g ON g.enrollment_id = e.id
            LEFT JOIN attendance a ON a.enrollment_id = e.id
            WHERE e.student_id = ?
        """, (student["id"],)).fetchall()

        # Enrollments list
        enrollments = conn.execute(
            "SELECT id FROM enrollments WHERE student_id = ?", (student["id"],)
        ).fetchall()

        # Calculate averages
        avg_grade = None
        overall_attendance = None
        if courses_summary:
            scores = [row["total_score"] for row in courses_summary if row["total_score"] > 0]
            if scores:
                avg_grade = sum(scores) / len(scores)
            att_scores = [row["attendance_pct"] for row in courses_summary]
            if att_scores:
                overall_attendance = sum(att_scores) / len(att_scores)

        # Announcements
        announcements = conn.execute(
            "SELECT * FROM announcements ORDER BY created_at DESC LIMIT 5"
        ).fetchall()

        conn.close()
        return render_template(
            "student/dashboard.html",
            student=student,
            enrollments=enrollments,
            courses_summary=courses_summary,
            avg_grade=avg_grade,
            overall_attendance=overall_attendance,
            announcements=announcements
        )

    @app.route("/student/profile", methods=["GET", "POST"])
    @roles_required("student")
    def student_profile():
        user_id = session["user_id"]
        conn = get_db_connection(app.config["DATABASE_PATH"])
        student = conn.execute(
            "SELECT * FROM students WHERE user_id = ?", (user_id,)
        ).fetchone()

        if not student:
            conn.close()
            abort(404)

        if request.method == "POST":
            # CSRF Verification
            submitted_token = request.form.get("csrf_token")
            if not validate_csrf_token(submitted_token):
                conn.close()
                flash("Invalid CSRF token.", "danger")
                return render_template("student/profile.html", student=student, departments=ALLOWED_DEPARTMENTS), 400

            email = request.form.get("email", "").strip()
            phone = request.form.get("phone", "").strip()
            department = request.form.get("department", "").strip()
            semester_raw = request.form.get("semester", "")

            # Input validation checks
            errors = []
            if not validate_email(email):
                errors.append("Invalid email address format.")
            if not validate_phone(phone):
                errors.append("Invalid phone number format.")
            if not validate_department(department):
                errors.append("Invalid department selected.")
            valid_sem, semester = validate_semester(semester_raw)
            if not valid_sem:
                errors.append("Semester must be an integer between 1 and 8.")

            if errors:
                for err in errors:
                    flash(err, "danger")
                conn.close()
                return render_template("student/profile.html", student=student, departments=ALLOWED_DEPARTMENTS), 400

            # Safe parameterized update of non-sensitive fields only
            conn.execute("""
                UPDATE students
                SET email = ?, phone = ?, department = ?, semester = ?
                WHERE id = ?
            """, (email, phone, department, semester, student["id"]))
            conn.commit()

            log_audit_event(
                "PROFILE_UPDATE",
                session.get("username"),
                "SUCCESS",
                f"Student profile updated for ID {student['student_id_code']} (Email: {email}, Dept: {department}, Sem: {semester}).",
                user_id=user_id
            )

            # Re-fetch updated record
            student = conn.execute(
                "SELECT * FROM students WHERE id = ?", (student["id"],)
            ).fetchone()
            conn.close()

            flash("Profile updated successfully.", "success")
            return render_template("student/profile.html", student=student, departments=ALLOWED_DEPARTMENTS)

        conn.close()
        return render_template("student/profile.html", student=student, departments=ALLOWED_DEPARTMENTS)

    @app.route("/student/grades")
    @roles_required("student")
    def student_grades():
        user_id = session["user_id"]
        conn = get_db_connection(app.config["DATABASE_PATH"])
        student = conn.execute(
            "SELECT id FROM students WHERE user_id = ?", (user_id,)
        ).fetchone()

        if not student:
            conn.close()
            abort(404)

        grades_data = conn.execute("""
            SELECT c.course_code, c.title, c.credits, f.full_name AS faculty_name,
                   g.midterm_score, g.final_score, g.total_score, g.letter_grade
            FROM enrollments e
            JOIN courses c ON e.course_id = c.id
            LEFT JOIN faculty f ON c.faculty_id = f.id
            JOIN grades g ON g.enrollment_id = e.id
            WHERE e.student_id = ?
            ORDER BY c.course_code ASC
        """, (student["id"],)).fetchall()

        conn.close()
        return render_template("student/grades.html", grades_data=grades_data)

    @app.route("/student/attendance")
    @roles_required("student")
    def student_attendance():
        user_id = session["user_id"]
        conn = get_db_connection(app.config["DATABASE_PATH"])
        student = conn.execute(
            "SELECT id FROM students WHERE user_id = ?", (user_id,)
        ).fetchone()

        if not student:
            conn.close()
            abort(404)

        attendance_data = conn.execute("""
            SELECT c.course_code, c.title, a.total_classes, a.attended_classes,
                   a.percentage, a.updated_at
            FROM enrollments e
            JOIN courses c ON e.course_id = c.id
            JOIN attendance a ON a.enrollment_id = e.id
            WHERE e.student_id = ?
            ORDER BY c.course_code ASC
        """, (student["id"],)).fetchall()

        conn.close()
        return render_template("student/attendance.html", attendance_data=attendance_data)

    # -------------------------------------------------------------
    # Faculty Routes
    # -------------------------------------------------------------

    @app.route("/faculty/dashboard")
    @roles_required("faculty")
    def faculty_dashboard():
        user_id = session["user_id"]
        conn = get_db_connection(app.config["DATABASE_PATH"])
        faculty = conn.execute(
            "SELECT * FROM faculty WHERE user_id = ?", (user_id,)
        ).fetchone()

        if not faculty:
            conn.close()
            abort(404)

        # Courses assigned to this faculty member with enrolled student counts
        courses = conn.execute("""
            SELECT c.*, COUNT(e.id) AS enrolled_count
            FROM courses c
            LEFT JOIN enrollments e ON c.id = e.course_id
            WHERE c.faculty_id = ?
            GROUP BY c.id
            ORDER BY c.course_code ASC
        """, (faculty["id"],)).fetchall()

        total_students = sum(c["enrolled_count"] for c in courses) if courses else 0

        conn.close()
        return render_template(
            "faculty/dashboard.html",
            faculty=faculty,
            courses=courses,
            total_students=total_students
        )

    @app.route("/faculty/grades")
    @roles_required("faculty")
    def faculty_grades():
        user_id = session["user_id"]
        conn = get_db_connection(app.config["DATABASE_PATH"])
        faculty = conn.execute(
            "SELECT id FROM faculty WHERE user_id = ?", (user_id,)
        ).fetchone()

        if not faculty:
            conn.close()
            abort(404)

        courses = conn.execute("""
            SELECT c.*, COUNT(e.id) AS enrolled_count
            FROM courses c
            LEFT JOIN enrollments e ON c.id = e.course_id
            WHERE c.faculty_id = ?
            GROUP BY c.id
            ORDER BY c.course_code ASC
        """, (faculty["id"],)).fetchall()

        course_id_param = request.args.get("course_id")
        selected_course = None
        roster = []

        if courses:
            if course_id_param:
                # Find matching assigned course (verifying faculty ownership)
                for c in courses:
                    if str(c["id"]) == str(course_id_param):
                        selected_course = c
                        break
            if not selected_course:
                selected_course = courses[0]

            # Fetch roster for selected course
            roster = conn.execute("""
                SELECT s.student_id_code, s.full_name, g.id AS grade_id,
                       g.midterm_score, g.final_score, g.total_score, g.letter_grade,
                       COALESCE(a.total_classes, 0) AS total_classes,
                       COALESCE(a.attended_classes, 0) AS attended_classes,
                       COALESCE(a.percentage, 0.0) AS attendance_pct
                FROM enrollments e
                JOIN students s ON e.student_id = s.id
                JOIN grades g ON g.enrollment_id = e.id
                LEFT JOIN attendance a ON a.enrollment_id = e.id
                WHERE e.course_id = ?
                ORDER BY s.student_id_code ASC
            """, (selected_course["id"],)).fetchall()

        conn.close()
        return render_template(
            "faculty/grades.html",
            courses=courses,
            selected_course=selected_course,
            roster=roster
        )

    @app.route("/faculty/update-grade", methods=["POST"])
    @roles_required("faculty")
    def faculty_update_grade():
        user_id = session["user_id"]
        submitted_token = request.form.get("csrf_token")
        if not validate_csrf_token(submitted_token):
            flash("Invalid CSRF token.", "danger")
            return redirect(url_for("faculty_grades"))

        conn = get_db_connection(app.config["DATABASE_PATH"])
        faculty = conn.execute(
            "SELECT id FROM faculty WHERE user_id = ?", (user_id,)
        ).fetchone()

        grade_id = request.form.get("grade_id")
        course_id = request.form.get("course_id")
        midterm_raw = request.form.get("midterm_score")
        final_raw = request.form.get("final_score")

        # Authorization check: verify that this grade record belongs to an enrollment in a course assigned to this faculty!
        # This defends against IDOR and cross-faculty grade tampering.
        grade_record = conn.execute("""
            SELECT g.id, g.enrollment_id, g.midterm_score, g.final_score, c.faculty_id, c.course_code, s.student_id_code
            FROM grades g
            JOIN enrollments e ON g.enrollment_id = e.id
            JOIN courses c ON e.course_id = c.id
            JOIN students s ON e.student_id = s.id
            WHERE g.id = ?
        """, (grade_id,)).fetchone()

        if not grade_record or grade_record["faculty_id"] != faculty["id"]:
            log_audit_event(
                "ACCESS_DENIED",
                session.get("username"),
                "FAILURE",
                f"Unauthorized attempt to modify grade_id {grade_id} for course not assigned to faculty.",
                user_id=user_id
            )
            conn.close()
            abort(403)

        # Validate score values
        valid_mid, mid_score = validate_score(midterm_raw, max_score=50.0)
        valid_fin, fin_score = validate_score(final_raw, max_score=50.0)

        if not valid_mid or not valid_fin:
            conn.close()
            flash("Scores must be valid numbers between 0.0 and 50.0.", "danger")
            return redirect(url_for("faculty_grades", course_id=course_id))

        total_score = round(mid_score + fin_score, 2)
        letter_grade = compute_letter_grade(total_score)
        now_iso = datetime.now(timezone.utc).isoformat()

        # Update grade with parameterized query
        conn.execute("""
            UPDATE grades
            SET midterm_score = ?, final_score = ?, total_score = ?, letter_grade = ?,
                updated_by_faculty_id = ?, updated_at = ?
            WHERE id = ?
        """, (mid_score, fin_score, total_score, letter_grade, faculty["id"], now_iso, grade_id))
        conn.commit()

        # Non-repudiation: Audit log record
        log_audit_event(
            "GRADE_UPDATE",
            session.get("username"),
            "SUCCESS",
            f"Grade modified for student {grade_record['student_id_code']} in {grade_record['course_code']}: Midterm={mid_score}, Final={fin_score}, Total={total_score} ({letter_grade}).",
            user_id=user_id
        )

        conn.close()
        flash(f"Grade updated for {grade_record['student_id_code']} ({letter_grade}).", "success")
        return redirect(url_for("faculty_grades", course_id=course_id))

    # -------------------------------------------------------------
    # Administrator Routes
    # -------------------------------------------------------------

    @app.route("/admin/dashboard")
    @roles_required("admin")
    def admin_dashboard():
        conn = get_db_connection(app.config["DATABASE_PATH"])

        total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        total_students = conn.execute("SELECT COUNT(*) FROM students").fetchone()[0]
        total_faculty = conn.execute("SELECT COUNT(*) FROM faculty").fetchone()[0]
        total_audit_events = conn.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]

        recent_logs = conn.execute("""
            SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 6
        """).fetchall()

        conn.close()

        stats = {
            "total_users": total_users,
            "total_students": total_students,
            "total_faculty": total_faculty,
            "total_audit_events": total_audit_events
        }

        return render_template("admin/dashboard.html", stats=stats, recent_logs=recent_logs)

    @app.route("/admin/users")
    @roles_required("admin")
    def admin_users():
        conn = get_db_connection(app.config["DATABASE_PATH"])
        users = conn.execute("""
            SELECT u.id, u.username, u.role, u.is_active, u.created_at, u.last_login,
                   COALESCE(s.full_name, f.full_name) AS full_name,
                   COALESCE(s.student_id_code, f.faculty_id_code) AS id_code,
                   COALESCE(s.department, f.department) AS department
            FROM users u
            LEFT JOIN students s ON s.user_id = u.id
            LEFT JOIN faculty f ON f.user_id = u.id
            ORDER BY u.id ASC
        """).fetchall()
        conn.close()

        return render_template("admin/users.html", users=users, departments=ALLOWED_DEPARTMENTS)

    @app.route("/admin/create-user", methods=["POST"])
    @roles_required("admin")
    def admin_create_user():
        submitted_token = request.form.get("csrf_token")
        if not validate_csrf_token(submitted_token):
            flash("Invalid CSRF token.", "danger")
            return redirect(url_for("admin_users"))

        username = request.form.get("username", "").strip()
        raw_password = request.form.get("password", "").strip()
        role = request.form.get("role", "").strip()
        full_name = request.form.get("full_name", "").strip()
        id_code = request.form.get("id_code", "").strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "555-0199").strip()
        department = request.form.get("department", "").strip()
        semester_raw = request.form.get("semester", "1")

        if role not in ["student", "faculty"]:
            flash("Invalid role selected.", "danger")
            return redirect(url_for("admin_users"))

        if not username or len(username) < 3 or not raw_password or len(raw_password) < 6:
            flash("Username must be at least 3 chars and password at least 6 chars.", "danger")
            return redirect(url_for("admin_users"))

        if not validate_email(email):
            flash("Invalid email format.", "danger")
            return redirect(url_for("admin_users"))

        conn = get_db_connection(app.config["DATABASE_PATH"])

        # Check unique username
        existing_user = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if existing_user:
            conn.close()
            flash(f"Username '{username}' already exists.", "danger")
            return redirect(url_for("admin_users"))

        now_iso = datetime.now(timezone.utc).isoformat()
        pw_hash = hash_password(raw_password)

        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO users (username, password_hash, role, is_active, created_at)
            VALUES (?, ?, ?, 1, ?)
        """, (username, pw_hash, role, now_iso))
        new_user_id = cursor.lastrowid

        if role == "student":
            valid_sem, sem_val = validate_semester(semester_raw)
            cursor.execute("""
                INSERT INTO students (user_id, student_id_code, full_name, email, phone, department, semester)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (new_user_id, id_code, full_name, email, phone, department, sem_val if valid_sem else 1))
        elif role == "faculty":
            cursor.execute("""
                INSERT INTO faculty (user_id, faculty_id_code, full_name, email, phone, department)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (new_user_id, id_code, full_name, email, phone, department))

        conn.commit()

        log_audit_event(
            "USER_CREATED",
            session.get("username"),
            "SUCCESS",
            f"Admin created new {role} user '{username}' (ID Code: {id_code}).",
            user_id=session.get("user_id")
        )

        conn.close()
        flash(f"Successfully provisioned synthetic {role} account '{username}'.", "success")
        return redirect(url_for("admin_users"))

    @app.route("/admin/toggle-user-status", methods=["POST"])
    @roles_required("admin")
    def admin_toggle_user_status():
        submitted_token = request.form.get("csrf_token")
        if not validate_csrf_token(submitted_token):
            flash("Invalid CSRF token.", "danger")
            return redirect(url_for("admin_users"))

        target_user_id = request.form.get("user_id")
        current_admin_id = session.get("user_id")

        if str(target_user_id) == str(current_admin_id):
            flash("Defensive guard: You cannot deactivate your own administrative account.", "warning")
            return redirect(url_for("admin_users"))

        conn = get_db_connection(app.config["DATABASE_PATH"])
        target_user = conn.execute("SELECT * FROM users WHERE id = ?", (target_user_id,)).fetchone()

        if not target_user:
            conn.close()
            flash("User not found.", "danger")
            return redirect(url_for("admin_users"))

        new_status = 0 if target_user["is_active"] == 1 else 1
        conn.execute("UPDATE users SET is_active = ? WHERE id = ?", (new_status, target_user_id))
        conn.commit()

        status_label = "Activated" if new_status == 1 else "Deactivated"
        log_audit_event(
            "USER_STATUS_TOGGLED",
            session.get("username"),
            "SUCCESS",
            f"Admin set account status of '{target_user['username']}' (ID {target_user_id}) to {status_label}.",
            user_id=current_admin_id
        )

        conn.close()
        flash(f"Account '{target_user['username']}' has been {status_label}.", "info")
        return redirect(url_for("admin_users"))

    @app.route("/admin/audit")
    @roles_required("admin")
    def admin_audit():
        event_type_filter = request.args.get("event_type", "").strip()
        status_filter = request.args.get("status", "").strip()

        conn = get_db_connection(app.config["DATABASE_PATH"])

        # Fetch distinct event types for filter dropdown
        event_types = [
            row[0] for row in conn.execute(
                "SELECT DISTINCT event_type FROM audit_logs ORDER BY event_type ASC"
            ).fetchall()
        ]

        # Dynamic parameterized query based on filters
        query = "SELECT * FROM audit_logs WHERE 1=1"
        params = []

        if event_type_filter:
            query += " AND event_type = ?"
            params.append(event_type_filter)
        if status_filter:
            query += " AND status = ?"
            params.append(status_filter)

        query += " ORDER BY timestamp DESC LIMIT 200"

        logs = conn.execute(query, params).fetchall()
        conn.close()

        return render_template(
            "admin/audit.html",
            logs=logs,
            event_types=event_types,
            selected_type=event_type_filter,
            selected_status=status_filter
        )

    return app

if __name__ == "__main__":
    app = create_app()
    print("==================================================================")
    print(" ⚠️  CAMPUSPORTAL - LOCAL DEFENSIVE CYBERSECURITY LAB")
    print(f" Strict Localhost Binding: http://{Config.HOST}:{Config.PORT}")
    print(" No external network connections. Synthetic demo data only.")
    print("==================================================================")
    app.run(host=Config.HOST, port=Config.PORT, debug=Config.DEBUG)
