"""
CampusPortal - Database Initialization and Connection Management
Authorized Local Defensive Lab - SQLite with Parameterized Queries.
"""

import sqlite3
import datetime
from werkzeug.security import generate_password_hash
from config import Config

def get_db_connection(db_path=None):
    """
    Returns a connection to the SQLite database with row factory enabled
    for dictionary-style access.
    """
    if db_path is None:
        try:
            from flask import current_app
            if current_app and current_app.config.get("DATABASE_PATH"):
                db_path = current_app.config["DATABASE_PATH"]
        except (RuntimeError, ImportError):
            pass
    path = db_path or Config.DATABASE_PATH
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db(db_path=None):
    """
    Initializes database tables and seeds synthetic demo data if tables are empty.
    """
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    # 1. users
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('student', 'faculty', 'admin')),
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            last_login TEXT
        )
    """)

    # 2. students
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE NOT NULL,
            student_id_code TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT NOT NULL,
            department TEXT NOT NULL,
            semester INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    # 3. faculty
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS faculty (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE NOT NULL,
            faculty_id_code TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT NOT NULL,
            department TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    # 4. courses
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS courses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            course_code TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL,
            department TEXT NOT NULL,
            credits INTEGER NOT NULL,
            faculty_id INTEGER,
            FOREIGN KEY (faculty_id) REFERENCES faculty(id) ON DELETE SET NULL
        )
    """)

    # 5. enrollments
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS enrollments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            course_id INTEGER NOT NULL,
            enrollment_date TEXT NOT NULL,
            UNIQUE(student_id, course_id),
            FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE,
            FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE
        )
    """)

    # 6. grades
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS grades (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            enrollment_id INTEGER UNIQUE NOT NULL,
            midterm_score REAL DEFAULT 0.0,
            final_score REAL DEFAULT 0.0,
            total_score REAL DEFAULT 0.0,
            letter_grade TEXT DEFAULT 'N/A',
            updated_by_faculty_id INTEGER,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (enrollment_id) REFERENCES enrollments(id) ON DELETE CASCADE,
            FOREIGN KEY (updated_by_faculty_id) REFERENCES faculty(id) ON DELETE SET NULL
        )
    """)

    # 7. attendance
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            enrollment_id INTEGER UNIQUE NOT NULL,
            total_classes INTEGER DEFAULT 0,
            attended_classes INTEGER DEFAULT 0,
            percentage REAL DEFAULT 0.0,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (enrollment_id) REFERENCES enrollments(id) ON DELETE CASCADE
        )
    """)

    # 8. announcements
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS announcements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            author_role TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    # 9. audit_logs
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            user_id INTEGER,
            username TEXT,
            ip_address TEXT NOT NULL,
            status TEXT NOT NULL,
            details TEXT NOT NULL
        )
    """)

    conn.commit()

    # Seed data check
    cursor.execute("SELECT COUNT(*) FROM users")
    user_count = cursor.fetchone()[0]

    if user_count == 0:
        seed_data(conn)

    conn.close()

def compute_letter_grade(total_score):
    """Calculate letter grade from numerical score 0-100."""
    if total_score >= 90:
        return 'A+'
    elif total_score >= 80:
        return 'A'
    elif total_score >= 70:
        return 'B'
    elif total_score >= 60:
        return 'C'
    elif total_score >= 50:
        return 'D'
    else:
        return 'F'

def seed_data(conn):
    """Seeds synthetic demo accounts and records for defensive modeling."""
    cursor = conn.cursor()
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Synthetic demo accounts
    demo_users = [
        # (username, password, role)
        ("admin_user", "AdminPass123!", "admin"),
        ("prof_smith", "FacultyPass123!", "faculty"),
        ("prof_chen", "FacultyPass123!", "faculty"),
        ("alice_student", "StudentPass123!", "student"),
        ("bob_student", "StudentPass123!", "student"),
    ]

    user_ids = {}
    for username, raw_password, role in demo_users:
        pw_hash = generate_password_hash(raw_password)
        cursor.execute(
            """INSERT INTO users (username, password_hash, role, is_active, created_at)
               VALUES (?, ?, ?, 1, ?)""",
            (username, pw_hash, role, now_iso)
        )
        user_ids[username] = cursor.lastrowid

    # Seed Faculty
    cursor.execute(
        """INSERT INTO faculty (user_id, faculty_id_code, full_name, email, phone, department)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (user_ids["prof_smith"], "FAC-2021-010", "Prof. Arthur Smith", "a.smith@campus.local", "555-0201", "Computer Science")
    )
    fac_smith_id = cursor.lastrowid

    cursor.execute(
        """INSERT INTO faculty (user_id, faculty_id_code, full_name, email, phone, department)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (user_ids["prof_chen"], "FAC-2022-015", "Dr. Maya Chen", "m.chen@campus.local", "555-0202", "Cybersecurity")
    )
    fac_chen_id = cursor.lastrowid

    # Seed Students
    cursor.execute(
        """INSERT INTO students (user_id, student_id_code, full_name, email, phone, department, semester)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (user_ids["alice_student"], "STU-2024-001", "Alice Vance", "alice.vance@campus.local", "555-0101", "Computer Science", 4)
    )
    stu_alice_id = cursor.lastrowid

    cursor.execute(
        """INSERT INTO students (user_id, student_id_code, full_name, email, phone, department, semester)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (user_ids["bob_student"], "STU-2024-002", "Bob Martinez", "bob.martinez@campus.local", "555-0102", "Cybersecurity", 3)
    )
    stu_bob_id = cursor.lastrowid

    # Seed Courses
    courses = [
        ("CS101", "Intro to Secure Programming", "Computer Science", 4, fac_smith_id),
        ("SEC201", "Network & System Defense", "Cybersecurity", 3, fac_chen_id),
        ("CS305", "Database Systems & Architecture", "Computer Science", 3, fac_smith_id),
    ]
    course_ids = {}
    for code, title, dept, credits_val, fac_id in courses:
        cursor.execute(
            """INSERT INTO courses (course_code, title, department, credits, faculty_id)
               VALUES (?, ?, ?, ?, ?)""",
            (code, title, dept, credits_val, fac_id)
        )
        course_ids[code] = cursor.lastrowid

    # Seed Enrollments
    enrollments_data = [
        (stu_alice_id, course_ids["CS101"], "2024-08-20"),
        (stu_alice_id, course_ids["SEC201"], "2024-08-20"),
        (stu_alice_id, course_ids["CS305"], "2024-08-21"),
        (stu_bob_id, course_ids["CS101"], "2024-08-22"),
        (stu_bob_id, course_ids["SEC201"], "2024-08-22"),
    ]

    enrollment_ids = []
    for s_id, c_id, date_val in enrollments_data:
        cursor.execute(
            """INSERT INTO enrollments (student_id, course_id, enrollment_date)
               VALUES (?, ?, ?)""",
            (s_id, c_id, date_val)
        )
        enrollment_ids.append((cursor.lastrowid, s_id, c_id))

    # Seed Grades & Attendance
    # 0: Alice CS101, 1: Alice SEC201, 2: Alice CS305, 3: Bob CS101, 4: Bob SEC201
    grades_seed = [
        (enrollment_ids[0][0], 42.0, 46.0, fac_smith_id),  # Alice CS101 (88.0 -> A)
        (enrollment_ids[1][0], 45.0, 47.0, fac_chen_id),   # Alice SEC201 (92.0 -> A+)
        (enrollment_ids[2][0], 38.0, 41.0, fac_smith_id),  # Alice CS305 (79.0 -> B)
        (enrollment_ids[3][0], 35.0, 39.0, fac_smith_id),  # Bob CS101 (74.0 -> B)
        (enrollment_ids[4][0], 40.0, 44.0, fac_chen_id),   # Bob SEC201 (84.0 -> A)
    ]

    for enr_id, mid, fin, f_id in grades_seed:
        tot = mid + fin
        letter = compute_letter_grade(tot)
        cursor.execute(
            """INSERT INTO grades (enrollment_id, midterm_score, final_score, total_score, letter_grade, updated_by_faculty_id, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (enr_id, mid, fin, tot, letter, f_id, now_iso)
        )

    attendance_seed = [
        (enrollment_ids[0][0], 30, 28, 93.3),  # Alice CS101
        (enrollment_ids[1][0], 25, 25, 100.0), # Alice SEC201
        (enrollment_ids[2][0], 28, 26, 92.9),  # Alice CS305
        (enrollment_ids[3][0], 30, 25, 83.3),  # Bob CS101
        (enrollment_ids[4][0], 25, 23, 92.0),  # Bob SEC201
    ]

    for enr_id, tot_cls, att_cls, pct in attendance_seed:
        cursor.execute(
            """INSERT INTO attendance (enrollment_id, total_classes, attended_classes, percentage, updated_at)
               VALUES (?, ?, ?, ?, ?)""",
            (enr_id, tot_cls, att_cls, pct, now_iso)
        )

    # Seed Announcements
    announcements = [
        ("Midterm Threat-Modeling Workshop", "Hands-on threat-modeling session on STRIDE methodology scheduled for Friday in Lab 3.", "Faculty", "2026-09-28 09:30:00"),
        ("Campus System Maintenance Window", "Routine database index maintenance scheduled for Sunday at 02:00 UTC. Zero downtime expected.", "Administrator", "2026-09-30 14:00:00"),
        ("Cybersecurity Defense Challenge", "Students interested in defensive security challenges and CTFs please meet Prof. Chen in Room 402.", "Faculty", "2026-10-01 11:15:00"),
    ]

    for title, content, author_role, created_at in announcements:
        cursor.execute(
            """INSERT INTO announcements (title, content, author_role, created_at)
               VALUES (?, ?, ?, ?)""",
            (title, content, author_role, created_at)
        )

    # Seed initial audit log event
    cursor.execute(
        """INSERT INTO audit_logs (timestamp, event_type, user_id, username, ip_address, status, details)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (now_iso, "SYSTEM_INIT", user_ids["admin_user"], "admin_user", "127.0.0.1", "SUCCESS", "Database seeded with synthetic demo records.")
    )

    conn.commit()

if __name__ == "__main__":
    init_db()
    print("Database initialized successfully at", Config.DATABASE_PATH)
