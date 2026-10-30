import os
import sqlite3
import uuid
import secrets
from functools import wraps

from flask import (
    Flask, render_template, request,
    redirect, url_for, session
)
from werkzeug.utils import secure_filename
from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)


# Project paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_FOLDER = os.path.join(BASE_DIR, "templates")
STATIC_FOLDER = os.path.join(BASE_DIR, "static")
DATABASE_PATH = os.path.join(BASE_DIR, "reports.db")

app = Flask(
    __name__,
    template_folder=TEMPLATE_FOLDER,
    static_folder=STATIC_FOLDER
)

# Session security
app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "change-this-demo-secret-key"
)

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Demo admin login
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "Admin@123"

UPLOAD_FOLDER = os.path.join(STATIC_FOLDER, "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# Database connection
def get_db():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# Admin login required
def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("is_admin"):
            return redirect(url_for("admin_login"))
        return view(*args, **kwargs)

    return wrapped


# Database setup
def init_db():
    conn = get_db()

    # Complaints table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT NOT NULL,
            location TEXT NOT NULL,
            photo TEXT,
            status TEXT DEFAULT 'Pending',
            user_id INTEGER
        )
    """)

    # Existing database compatibility
    columns = [
        row["name"]
        for row in conn.execute(
            "PRAGMA table_info(reports)"
        ).fetchall()
    ]

    if "photo" not in columns:
        conn.execute(
            "ALTER TABLE reports ADD COLUMN photo TEXT"
        )

    if "status" not in columns:
        conn.execute("""
            ALTER TABLE reports
            ADD COLUMN status TEXT DEFAULT 'Pending'
        """)

    if "user_id" not in columns:
        conn.execute("""
            ALTER TABLE reports
            ADD COLUMN user_id INTEGER
        """)

    # User registration table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            mobile TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()


# Check image extension
def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower()
        in ALLOWED_EXTENSIONS
    )


# Home page
@app.route("/")
def home():
    return render_template("index.html")


# User Registration
@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        full_name = request.form.get(
            "full_name", ""
        ).strip()

        mobile = request.form.get(
            "mobile", ""
        ).strip()

        email = request.form.get(
            "email", ""
        ).strip().lower()

        username = request.form.get(
            "username", ""
        ).strip().lower()

        password = request.form.get("password", "")

        confirm_password = request.form.get(
            "confirm_password", ""
        )

        terms = request.form.get("terms")

        # Required fields
        if not all([
            full_name, mobile, email,
            username, password
        ]):
            return render_template(
                "register.html",
                error="Please fill in all required fields."
            )

        # Mobile validation
        if not mobile.isdigit() or len(mobile) != 10:
            return render_template(
                "register.html",
                error="Enter a valid 10-digit mobile number."
            )

        # Basic email validation
        if (
            "@" not in email
            or "." not in email.split("@")[-1]
        ):
            return render_template(
                "register.html",
                error="Enter a valid email address."
            )

        # Username validation
        if (
            len(username) < 3
            or not all(
                char.isalnum() or char == "_"
                for char in username
            )
        ):
            return render_template(
                "register.html",
                error=(
                    "Username must have at least 3 characters. "
                    "Use letters, numbers or underscores."
                )
            )

        # Password validation
        if len(password) < 8:
            return render_template(
                "register.html",
                error="Password must contain at least 8 characters."
            )

        if password != confirm_password:
            return render_template(
                "register.html",
                error="Passwords do not match."
            )

        if terms != "accepted":
            return render_template(
                "register.html",
                error="Please accept the terms and conditions."
            )

        # Save user
        conn = get_db()

        try:
            conn.execute("""
                INSERT INTO users (
                    full_name,
                    mobile,
                    email,
                    username,
                    password
                )
                VALUES (?, ?, ?, ?, ?)
            """, (
                full_name,
                mobile,
                email,
                username,
                generate_password_hash(password)
            ))

            conn.commit()

        except sqlite3.IntegrityError:
            conn.close()

            return render_template(
                "register.html",
                error=(
                    "Mobile number, email or username "
                    "is already registered."
                )
            )

        conn.close()

        return redirect(
            url_for("user_login", registered="1")
        )

    return render_template("register.html")


# User Login
@app.route("/user-login", methods=["GET", "POST"])
def user_login():

    if session.get("user_id"):
        return redirect(url_for("report"))

    if request.method == "POST":

        username = request.form.get(
            "username", ""
        ).strip().lower()

        password = request.form.get("password", "")

        conn = get_db()

        user = conn.execute("""
            SELECT id, full_name, username, password
            FROM users
            WHERE username = ?
        """, (username,)).fetchone()

        conn.close()

        if (
            user
            and check_password_hash(
                user["password"], password
            )
        ):
            session.clear()

            session["user_id"] = user["id"]
            session["user_name"] = user["full_name"]

            return redirect(url_for("report"))

        return render_template(
            "user_login.html",
            error="Invalid username or password."
        )

    return render_template(
        "user_login.html",
        registered=request.args.get("registered")
    )


# User Logout
@app.route("/user-logout", methods=["POST"])
def user_logout():

    session.pop("user_id", None)
    session.pop("user_name", None)

    return redirect(url_for("home"))


# Report form page - login required
@app.route("/report")
def report():

    if not session.get("user_id"):
        return redirect(url_for("user_login"))

    return render_template("report.html")


# Submit a new report - login required
@app.route("/submit", methods=["POST"])
def submit():

    if not session.get("user_id"):
        return redirect(url_for("user_login"))

    title = request.form.get("title", "").strip()
    category = request.form.get("category", "").strip()
    location = request.form.get("location", "").strip()

    description = request.form.get(
        "description", ""
    ).strip()

    if not all([
        title, category, location, description
    ]):
        return "Please fill in all required fields.", 400

    photo_path = None
    photo = request.files.get("photo")

    if photo and photo.filename:

        if not allowed_file(photo.filename):
            return (
                "Please upload a JPG, PNG or WEBP image.",
                400
            )

        original_name = secure_filename(photo.filename)

        if "." not in original_name:
            return "Invalid image filename.", 400

        extension = original_name.rsplit(".", 1)[1].lower()
        new_name = f"{uuid.uuid4().hex}.{extension}"

        photo.save(
            os.path.join(
                app.config["UPLOAD_FOLDER"],
                new_name
            )
        )

        photo_path = f"uploads/{new_name}"

    conn = get_db()

    cursor = conn.execute("""
        INSERT INTO reports (
            title,
            category,
            description,
            location,
            photo,
            user_id
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        title,
        category,
        description,
        location,
        photo_path,
        session["user_id"]
    ))

    conn.commit()
    complaint_id = cursor.lastrowid
    conn.close()

    return redirect(
        url_for(
            "status_result",
            complaint_id=complaint_id
        )
    )


# Status check page
@app.route("/status")
def status_page():
    return render_template("status.html")


# Check complaint status
@app.route("/check-status", methods=["POST"])
def check_status():

    complaint_id = request.form.get(
        "complaint_id", ""
    ).strip()

    if (
        not complaint_id.isdigit()
        or int(complaint_id) < 1
    ):
        return render_template(
            "status_result.html",
            report=None,
            error="Please enter a valid Complaint ID."
        )

    return redirect(
        url_for(
            "status_result",
            complaint_id=int(complaint_id)
        )
    )


# Display complaint status
@app.route("/status-result/<int:complaint_id>")
def status_result(complaint_id):

    conn = get_db()

    report = conn.execute("""
        SELECT id, title, category, location, status
        FROM reports
        WHERE id = ?
    """, (complaint_id,)).fetchone()

    conn.close()

    if report is None:
        return render_template(
            "status_result.html",
            report=None,
            error=(
                "No complaint found with this ID. "
                "Please check your Complaint ID."
            )
        )

    return render_template(
        "status_result.html",
        report=report,
        error=None
    )


# View all public reports
@app.route("/reports")
def reports():

    conn = get_db()

    all_reports = conn.execute("""
        SELECT *
        FROM reports
        ORDER BY id DESC
    """).fetchall()

    conn.close()

    return render_template(
        "reports.html",
        reports=all_reports
    )


# Admin login page
@app.route("/admin-login", methods=["GET", "POST"])
def admin_login():

    if session.get("is_admin"):
        return redirect(url_for("admin"))

    if request.method == "POST":

        username = request.form.get("username", "")
        password = request.form.get("password", "")

        if (
            secrets.compare_digest(
                username, ADMIN_USERNAME
            )
            and secrets.compare_digest(
                password, ADMIN_PASSWORD
            )
        ):
            session.clear()
            session.permanent = False
            session["is_admin"] = True

            return redirect(url_for("admin"))

        return render_template(
            "admin_login.html",
            error="Invalid username or password."
        )

    return render_template("admin_login.html")


# Admin dashboard - login required
@app.route("/admin")
@admin_required
def admin():

    conn = get_db()

    # Get complaint details and the reporting user's information
    all_reports = conn.execute("""
        SELECT
            reports.*,
            users.full_name AS reporter_name,
            users.mobile AS reporter_mobile
        FROM reports
        LEFT JOIN users
            ON reports.user_id = users.id
        ORDER BY reports.id DESC
    """).fetchall()

    conn.close()

    return render_template(
        "admin.html",
        reports=all_reports
    )


# Update report status
@app.route(
    "/update_status/<int:report_id>",
    methods=["POST"]
)
@admin_required
def update_status(report_id):

    status = request.form.get("status", "")

    allowed_statuses = [
        "Pending",
        "In Progress",
        "Resolved"
    ]

    if status not in allowed_statuses:
        return "Invalid status.", 400

    conn = get_db()

    cursor = conn.execute(
        "UPDATE reports SET status = ? WHERE id = ?",
        (status, report_id)
    )

    conn.commit()
    updated = cursor.rowcount
    conn.close()

    if updated == 0:
        return "Report not found.", 404

    return redirect(url_for("admin"))


# Delete report
@app.route(
    "/delete_report/<int:report_id>",
    methods=["POST"]
)
@admin_required
def delete_report(report_id):

    conn = get_db()

    report_to_delete = conn.execute(
        "SELECT photo FROM reports WHERE id = ?",
        (report_id,)
    ).fetchone()

    if report_to_delete is None:
        conn.close()
        return "Report not found.", 404

    photo_path = report_to_delete["photo"]

    conn.execute(
        "DELETE FROM reports WHERE id = ?",
        (report_id,)
    )

    conn.commit()
    conn.close()

    if photo_path:
        full_photo_path = os.path.join(
            app.config["UPLOAD_FOLDER"],
            os.path.basename(photo_path)
        )

        if os.path.isfile(full_photo_path):
            try:
                os.remove(full_photo_path)
            except OSError:
                pass

    return redirect(url_for("admin"))


# Admin logout
@app.route("/admin-logout", methods=["POST"])
@admin_required
def admin_logout():

    session.clear()

    return redirect(url_for("admin_login"))


# Run application
if __name__ == "__main__":
    init_db()
    app.run(debug=True)