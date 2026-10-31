import csv
import io
import hmac
import os
import secrets
import sqlite3
import logging
from pathlib import Path
from datetime import datetime
from functools import wraps
from typing import Any

from flask import (  # type: ignore[reportMissingImports]
    Flask, abort, render_template, request, redirect,
    url_for, flash, session, send_file
)
from werkzeug.security import generate_password_hash, check_password_hash  # type: ignore[reportMissingImports]
from werkzeug.utils import secure_filename  # type: ignore[reportMissingImports]
from pypdf import PdfReader  # type: ignore[reportMissingImports]
from io import BytesIO
from reportlab.lib import colors  # type: ignore[reportMissingModuleSource]
from reportlab.lib.enums import TA_CENTER  # type: ignore[reportMissingModuleSource]
from reportlab.lib.pagesizes import A4  # type: ignore[reportMissingModuleSource]
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle  # type: ignore[reportMissingModuleSource]
from reportlab.lib.units import mm  # type: ignore[reportMissingModuleSource]
from reportlab.platypus import (  # type: ignore[reportMissingModuleSource]
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)


# ==========================================
# 1. APP CONFIGURATION
# ==========================================

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "career_copilot.db"
UPLOAD_FOLDER = BASE_DIR / "uploads"
STATIC_FOLDER = BASE_DIR / "static"

UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)

app = Flask(
    __name__,
    static_folder=str(STATIC_FOLDER),
    static_url_path="/static"
)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "career-copilot-local-key-2026-stable"
)

app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024
app.config["UPLOAD_FOLDER"] = str(UPLOAD_FOLDER)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False
app.config["PERMANENT_SESSION_LIFETIME"] = 3600

def generate_csrf():
    token = session.get("csrf_token")
    if token is None:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


@app.before_request
def validate_csrf_token():
    if request.method in {"GET", "HEAD", "OPTIONS", "TRACE"}:
        return

    submitted_token = (
        request.form.get("csrf_token")
        or request.headers.get("X-CSRFToken")
        or request.headers.get("X-CSRF-Token")
    )
    expected_token = session.get("csrf_token", "")

    if not submitted_token or not expected_token or not hmac.compare_digest(
        submitted_token, expected_token
    ):
        abort(400, description="The CSRF token is missing or invalid.")


@app.context_processor
def inject_csrf_token():
    return {"csrf_token": generate_csrf}



logging.basicConfig(level=logging.INFO)


# ==========================================
# 2. DATABASE
# ==========================================

def get_db_connection():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_db_connection()

    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                match_score INTEGER DEFAULT 0,
                matched_skills TEXT DEFAULT '',
                missing_skills TEXT DEFAULT '',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.commit()
    finally:
        conn.close()


init_db()


# ==========================================
# 3. RESUME ANALYSIS
# ==========================================

SKILLS = [
    "python", "java", "javascript", "html", "css",
    "flask", "django", "sql", "sqlite", "mysql",
    "machine learning", "deep learning", "data analysis",
    "pandas", "numpy", "power bi", "excel", "react",
    "node.js", "git", "github", "api", "communication",
    "problem solving", "teamwork", "c++", "oop", "aws"
]


def extract_resume_text(file_path):
    reader = PdfReader(str(file_path))

    if reader.is_encrypted:
        raise ValueError(
            "Password-protected PDFs are not supported."
        )

    if len(reader.pages) > 30:
        raise ValueError(
            "Please upload a PDF with 30 pages or fewer."
        )

    text = "\n".join(
        page.extract_text() or ""
        for page in reader.pages
    ).strip()

    if not text:
        raise ValueError(
            "No readable text found. Please upload a text-based PDF."
        )

    return text


def analyze_resume(resume_text, job_description=""):
    resume_lower = resume_text.lower()
    job_lower = job_description.lower()

    if job_lower:
        relevant_skills = [
            skill for skill in SKILLS
            if skill in job_lower
        ]
    else:
        relevant_skills = SKILLS

    matched_skills = [
        skill for skill in relevant_skills
        if skill in resume_lower
    ]

    missing_skills = [
        skill for skill in relevant_skills
        if skill not in resume_lower
    ]

    score = (
        round(len(matched_skills) / len(relevant_skills) * 100)
        if relevant_skills else 0
    )

    return {
        "match_score": score,
        "matched_skills": matched_skills,
        "missing_skills": missing_skills,
        "interview_questions": [
            "Tell me about yourself.",
            "Explain one project you have completed.",
            "What technical skills are your strongest?",
            "How do you debug a programming problem?",
            "What are your career goals?"
        ]
    }


# ==========================================
# PDF REPORT GENERATOR
# ==========================================

def create_analysis_pdf(result):
    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm
    )

    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="ReportTitle",
        parent=styles["Title"],
        fontSize=22,
        leading=28,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#6550EE"),
        spaceAfter=8
    ))

    styles.add(ParagraphStyle(
        name="SectionHeading",
        parent=styles["Heading2"],
        textColor=colors.HexColor("#4338CA"),
        spaceBefore=12,
        spaceAfter=6
    ))

    story = []

    story.append(Paragraph(
        "AI Career Copilot",
        styles["ReportTitle"]
    ))

    story.append(Paragraph(
        "Resume Analysis Report",
        styles["Heading2"]
    ))

    story.append(Spacer(1, 12))

    story.append(Paragraph(
        f"<b>Report Date:</b> "
        f"{datetime.now().strftime('%d %B %Y, %I:%M %p')}",
        styles["Normal"]
    ))

    story.append(Spacer(1, 12))

    score = int(result.get("match_score", 0))

    score_table = Table(
        [
            ["Resume Match Score"],
            [f"{score}%"]
        ],
        colWidths=[160 * mm]
    )

    score_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#5946D8")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#F1EFFF")),
        ("TEXTCOLOR", (0, 1), (-1, 1), colors.HexColor("#312E81")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTSIZE", (0, 0), (-1, 0), 12),
        ("FONTSIZE", (0, 1), (-1, 1), 24),
        ("TOPPADDING", (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#D8D3FF")),
    ]))

    story.append(score_table)

    matched = result.get("matched_skills", [])
    missing = result.get("missing_skills", [])
    questions = result.get("interview_questions", [])

    story.append(Paragraph(
        "Matched Skills",
        styles["SectionHeading"]
    ))

    if matched:
        for skill in matched:
            story.append(Paragraph(
                f"&#8226; {skill}",
                styles["Normal"]
            ))
    else:
        story.append(Paragraph(
            "No matching skills identified.",
            styles["Normal"]
        ))

    story.append(Paragraph(
        "Skills to Improve",
        styles["SectionHeading"]
    ))

    if missing:
        for skill in missing:
            story.append(Paragraph(
                f"&#8226; {skill}",
                styles["Normal"]
            ))
    else:
        story.append(Paragraph(
            "No missing skills identified.",
            styles["Normal"]
        ))

    story.append(Paragraph(
        "Interview Preparation Questions",
        styles["SectionHeading"]
    ))

    if questions:
        for number, question in enumerate(questions, start=1):
            story.append(Paragraph(
                f"{number}. {question}",
                styles["Normal"]
            ))
            story.append(Spacer(1, 4))
    else:
        story.append(Paragraph(
            "No interview questions available.",
            styles["Normal"]
        ))

    story.append(Spacer(1, 18))

    story.append(Paragraph(
        "Note: This report provides a basic keyword-based resume analysis. "
        "It is intended as guidance, not a guarantee of job suitability.",
        styles["Italic"]
    ))

    document.build(story)

    buffer.seek(0)
    return buffer


# ==========================================
# 4. ADMIN LOGIN PROTECTION
# ==========================================

def admin_required(view_function):
    @wraps(view_function)
    def wrapped_view(*args, **kwargs):
        if not session.get("admin_id"):
            app.logger.warning(
                "Admin page requested without a valid login session."
            )
            flash(
                "Please log in as an administrator.",
                "error"
            )
            return redirect(url_for("login"))

        return view_function(*args, **kwargs)

    return wrapped_view


# ==========================================
# 5. HOME PAGE AND RESUME UPLOAD
# ==========================================

@app.route("/", methods=["GET", "POST"])
def index():
    result = None

    if request.method == "POST":
        uploaded_file = (
            request.files.get("resume")
            or request.files.get("file")
        )

        job_description = request.form.get(
            "job_description", ""
        ).strip()

        if not uploaded_file or not uploaded_file.filename:
            flash("Please select a resume PDF.", "error")
            return render_template("index.html", result=None)

        if Path(uploaded_file.filename).suffix.lower() != ".pdf":
            flash("Only PDF files are supported.", "error")
            return render_template("index.html", result=None)

        safe_name = secure_filename(uploaded_file.filename)

        if not safe_name:
            flash("Invalid filename.", "error")
            return render_template("index.html", result=None)

        unique_name = (
            datetime.now().strftime("%Y%m%d%H%M%S%f")
            + "_"
            + safe_name
        )

        file_path = UPLOAD_FOLDER / unique_name

        try:
            uploaded_file.save(file_path)
            resume_text = extract_resume_text(file_path)

            result = analyze_resume(
                resume_text,
                job_description
            )

            conn = get_db_connection()

            try:
                conn.execute("""
                    INSERT INTO analyses (
                        filename,
                        match_score,
                        matched_skills,
                        missing_skills
                    )
                    VALUES (?, ?, ?, ?)
                """, (
                    safe_name,
                    result["match_score"],
                    ", ".join(result["matched_skills"]),
                    ", ".join(result["missing_skills"])
                ))

                conn.commit()
            finally:
                conn.close()

        except Exception:
            app.logger.exception("Resume analysis failed")
            flash(
                "Resume analysis failed. Check the PDF and try again.",
                "error"
            )

        finally:
            if file_path.exists():
                try:
                    file_path.unlink()
                except OSError:
                    app.logger.warning(
                        "Could not remove temporary upload."
                    )

    return render_template("index.html", result=result)


# ==========================================
# DOWNLOAD ANALYSIS REPORT
# ==========================================

@app.route("/download-report", methods=["POST"])
def download_report():
    score = request.form.get("match_score", type=int)

    if score is None or not 0 <= score <= 100:
        flash(
            "Invalid analysis result. Please analyze your resume again.",
            "error"
        )
        return redirect(url_for("index"))

    matched_skills = [
        skill.strip()
        for skill in request.form.getlist("matched_skills")
        if skill.strip()
    ]

    missing_skills = [
        skill.strip()
        for skill in request.form.getlist("missing_skills")
        if skill.strip()
    ]

    interview_questions = [
        question.strip()
        for question in request.form.getlist("interview_questions")
        if question.strip()
    ]

    result = {
        "match_score": score,
        "matched_skills": matched_skills,
        "missing_skills": missing_skills,
        "interview_questions": interview_questions
    }

    pdf_buffer = create_analysis_pdf(result)

    response = send_file(
        pdf_buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name="AI_Career_Copilot_Report.pdf"
    )

    response.headers["Cache-Control"] = "no-store"
    return response
# ==========================================
# 6. CREATE ADMIN ACCOUNT
# ==========================================

@app.route("/setup-admin", methods=["GET", "POST"])
def setup_admin():
    conn = get_db_connection()

    try:
        admin_exists = conn.execute(
            "SELECT id FROM admins LIMIT 1"
        ).fetchone()
    finally:
        conn.close()

    if admin_exists:
        flash(
            "An administrator account already exists.",
            "info"
        )
        return redirect(url_for("login"))

    if request.method == "POST":
        username = request.form.get(
            "username", ""
        ).strip()

        password = request.form.get("password", "")

        confirm_password = request.form.get(
            "confirm_password", ""
        )

        if not username or not password:
            flash(
                "Username and password are required.",
                "error"
            )
            return render_template("add_admin.html")

        if len(username) < 3:
            flash(
                "Username must contain at least 3 characters.",
                "error"
            )
            return render_template("add_admin.html")

        if len(password) < 8:
            flash(
                "Password must contain at least 8 characters.",
                "error"
            )
            return render_template("add_admin.html")

        if password != confirm_password:
            flash(
                "Passwords do not match.",
                "error"
            )
            return render_template("add_admin.html")

        password_hash = generate_password_hash(password)

        conn = get_db_connection()

        try:
            conn.execute("""
                INSERT INTO admins (username, password_hash)
                VALUES (?, ?)
            """, (username, password_hash))

            conn.commit()

        except sqlite3.IntegrityError:
            flash(
                "This username already exists.",
                "error"
            )
            return render_template("add_admin.html")

        finally:
            conn.close()

        flash(
            "Admin account created successfully. Please log in.",
            "success"
        )

        return redirect(url_for("login"))

    return render_template("add_admin.html")


# ==========================================
# 7. ADMIN LOGIN
# ==========================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("admin_id"):
        return redirect(url_for("admin"))

    if request.method == "POST":
        username = request.form.get(
            "username", ""
        ).strip()

        password = request.form.get("password", "")

        if not username or not password:
            flash(
                "Enter your username and password.",
                "error"
            )
            return render_template("login.html")

        conn = get_db_connection()

        try:
            admin_user = conn.execute("""
                SELECT id, username, password_hash
                FROM admins
                WHERE username = ?
            """, (username,)).fetchone()
        finally:
            conn.close()

        if (
            admin_user
            and check_password_hash(
                admin_user["password_hash"],
                password
            )
        ):
            session.clear()
            session.permanent = True
            session["admin_id"] = admin_user["id"]
            session["admin_username"] = admin_user["username"]

            flash(
                "Login successful.",
                "success"
            )

            return redirect(url_for("admin"))

        flash(
            "Invalid username or password.",
            "error"
        )

    return render_template("login.html")



# ==========================================
# 8. ADMIN DASHBOARD
# ==========================================

@app.route("/admin")
@admin_required
def admin():
    search = request.args.get("search", "").strip()
    min_score = request.args.get("min_score", type=int)
    max_score = request.args.get("max_score", type=int)

    page = max(request.args.get("page", 1, type=int), 1)
    per_page = 10

    conditions = []
    parameters = []

    if search:
        conditions.append("filename LIKE ?")
        parameters.append(f"%{search}%")

    if min_score is not None:
        conditions.append("match_score >= ?")
        parameters.append(min_score)

    if max_score is not None:
        conditions.append("match_score <= ?")
        parameters.append(max_score)

    where_clause = (
        " WHERE " + " AND ".join(conditions)
        if conditions else ""
    )

    conn = get_db_connection()

    try:
        total_analyses = conn.execute(
            "SELECT COUNT(*) AS total FROM analyses"
        ).fetchone()["total"]

        filtered_count = conn.execute(
            "SELECT COUNT(*) AS total FROM analyses" + where_clause,
            parameters
        ).fetchone()["total"]

        average_score = conn.execute(
            "SELECT AVG(match_score) AS average FROM analyses"
        ).fetchone()["average"]

        high_score_count = conn.execute(
            "SELECT COUNT(*) AS total FROM analyses WHERE match_score >= 70"
        ).fetchone()["total"]

        low_score_count = conn.execute(
            "SELECT COUNT(*) AS total FROM analyses WHERE match_score < 40"
        ).fetchone()["total"]

        total_pages = max(
            1, (filtered_count + per_page - 1) // per_page
        )
        page = min(page, total_pages)
        offset = (page - 1) * per_page

        analyses = conn.execute(
            """
            SELECT id, filename, match_score,
                   matched_skills, missing_skills, created_at
            FROM analyses
            """
            + where_clause
            + " ORDER BY id DESC LIMIT ? OFFSET ?",
            parameters + [per_page, offset]
        ).fetchall()

        # Load administrator accounts using the existing table.
        admins = conn.execute(
            "SELECT username FROM admins ORDER BY username"
        ).fetchall()

    finally:
        conn.close()

    return render_template(
        "admin.html",
        analyses=analyses,
        recent_analyses=analyses,
        total_analyses=total_analyses,
        total_donors=total_analyses,
        average_score=round(average_score or 0, 1),
        high_score_count=high_score_count,
        low_score_count=low_score_count,
        admins=admins,
        admin_username=session.get("admin_username", ""),
        search=search,
        min_score=min_score,
        max_score=max_score,
        page=page,
        total_pages=total_pages,
        filtered_count=filtered_count,
        filtered_total=filtered_count
    )

# ==========================================
# 9. ADMIN LOGOUT
# ==========================================

@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()

    flash(
        "You have been logged out.",
        "success"
    )

    return redirect(url_for("login"))
# ============================================================
# ADMIN: VIEW INDIVIDUAL ANALYSIS
# ============================================================

@app.route("/admin/analysis/<int:analysis_id>")
@admin_required
def admin_analysis_detail(analysis_id):
    conn = get_db_connection()

    analysis = conn.execute(
        """
        SELECT id, filename, match_score, matched_skills,
               missing_skills, created_at
        FROM analyses
        WHERE id = ?
        """,
        (analysis_id,)
    ).fetchone()

    conn.close()

    if analysis is None:
        return "Analysis not found", 404

    return render_template(
        "analysis_detail.html",
        analysis=analysis
    )


# ============================================================
# ADMIN: EXPORT ANALYSES TO CSV
# ============================================================

@app.route("/admin/export-csv")
@admin_required
def export_admin_csv():
    conn = get_db_connection()

    analyses = conn.execute(
        """
        SELECT id, filename, match_score, matched_skills,
               missing_skills, created_at
        FROM analyses
        ORDER BY id DESC
        """
    ).fetchall()

    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "ID",
        "Resume Filename",
        "Match Score",
        "Matched Skills",
        "Missing Skills",
        "Created At"
    ])

    for analysis in analyses:
        writer.writerow([
            analysis["id"],
            analysis["filename"],
            analysis["match_score"],
            analysis["matched_skills"],
            analysis["missing_skills"],
            analysis["created_at"]
        ])

    csv_data = output.getvalue()
    output.close()

    return send_file(
        io.BytesIO(csv_data.encode("utf-8-sig")),
        mimetype="text/csv",
        as_attachment=True,
        download_name="career_copilot_analyses.csv"
    )
# ============================================================
# ADMIN: EXPORT ALL ANALYSES TO PDF
# ============================================================

@app.route("/admin/export-pdf")
@admin_required
def export_admin_pdf():
    conn = get_db_connection()

    analyses = conn.execute(
        """
        SELECT id, filename, match_score, matched_skills,
               missing_skills, created_at
        FROM analyses
        ORDER BY id DESC
        """
    ).fetchall()

    conn.close()

    buffer = BytesIO()

    from reportlab.lib import colors  # type: ignore[reportMissingModuleSource]
    from reportlab.lib.pagesizes import A4, landscape  # type: ignore[reportMissingModuleSource]
    from reportlab.lib.styles import getSampleStyleSheet  # type: ignore[reportMissingModuleSource]
    from reportlab.lib.units import mm  # type: ignore[reportMissingModuleSource]
    from reportlab.platypus import (  # type: ignore[reportMissingModuleSource]
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle
    )

    document = SimpleDocTemplate(
        buffer,
        pagesize=landscape(A4),
        rightMargin=12 * mm,
        leftMargin=12 * mm,
        topMargin=12 * mm,
        bottomMargin=12 * mm
    )

    styles = getSampleStyleSheet()
    elements = []

    elements.append(
        Paragraph("AI Career Copilot - Analysis Report", styles["Title"])
    )
    elements.append(Spacer(1, 8 * mm))

    elements.append(
        Paragraph(
            f"Report generated: {datetime.now().strftime('%d-%m-%Y %H:%M')}",
            styles["Normal"]
        )
    )
    elements.append(Spacer(1, 6 * mm))

    table_data = [[
        "ID",
        "Resume",
        "Score",
        "Matched Skills",
        "Missing Skills",
        "Created At"
    ]]

    for analysis in analyses:
        table_data.append([
            str(analysis["id"]),
            Paragraph(
                str(analysis["filename"] or "-"),
                styles["Normal"]
            ),
            f'{analysis["match_score"]}%',
            Paragraph(
                str(analysis["matched_skills"] or "-"),
                styles["Normal"]
            ),
            Paragraph(
                str(analysis["missing_skills"] or "-"),
                styles["Normal"]
            ),
            str(analysis["created_at"] or "-")
        ])

    if len(table_data) == 1:
        table_data.append([
            "-", "No analyses found", "-", "-", "-", "-"
        ])

    table = Table(
        table_data,
        repeatRows=1,
        colWidths=[15 * mm, 42 * mm, 20 * mm, 55 * mm, 55 * mm, 40 * mm]
    )

    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#243B53")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
            colors.white,
            colors.HexColor("#F1F5F9")
        ])
    ]))

    elements.append(table)
    document.build(elements)

    buffer.seek(0)

    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name="career_copilot_analyses.pdf"
    )


# ============================================================
# START APPLICATION
# ============================================================

if __name__ == "__main__":
    app.run(debug=True)