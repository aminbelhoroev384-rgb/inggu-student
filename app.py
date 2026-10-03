import os
import sqlite3
import secrets
from datetime import datetime, date
from functools import wraps

from flask import (
    Flask,
    request,
    redirect,
    url_for,
    session,
    render_template_string,
    jsonify,
)
from werkzeug.security import generate_password_hash, check_password_hash


# =========================================================
# НАСТРОЙКИ
# =========================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "inggu.db")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "inggu-student-local-secret-2026"
)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


# =========================================================
# DATABASE
# =========================================================

def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def column_exists(db, table, column):
    rows = db.execute(f"PRAGMA table_info({table})").fetchall()
    return any(row["name"] == column for row in rows)


def add_column(db, table, column, definition):
    if not column_exists(db, table, column):
        db.execute(
            f"ALTER TABLE {table} ADD COLUMN {column} {definition}"
        )


def init_db():
    db = get_db()

    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS directions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        );

        CREATE TABLE IF NOT EXISTS courses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            direction_id INTEGER NOT NULL,
            FOREIGN KEY(direction_id)
                REFERENCES directions(id)
                ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS groups_list (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            direction_id INTEGER NOT NULL,
            course_id INTEGER NOT NULL,
            FOREIGN KEY(direction_id)
                REFERENCES directions(id)
                ON DELETE CASCADE,
            FOREIGN KEY(course_id)
                REFERENCES courses(id)
                ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'student',
            group_id INTEGER,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            FOREIGN KEY(group_id)
                REFERENCES groups_list(id)
                ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS schedule (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id INTEGER NOT NULL,
            day TEXT NOT NULL,
            start_time TEXT NOT NULL,
            end_time TEXT NOT NULL,
            subject TEXT NOT NULL,
            teacher TEXT DEFAULT '',
            room TEXT DEFAULT '',
            FOREIGN KEY(group_id)
                REFERENCES groups_list(id)
                ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS cancellations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            schedule_id INTEGER NOT NULL,
            lesson_date TEXT NOT NULL,
            reason TEXT DEFAULT '',
            replacement TEXT DEFAULT '',
            FOREIGN KEY(schedule_id)
                REFERENCES schedule(id)
                ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS announcements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            text TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(group_id)
                REFERENCES groups_list(id)
                ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            event_date TEXT NOT NULL,
            description TEXT DEFAULT ''
        );

        CREATE INDEX IF NOT EXISTS idx_schedule_group
            ON schedule(group_id);

        CREATE INDEX IF NOT EXISTS idx_schedule_day
            ON schedule(day);

        CREATE INDEX IF NOT EXISTS idx_users_group
            ON users(group_id);

        CREATE INDEX IF NOT EXISTS idx_cancellations_date
            ON cancellations(lesson_date);

        CREATE INDEX IF NOT EXISTS idx_announcements_group
            ON announcements(group_id);
        """
    )

    # Миграции старой базы
    if column_exists(db, "users", "group"):
        add_column(db, "users", "group_id", "INTEGER")

    if not column_exists(db, "users", "active"):
        add_column(db, "users", "active", "INTEGER NOT NULL DEFAULT 1")

    if not column_exists(db, "users", "created_at"):
        add_column(
            db,
            "users",
            "created_at",
            "TEXT"
        )

    if not column_exists(db, "cancellations", "lesson_date"):
        add_column(
            db,
            "cancellations",
            "lesson_date",
            "TEXT"
        )

    if not column_exists(db, "cancellations", "reason"):
        add_column(
            db,
            "cancellations",
            "reason",
            "TEXT DEFAULT ''"
        )

    if not column_exists(db, "cancellations", "replacement"):
        add_column(
            db,
            "cancellations",
            "replacement",
            "TEXT DEFAULT ''"
        )

    now = datetime.now().isoformat(timespec="seconds")

    db.execute(
        """
        UPDATE users
        SET created_at = ?
        WHERE created_at IS NULL OR created_at = ''
        """,
        (now,)
    )

    # Создаём только аккаунты.
    # НАПРАВЛЕНИЯ АВТОМАТИЧЕСКИ НЕ СОЗДАЮТСЯ.
    create_default_user(
        db,
        "Амин",
        "admin",
        "inggu2026",
        "admin"
    )

    create_default_user(
        db,
        "Астемир",
        "astemir",
        "inggu2026",
        "admin"
    )

    db.commit()
    db.close()


def create_default_user(db, name, username, password, role):
    existing = db.execute(
        "SELECT id FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    if existing:
        return

    db.execute(
        """
        INSERT INTO users
        (name, username, password_hash, role, active, created_at)
        VALUES (?, ?, ?, ?, 1, ?)
        """,
        (
            name,
            username,
            generate_password_hash(password),
            role,
            datetime.now().isoformat(timespec="seconds"),
        )
    )


# =========================================================
# CSRF
# =========================================================

def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


@app.context_processor
def inject_globals():
    return {
        "csrf_token": csrf_token()
    }


def check_csrf():
    if request.method == "POST":
        token = request.form.get("csrf_token", "")
        if not token or token != session.get("csrf_token"):
            return False
    return True


# =========================================================
# AUTH
# =========================================================

def current_user():
    user_id = session.get("user_id")

    if not user_id:
        return None

    db = get_db()

    user = db.execute(
        """
        SELECT
            users.*,
            groups_list.name AS group_name,
            directions.name AS direction_name,
            courses.name AS course_name
        FROM users
        LEFT JOIN groups_list
            ON users.group_id = groups_list.id
        LEFT JOIN directions
            ON groups_list.direction_id = directions.id
        LEFT JOIN courses
            ON groups_list.course_id = courses.id
        WHERE users.id = ?
        """,
        (user_id,)
    ).fetchone()

    db.close()

    if not user:
        session.clear()
        return None

    if not user["active"]:
        session.clear()
        return None

    return user


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login"))
        return func(*args, **kwargs)

    return wrapper


def role_required(*roles):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user = current_user()

            if not user:
                return redirect(url_for("login"))

            if user["role"] not in roles:
                return page(
                    "Доступ запрещён",
                    """
                    <div class="card">
                        <h2>Нет доступа</h2>
                        <p class="muted">
                            У вашей учётной записи нет прав для этой страницы.
                        </p>
                    </div>
                    """,
                    403
                )

            return func(*args, **kwargs)

        return wrapper

    return decorator


def is_admin(user):
    return user and user["role"] == "admin"


# =========================================================
# HTML
# =========================================================

BASE_CSS = """
:root {
    --bg: #0b0f14;
    --panel: #121820;
    --panel2: #18212c;
    --text: #f1f5f9;
    --muted: #94a3b8;
    --accent: #4f8cff;
    --accent2: #2563eb;
    --border: #263241;
    --danger: #ef4444;
    --success: #22c55e;
}

body.light {
    --bg: #f4f6f8;
    --panel: #ffffff;
    --panel2: #eef2f6;
    --text: #111827;
    --muted: #64748b;
    --accent: #2563eb;
    --accent2: #1d4ed8;
    --border: #d8dee7;
}

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family: Arial, Helvetica, sans-serif;
}

a {
    color: inherit;
    text-decoration: none;
}

button,
input,
select,
textarea {
    font: inherit;
}

button,
.btn {
    border: 0;
    border-radius: 10px;
    padding: 10px 14px;
    background: var(--accent);
    color: white;
    cursor: pointer;
}

button:hover,
.btn:hover {
    background: var(--accent2);
}

.btn.secondary {
    background: var(--panel2);
    color: var(--text);
    border: 1px solid var(--border);
}

.btn.danger {
    background: var(--danger);
}

.container {
    width: min(1180px, calc(100% - 28px));
    margin: 0 auto;
}

.nav {
    position: sticky;
    top: 0;
    z-index: 20;
    background: rgba(11, 15, 20, .92);
    backdrop-filter: blur(12px);
    border-bottom: 1px solid var(--border);
}

body.light .nav {
    background: rgba(255,255,255,.92);
}

.nav-inner {
    min-height: 64px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
}

.logo {
    font-weight: 800;
    font-size: 19px;
}

.nav-links {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
}

.nav-links a,
.nav-links button {
    padding: 8px 10px;
    background: transparent;
    color: var(--text);
    border-radius: 8px;
}

.nav-links a:hover,
.nav-links button:hover {
    background: var(--panel2);
}

main {
    padding: 28px 0 60px;
}

.hero {
    padding: 35px 0 20px;
}

.hero h1 {
    margin: 0 0 10px;
    font-size: clamp(30px, 5vw, 52px);
}

.hero p {
    color: var(--muted);
    max-width: 700px;
    line-height: 1.6;
}

.grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 14px;
}

.grid-2 {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 14px;
}

.card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 18px;
    margin-bottom: 14px;
}

.card h2,
.card h3 {
    margin-top: 0;
}

.muted {
    color: var(--muted);
}

form {
    display: grid;
    gap: 12px;
}

label {
    display: grid;
    gap: 6px;
    color: var(--muted);
}

input,
select,
textarea {
    width: 100%;
    padding: 11px 12px;
    color: var(--text);
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 10px;
    outline: none;
}

textarea {
    min-height: 110px;
    resize: vertical;
}

input:focus,
select:focus,
textarea:focus {
    border-color: var(--accent);
}

.actions {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
}

.table-wrap {
    overflow-x: auto;
}

table {
    width: 100%;
    border-collapse: collapse;
}

th,
td {
    padding: 11px 9px;
    border-bottom: 1px solid var(--border);
    text-align: left;
    vertical-align: top;
}

th {
    color: var(--muted);
    font-size: 13px;
}

.badge {
    display: inline-block;
    padding: 4px 8px;
    border-radius: 999px;
    background: var(--panel2);
    font-size: 12px;
}

.badge.green {
    color: #86efac;
}

.badge.red {
    color: #fca5a5;
}

.lesson {
    padding: 14px;
    border: 1px solid var(--border);
    border-radius: 12px;
    background: var(--panel);
    margin-bottom: 10px;
}

.lesson-time {
    color: var(--accent);
    font-weight: 700;
}

.lesson-subject {
    font-weight: 700;
    margin-top: 4px;
}

.lesson-meta {
    color: var(--muted);
    margin-top: 6px;
    font-size: 14px;
}

.day-title {
    margin: 20px 0 10px;
}

.alert {
    padding: 12px 14px;
    border-radius: 10px;
    margin-bottom: 14px;
    background: var(--panel2);
    border: 1px solid var(--border);
}

.alert.error {
    border-color: rgba(239,68,68,.5);
}

.alert.success {
    border-color: rgba(34,197,94,.5);
}

footer {
    color: var(--muted);
    border-top: 1px solid var(--border);
    padding: 25px 0;
    margin-top: 30px;
}

.stat {
    font-size: 28px;
    font-weight: 800;
}

@media (max-width: 800px) {
    .grid,
    .grid-2 {
        grid-template-columns: 1fr;
    }

    .nav-inner {
        align-items: flex-start;
        padding: 10px 0;
        flex-direction: column;
    }
}
"""


BASE_JS = """
<script>
(function () {
    const saved = localStorage.getItem("inggu-theme");

    if (saved === "light") {
        document.body.classList.add("light");
    }

    window.toggleTheme = function () {
        document.body.classList.toggle("light");

        const mode = document.body.classList.contains("light")
            ? "light"
            : "dark";

        localStorage.setItem("inggu-theme", mode);
    };

    window.enableNotifications = async function () {
        if (!("Notification" in window)) {
            alert("Ваш браузер не поддерживает уведомления.");
            return;
        }

        const permission = await Notification.requestPermission();

        if (permission === "granted") {
            alert("Уведомления включены.");
        } else {
            alert("Разрешение на уведомления не предоставлено.");
        }
    };
})();
</script>
"""


def page(title, content, status=200):
    user = current_user()

    if user:
        account_html = """
        <a href="/profile">Аккаунт</a>
        <a href="/logout">Выйти</a>
        """
        if user["role"] == "admin":
            account_html += '<a href="/admin">Админ</a>'
        elif user["role"] == "leader":
            account_html += '<a href="/leader">Староста</a>'
    else:
        account_html = '<a href="/login">Аккаунт</a>'

    html = """
<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>""" + title + """ — ИнгГУ Student</title>
<style>
""" + BASE_CSS + """
</style>
</head>

<body>

<nav class="nav">
    <div class="container nav-inner">
        <a class="logo" href="/">ИнгГУ Student</a>

        <div class="nav-links">
            <a href="/">Главная</a>
            <a href="/schedule">Расписание</a>
            """ + account_html + """
            <button onclick="toggleTheme()">Тема</button>
        </div>
    </div>
</nav>

<main>
<div class="container">
""" + content + """
</div>
</main>

<footer>
<div class="container">
    ИнгГУ Student
</div>
</footer>

""" + BASE_JS + """

</body>
</html>
"""

    return html, status


# =========================================================
# HELPERS
# =========================================================

DAYS = {
    "mon": "Понедельник",
    "tue": "Вторник",
    "wed": "Среда",
    "thu": "Четверг",
    "fri": "Пятница",
    "sat": "Суббота",
    "sun": "Воскресенье",
}

DAY_ORDER = [
    "mon",
    "tue",
    "wed",
    "thu",
    "fri",
    "sat",
    "sun",
]


def safe_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def get_group(group_id):
    db = get_db()

    group = db.execute(
        """
        SELECT
            groups_list.*,
            directions.name AS direction_name,
            courses.name AS course_name
        FROM groups_list
        JOIN directions
            ON groups_list.direction_id = directions.id
        JOIN courses
            ON groups_list.course_id = courses.id
        WHERE groups_list.id = ?
        """,
        (group_id,)
    ).fetchone()

    db.close()
    return group


def can_manage_group(user, group_id):
    if not user:
        return False

    if user["role"] == "admin":
        return True

    if user["role"] == "leader":
        return user["group_id"] == group_id

    return False


def get_groups():
    db = get_db()

    rows = db.execute(
        """
        SELECT
            groups_list.*,
            directions.name AS direction_name,
            courses.name AS course_name
        FROM groups_list
        JOIN directions
            ON groups_list.direction_id = directions.id
        JOIN courses
            ON groups_list.course_id = courses.id
        ORDER BY directions.name, courses.name, groups_list.name
        """
    ).fetchall()

    db.close()
    return rows


def render_schedule(group_id):
    db = get_db()

    lessons = db.execute(
        """
        SELECT *
        FROM schedule
        WHERE group_id = ?
        ORDER BY
            CASE day
                WHEN 'mon' THEN 1
                WHEN 'tue' THEN 2
                WHEN 'wed' THEN 3
                WHEN 'thu' THEN 4
                WHEN 'fri' THEN 5
                WHEN 'sat' THEN 6
                WHEN 'sun' THEN 7
                ELSE 8
            END,
            start_time
        """,
        (group_id,)
    ).fetchall()

    db.close()

    html = ""

    grouped = {day: [] for day in DAY_ORDER}

    for lesson in lessons:
        if lesson["day"] in grouped:
            grouped[lesson["day"]].append(lesson)

    for day in DAY_ORDER:
        html += '<h3 class="day-title">' + DAYS[day] + "</h3>"

        if not grouped[day]:
            html += '<p class="muted">Пар нет.</p>'
            continue

        for lesson in grouped[day]:
            html += """
            <div class="lesson">
                <div class="lesson-time">
                    """ + lesson["start_time"] + " — " + lesson["end_time"] + """
                </div>

                <div class="lesson-subject">
                    """ + escape_html(lesson["subject"]) + """
                </div>
                <div class="lesson-meta">
                    Преподаватель:
                    """ + escape_html(lesson["teacher"] or "—") + """
                    <br>
                    Аудитория:
                    """ + escape_html(lesson["room"] or "—") + """
                </div>
            </div>
            """

    return html


def escape_html(value):
    if value is None:
        return ""

    text = str(value)

    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#039;")
    )


# =========================================================
# MAIN
# =========================================================

@app.route("/")
def index():
    db = get_db()

    directions = db.execute(
        "SELECT * FROM directions ORDER BY name"
    ).fetchall()

    events = db.execute(
        """
        SELECT *
        FROM events
        ORDER BY event_date ASC
        LIMIT 10
        """
    ).fetchall()

    announcements = db.execute(
        """
        SELECT
            announcements.*,
            groups_list.name AS group_name
        FROM announcements
        JOIN groups_list
            ON announcements.group_id = groups_list.id
        ORDER BY announcements.created_at DESC
        LIMIT 10
        """
    ).fetchall()

    db.close()

    direction_cards = ""

    if directions:
        for direction in directions:
            direction_cards += """
            <div class="card">
                <h3>""" + escape_html(direction["name"]) + """</h3>
                <a class="btn" href="/schedule?direction=""" + str(
                    direction["id"]
                ) + """">
                    Открыть
                </a>
            </div>
            """
    else:
        direction_cards = """
        <div class="card">
            <h3>Направления пока не добавлены</h3>
            <p class="muted">
                Администратор может добавить направления через админ-панель.
            </p>
        </div>
        """

    event_html = ""

    for event in events:
        event_html += """
        <div class="card">
            <h3>""" + escape_html(event["title"]) + """</h3>
            <div class="muted">""" + escape_html(
                event["event_date"]
            ) + """</div>
            <p>""" + escape_html(
                event["description"] or ""
            ) + """</p>
        </div>
        """

    announcement_html = ""

    for announcement in announcements:
        announcement_html += """
        <div class="card">
            <h3>""" + escape_html(
                announcement["title"]
            ) + """</h3>

            <div class="badge">
                """ + escape_html(
                    announcement["group_name"]
                ) + """
            </div>

            <p>""" + escape_html(
                announcement["text"]
            ) + """</p>

            <div class="muted">
                """ + escape_html(
                    announcement["created_at"]
                ) + """
            </div>
        </div>
        """

    content = """
    <section class="hero">
        <h1>ИнгГУ Student</h1>
        <p>
            Расписание, группы, объявления и университетские мероприятия
            в одном месте.
        </p>

        <div class="actions">
            <a class="btn" href="/schedule">Расписание</a>
            <a class="btn secondary" href="/login">Аккаунт</a>
        </div>
    </section>

    <h2>Направления</h2>

    <div class="grid">
        """ + direction_cards + """
    </div>

    <h2>Объявления</h2>
    """ + (
        announcement_html
        if announcement_html
        else '<div class="card"><p class="muted">Объявлений пока нет.</p></div>'
    ) + """

    <h2>Мероприятия</h2>
    """ + (
        event_html
        if event_html
        else '<div class="card"><p class="muted">Мероприятий пока нет.</p></div>'
    ) + """
    """

    html, status = page("Главная", content)
    return html, status


# =========================================================
# LOGIN
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""

    if request.method == "POST":
        if not check_csrf():
            error = "Ошибка безопасности. Обновите страницу."
        else:
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")

            db = get_db()

            user = db.execute(
                """
                SELECT *
                FROM users
                WHERE username = ?
                """,
                (username,)
            ).fetchone()

            db.close()

            if (
                user
                and user["active"]
                and check_password_hash(
                    user["password_hash"],
                    password
                )
            ):
                session.clear()
                session["user_id"] = user["id"]
                session["csrf_token"] = secrets.token_hex(32)

                return redirect(url_for("profile"))

            error = "Неверный логин или пароль."

    error_html = ""

    if error:
        error_html = """
        <div class="alert error">
            """ + escape_html(error) + """
        </div>
        """

    content = """
    <div class="grid-2">
        <div class="card">
            <h2>Вход</h2>

            """ + error_html + """

            <form method="post">
                <input
                    type="hidden"
                    name="csrf_token"
                    value="{{ csrf_token }}"
                >

                <label>
                    Логин
                    <input
                        name="username"
                        autocomplete="username"
                        required
                    >
                </label>

                <label>
                    Пароль
                    <input
                        type="password"
                        name="password"
                        autocomplete="current-password"
                        required
                    >
                </label>

                <button type="submit">
                    Войти
                </button>
            </form>
        </div>

        <div class="card">
            <h2>Важно</h2>
            <p class="muted">
                Самостоятельной регистрации нет.
                Учётные записи создаёт администратор.
            </p>
        </div>
    </div>
    """

    html, status = page("Вход", content)

    html = render_template_string(
        html,
        csrf_token=csrf_token()
    )

    return html, status


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# =========================================================
# PROFILE
# =========================================================

@app.route("/profile")
@login_required
def profile():
    user = current_user()

    group_text = "Группа не назначена"

    if user["group_name"]:
        group_text = (
            user["group_name"]
            + " · "
            + (user["course_name"] or "")
            + " · "
            + (user["direction_name"] or "")
        )

    role_names = {
        "admin": "Администратор",
        "leader": "Староста",
        "student": "Студент",
    }

    content = """
    <div class="card">
        <h2>Аккаунт</h2>

        <p>
            <b>Имя:</b>
            """ + escape_html(user["name"]) + """
        </p>

        <p>
            <b>Логин:</b>
            """ + escape_html(user["username"]) + """
        </p>

        <p>
            <b>Роль:</b>
            """ + role_names.get(
                user["role"],
                user["role"]
            ) + """
        </p>

        <p>
            <b>Группа:</b>
            """ + escape_html(group_text) + """
        </p>

        <div class="actions">
            <button onclick="enableNotifications()">
                Включить уведомления
            </button>
        </div>
    </div>
    """

    if user["role"] == "leader" and not user["group_id"]:
        content += """
        <div class="alert">
            Вам пока не назначена группа.
            Обратитесь к администратору.
        </div>
        """

    html, status = page("Аккаунт", content)

    return html, status


# =========================================================
# SCHEDULE
# =========================================================

@app.route("/schedule")
def schedule():
    db = get_db()

    directions = db.execute(
        "SELECT * FROM directions ORDER BY name"
    ).fetchall()

    direction_id = safe_int(request.args.get("direction"))
    course_id = safe_int(request.args.get("course"))
    group_id = safe_int(request.args.get("group"))

    courses = []
    groups = []
    selected_group = None

    if direction_id:
        courses = db.execute(
            """
            SELECT *
            FROM courses
            WHERE direction_id = ?
            ORDER BY name
            """,
            (direction_id,)
        ).fetchall()

    if course_id:
        groups = db.execute(
            """
            SELECT *
            FROM groups_list
            WHERE course_id = ?
            ORDER BY name
            """,
            (course_id,)
        ).fetchall()

    if group_id:
        selected_group = db.execute(
            """
            SELECT
                groups_list.*,
                directions.name AS direction_name,
                courses.name AS course_name
            FROM groups_list
            JOIN directions
                ON groups_list.direction_id = directions.id
            JOIN courses
                ON groups_list.course_id = courses.id
            WHERE groups_list.id = ?
            """,
            (group_id,)
        ).fetchone()

    db.close()

    options_direction = '<option value="">Выберите направление</option>'

    for direction in directions:
        selected = (
            " selected"
            if direction_id == direction["id"]
            else ""
        )

        options_direction += (
            '<option value="' + str(direction["id"]) + '"' +
            selected + ">" +
            escape_html(direction["name"]) +
            "</option>"
        )

    options_course = '<option value="">Выберите курс</option>'

    for course in courses:
        selected = (
            " selected"
            if course_id == course["id"]
            else ""
        )

        options_course += (
            '<option value="' + str(course["id"]) + '"' +
            selected + ">" +
            escape_html(course["name"]) +
            "</option>"
        )

    options_group = '<option value="">Выберите группу</option>'

    for group in groups:
        selected = (
            " selected"
            if group_id == group["id"]
            else ""
        )

        options_group += (
            '<option value="' + str(group["id"]) + '"' +
            selected + ">" +
            escape_html(group["name"]) +
            "</option>"
        )

    schedule_html = ""

    if selected_group:
        schedule_html = render_schedule(selected_group["id"])

    content = """
    <h1>Расписание</h1>

    <div class="card">
        <form method="get">
            <label>
                Направление
                <select
                    name="direction"
                    onchange="this.form.submit()"
                >
                    """ + options_direction + """
                </select>
            </label>

            <label>
                Курс
                <select
                    name="course"
                    onchange="this.form.submit()"
                >
                    """ + options_course + """
                </select>
            </label>

            <label>
                Группа
                <select name="group">
                    """ + options_group + """
                </select>
            </label>

            <button type="submit">
                Показать
            </button>
        </form>
    </div>
    """

    if selected_group:
        content += """
        <div class="card">
            <h2>""" + escape_html(
                selected_group["name"]
            ) + """</h2>

            <p class="muted">
                """ + escape_html(
                    selected_group["direction_name"]
                ) + """
                ·
                """ + escape_html(
                    selected_group["course_name"]
                ) + """
            </p>
        </div>

        """ + schedule_html
    else:
        content += """
        <div class="card">
            <p class="muted">
                Выберите направление, курс и группу.
            </p>
        </div>
        """

    html, status = page("Расписание", content)

    return html, status


# =========================================================
# LEADER
# =========================================================

@app.route("/leader")
@role_required("leader", "admin")
def leader():
    user = current_user()

    requested_group = safe_int(request.args.get("group"))

    if user["role"] == "admin":
        group_id = requested_group

        if not group_id:
            groups = get_groups()

            content = """
            <h1>Панель управления</h1>

            <div class="card">
                <h2>Выберите группу</h2>
                """

            if not groups:
                content += """
                <p class="muted">
                    Групп пока нет.
                </p>
                """

            for group in groups:
                content += """
                <p>
                    <a class="btn secondary"
                       href="/leader?group=""" + str(
                           group["id"]
                       ) + """">
                        """ + escape_html(
                            group["name"]
                        ) + """
                    </a>
                </p>
                """

            content += "</div>"

            html, status = page(
                "Управление",
                content
            )

            return html, status

    else:
        group_id = user["group_id"]

        if not group_id:
            content = """
            <div class="card">
                <h2>Группа не назначена</h2>
                <p class="muted">
                    Администратор ещё не назначил вам группу.
                </p>
            </div>
            """

            html, status = page(
                "Панель старосты",
                content
            )

            return html, status

    group = get_group(group_id)

    if not group:
        return redirect(url_for("leader"))

    schedule_html = render_schedule(group_id)

    content = """
    <h1>Панель старосты</h1>

    <div class="card">
        <h2>""" + escape_html(group["name"]) + """</h2>

        <p class="muted">
            """ + escape_html(group["direction_name"]) + """
            ·
            """ + escape_html(group["course_name"]) + """
        </p>

        <div class="actions">
            <a class="btn" href="/leader/lesson/add?group=""" + str(
                group_id
            ) + """">
                Добавить пару
            </a>

            <a class="btn secondary"
               href="/leader/announcement?group=""" + str(
                   group_id
               ) + """">
                Объявление
            </a>

            <a class="btn secondary"
               href="/leader/cancel?group=""" + str(
                   group_id
               ) + """">
                Отмена / замена
            </a>
        </div>
    </div>

    """ + schedule_html + """
    """

    # Кнопки редактирования и удаления
    db = get_db()

    lessons = db.execute(
        """
        SELECT *
        FROM schedule
        WHERE group_id = ?
        ORDER BY
            CASE day
                WHEN 'mon' THEN 1
                WHEN 'tue' THEN 2
                WHEN 'wed' THEN 3
                WHEN 'thu' THEN 4
                WHEN 'fri' THEN 5
                WHEN 'sat' THEN 6
                WHEN 'sun' THEN 7
                ELSE 8
            END,
            start_time
        """,
        (group_id,)
    ).fetchall()

    db.close()

    content += """
    <div class="card">
        <h2>Управление парами</h2>
        <div class="table-wrap">
        <table>
            <tr>
                <th>День</th>
                <th>Время</th>
                <th>Предмет</th>
                <th>Преподаватель</th>
                <th>Аудитория</th>
                <th></th>
            </tr>
    """

    for lesson in lessons:
        content += """
        <tr>
            <td>""" + DAYS.get(
                lesson["day"],
                lesson["day"]
            ) + """</td>

            <td>""" + escape_html(
                lesson["start_time"]
            ) + """ —
            """ + escape_html(
                lesson["end_time"]
            ) + """</td>

            <td>""" + escape_html(
                lesson["subject"]
            ) + """</td>

            <td>""" + escape_html(
                lesson["teacher"]
            ) + """</td>

            <td>""" + escape_html(
                lesson["room"]
            ) + """</td>

            <td>
                <div class="actions">
                    <a class="btn secondary"
                       href="/leader/lesson/""" + str(
                           lesson["id"]
                       ) + """/edit">
                        Изменить
                    </a>

                    <form method="post"
                          action="/leader/lesson/""" + str(
                              lesson["id"]
                          ) + """/delete"
                          style="display:inline">

                        <input
                            type="hidden"
                            name="csrf_token"
                            value="{{ csrf_token }}"
                        >

                        <button class="btn danger"
                                type="submit"
                                onclick="return confirm('Удалить пару?')">
                            Удалить
                        </button>
                    </form>
                </div>
            </td>
        </tr>
        """

    content += """
        </table>
        </div>
    </div>
    """

    html, status = page(
        "Панель старосты",
        content
    )

    html = render_template_string(
        html,
        csrf_token=csrf_token()
    )

    return html, status


# =========================================================
# ADD LESSON
# =========================================================

@app.route("/leader/lesson/add", methods=["GET", "POST"])
@role_required("leader", "admin")
def add_lesson():
    user = current_user()

    requested_group = safe_int(request.args.get("group"))

    if user["role"] == "admin":
        group_id = requested_group
    else:
        group_id = user["group_id"]

    if not group_id or not can_manage_group(user, group_id):
        return page(
            "Ошибка",
            '<div class="alert error">Нет доступа к этой группе.</div>',
            403
        )

    group = get_group(group_id)

    if not group:
        return page(
            "Ошибка",
            '<div class="alert error">Группа не найдена.</div>',
            404
        )

    if request.method == "POST":
        if not check_csrf():
            return page(
                "Ошибка",
                '<div class="alert error">Ошибка безопасности.</div>',
                400
            )

        day = request.form.get("day", "").strip()
        start_time = request.form.get("start_time", "").strip()
        end_time = request.form.get("end_time", "").strip()
        subject = request.form.get("subject", "").strip()
        teacher = request.form.get("teacher", "").strip()
        room = request.form.get("room", "").strip()

        if (
            day not in DAY_ORDER
            or not start_time
            or not end_time
            or not subject
        ):
            error = "Заполните день, время и предмет."

        elif start_time >= end_time:
            error = "Время окончания должно быть позже начала."

        else:
            db = get_db()

            db.execute(
                """
                INSERT INTO schedule
                (
                    group_id,
                    day,
                    start_time,
                    end_time,
                    subject,
                    teacher,
                    room
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    group_id,
                    day,
                    start_time,
                    end_time,
                    subject,
                    teacher,
                    room,
                )
            )

            db.commit()
            db.close()

            return redirect(
                url_for(
                    "leader",
                    group=group_id
                    if user["role"] == "admin"
                    else None
                )
            )

    else:
        error = ""

    content = """
    <div class="card">
        <h2>Добавить пару</h2>

        """ + (
            '<div class="alert error">' +
            escape_html(error) +
            "</div>"
            if error
            else ""
        ) + """

        <form method="post">
            <input
                type="hidden"
                name="csrf_token"
                value="{{ csrf_token }}"
            >

            <label>
                День
                <select name="day" required>
    """

    for day in DAY_ORDER:
        content += (
            '<option value="' + day + '">' +
            DAYS[day] +
            "</option>"
        )

    content += """
                </select>
            </label>

            <label>
                Начало
                <input
                    type="time"
                    name="start_time"
                    required
                >
            </label>

            <label>
                Конец
                <input
                    type="time"
                    name="end_time"
                    required
                >
            </label>

            <label>
                Предмет
                <input name="subject" required>
            </label>

            <label>
                Преподаватель
                <input name="teacher">
            </label>

            <label>
                Аудитория
                <input name="room">
            </label>

            <button type="submit">
                Сохранить
            </button>
        </form>
    </div>
    """

    html, status = page(
        "Добавить пару",
        content
    )

    html = render_template_string(
        html,
        csrf_token=csrf_token()
    )

    return html, status


# =========================================================
# EDIT LESSON
# =========================================================

@app.route(
    "/leader/lesson/<int:lesson_id>/edit",
    methods=["GET", "POST"]
)
@role_required("leader", "admin")
def edit_lesson(lesson_id):
    user = current_user()

    db = get_db()

    lesson = db.execute(
        "SELECT * FROM schedule WHERE id = ?",
        (lesson_id,)
    ).fetchone()

    db.close()

    if not lesson:
        return page(
            "Ошибка",
            '<div class="alert error">Пара не найдена.</div>',
            404
        )

    if not can_manage_group(
        user,
        lesson["group_id"]
    ):
        return page(
            "Ошибка",
            '<div class="alert error">Нет доступа.</div>',
            403
        )

    if request.method == "POST":
        if not check_csrf():
            return page(
                "Ошибка",
                '<div class="alert error">Ошибка безопасности.</div>',
                400
            )

        day = request.form.get("day", "").strip()
        start_time = request.form.get("start_time", "").strip()
        end_time = request.form.get("end_time", "").strip()
        subject = request.form.get("subject", "").strip()
        teacher = request.form.get("teacher", "").strip()
        room = request.form.get("room", "").strip()

        if (
            day not in DAY_ORDER
            or not start_time
            or not end_time
            or not subject
        ):
            error = "Заполните обязательные поля."

        elif start_time >= end_time:
            error = "Время окончания должно быть позже начала."

        else:
            db = get_db()

            db.execute(
                """
                UPDATE schedule
                SET
                    day = ?,
                    start_time = ?,
                    end_time = ?,
                    subject = ?,
                    teacher = ?,
                    room = ?
                WHERE id = ?
                """,
                (
                    day,
                    start_time,
                    end_time,
                    subject,
                    teacher,
                    room,
                    lesson_id,
                )
            )

            db.commit()
            db.close()

            return redirect(
                url_for(
                    "leader",
                    group=lesson["group_id"]
                    if user["role"] == "admin"
                    else None
                )
            )
    else:
        error = ""

    content = """
    <div class="card">
        <h2>Изменить пару</h2>

        """ + (
            '<div class="alert error">' +
            escape_html(error) +
            "</div>"
            if error
            else ""
        ) + """

        <form method="post">
            <input
                type="hidden"
                name="csrf_token"
                value="{{ csrf_token }}"
            >

            <label>
                День
                <select name="day">
    """

    for day in DAY_ORDER:
        selected = (
            " selected"
            if lesson["day"] == day
            else ""
        )

        content += (
            '<option value="' + day + '"' +
            selected + ">" +
            DAYS[day] +
            "</option>"
        )

    content += """
                </select>
            </label>

            <label>
                Начало
                <input
                    type="time"
                    name="start_time"
                    value=\"""" + escape_html(
                        lesson["start_time"]
                    ) + """\"
                    required
                >
            </label>

            <label>
                Конец
                <input
                    type="time"
                    name="end_time"
                    value=\"""" + escape_html(
                        lesson["end_time"]
                    ) + """\"
                    required
                >
            </label>

            <label>
                Предмет
                <input
                    name="subject"
                    value=\"""" + escape_html(
                        lesson["subject"]
                    ) + """\"
                    required
                >
            </label>

            <label>
                Преподаватель
                <input
                    name="teacher"
                    value=\"""" + escape_html(
                        lesson["teacher"] or ""
                    ) + """\"
                >
            </label>

            <label>
                Аудитория
                <input
                    name="room"
                    value=\"""" + escape_html(
                        lesson["room"] or ""
                    ) + """\"
                >
            </label>

            <button type="submit">
                Сохранить изменения
            </button>
        </form>
    </div>
    """

    html, status = page(
        "Изменить пару",
        content
    )

    html = render_template_string(
        html,
        csrf_token=csrf_token()
    )

    return html, status


# =========================================================
# DELETE LESSON
# =========================================================

@app.route(
    "/leader/lesson/<int:lesson_id>/delete",
    methods=["POST"]
)
@role_required("leader", "admin")
def delete_lesson(lesson_id):
    user = current_user()

    if not check_csrf():
        return "CSRF error", 400

    db = get_db()

    lesson = db.execute(
        "SELECT * FROM schedule WHERE id = ?",
        (lesson_id,)
    ).fetchone()

    if not lesson:
        db.close()
        return redirect(url_for("leader"))

    if not can_manage_group(
        user,
        lesson["group_id"]
    ):
        db.close()
        return "Нет доступа", 403

    db.execute(
        "DELETE FROM schedule WHERE id = ?",
        (lesson_id,)
    )

    db.commit()
    db.close()

    return redirect(
        url_for(
            "leader",
            group=lesson["group_id"]
            if user["role"] == "admin"
            else None
        )
    )


# =========================================================
# CANCEL / REPLACEMENT
# =========================================================

@app.route("/leader/cancel", methods=["GET", "POST"])
@role_required("leader", "admin")
def cancel_lesson():
    user = current_user()
    group_id = safe_int(request.args.get("group"))

    if user["role"] == "leader":
        group_id = user["group_id"]

    if not group_id or not can_manage_group(
        user,
        group_id
    ):
        return page(
            "Ошибка",
            '<div class="alert error">Нет доступа.</div>',
            403
        )

    db = get_db()

    lessons = db.execute(
        """
        SELECT *
        FROM schedule
        WHERE group_id = ?
        ORDER BY day, start_time
        """,
        (group_id,)
    ).fetchall()

    if request.method == "POST":
        if not check_csrf():
            db.close()
            return "CSRF error", 400

        schedule_id = safe_int(
            request.form.get("schedule_id")
        )
        lesson_date = request.form.get(
            "lesson_date",
            ""
        ).strip()
        reason = request.form.get(
            "reason",
            ""
        ).strip()
        replacement = request.form.get(
            "replacement",
            ""
        ).strip()

        valid_lesson = db.execute(
            """
            SELECT id
            FROM schedule
            WHERE id = ? AND group_id = ?
            """,
            (
                schedule_id,
                group_id
            )
        ).fetchone()

        if (
            valid_lesson
            and lesson_date
        ):
            existing = db.execute(
                """
                SELECT id
                FROM cancellations
                WHERE schedule_id = ?
                AND lesson_date = ?
                """,
                (
                    schedule_id,
                    lesson_date
                )
            ).fetchone()

            if existing:
                db.execute(
                    """
                    UPDATE cancellations
                    SET
                        reason = ?,
                        replacement = ?
                    WHERE id = ?
                    """,
                    (
                        reason,
                        replacement,
                        existing["id"]
                    )
                )
            else:
                db.execute(
                    """
                    INSERT INTO cancellations
                    (
                        schedule_id,
                        lesson_date,
                        reason,
                        replacement
                    )
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        schedule_id,
                        lesson_date,
                        reason,
                        replacement
                    )
                )

            db.commit()

        db.close()

        return redirect(
            url_for(
                "leader",
                group=group_id
                if user["role"] == "admin"
                else None
            )
        )

    db.close()

    options = ""

    for lesson in lessons:
        options += """
        <option value=\"""" + str(
            lesson["id"]
        ) + """\">
            """ + DAYS.get(
                lesson["day"],
                lesson["day"]
            ) + """
            —
            """ + escape_html(
                lesson["start_time"]
            ) + """
            —
            """ + escape_html(
                lesson["subject"]
            ) + """
        </option>
        """

    content = """
    <div class="card">
        <h2>Отмена / замена пары</h2>

        <form method="post">
            <input
                type="hidden"
                name="csrf_token"
                value="{{ csrf_token }}"
            >

            <label>
                Пара
                <select name="schedule_id" required>
                    """ + options + """
                </select>
            </label>

            <label>
                Дата
                <input
                    type="date"
                    name="lesson_date"
                    required
                >
            </label>

            <label>
                Причина
                <input name="reason">
            </label>

            <label>
                Замена
                <textarea
                    name="replacement"
                    placeholder="Например: пара перенесена на 15:30, ауд. 205"
                ></textarea>
            </label>

            <button type="submit">
                Сохранить
            </button>
        </form>
    </div>
    """

    html, status = page(
        "Отмена / замена",
        content
    )

    html = render_template_string(
        html,
        csrf_token=csrf_token()
    )

    return html, status


# =========================================================
# ANNOUNCEMENT
# =========================================================

@app.route("/leader/announcement", methods=["GET", "POST"])
@role_required("leader", "admin")
def announcement():
    user = current_user()
    group_id = safe_int(request.args.get("group"))

    if user["role"] == "leader":
        group_id = user["group_id"]

    if not group_id or not can_manage_group(
        user,
        group_id
    ):
        return page(
            "Ошибка",
            '<div class="alert error">Нет доступа.</div>',
            403
        )

    if request.method == "POST":
        if not check_csrf():
            return "CSRF error", 400

        title = request.form.get(
            "title",
            ""
        ).strip()

        text = request.form.get(
            "text",
            ""
        ).strip()

        if title and text:
            db = get_db()

            db.execute(
                """
                INSERT INTO announcements
                (
                    group_id,
                    title,
                    text,
                    created_at
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    group_id,
                    title,
                    text,
                    datetime.now().isoformat(
                        timespec="seconds"
                    ),
                )
            )

            db.commit()
            db.close()

            return redirect(
                url_for(
                    "leader",
                    group=group_id
                    if user["role"] == "admin"
                    else None
                )
            )

    content = """
    <div class="card">
        <h2>Новое объявление</h2>

        <form method="post">
            <input
                type="hidden"
                name="csrf_token"
                value="{{ csrf_token }}"
            >

            <label>
                Заголовок
                <input name="title" required>
            </label>

            <label>
                Текст
                <textarea name="text" required></textarea>
            </label>

            <button type="submit">
                Опубликовать
            </button>
        </form>
    </div>
    """

    html, status = page(
        "Объявление",
        content
    )

    html = render_template_string(
        html,
        csrf_token=csrf_token()
    )

    return html, status


# =========================================================
# ADMIN
# =========================================================

@app.route("/admin")
@role_required("admin")
def admin():
    db = get_db()

    directions = db.execute(
        "SELECT * FROM directions ORDER BY name"
    ).fetchall()

    courses = db.execute(
        """
        SELECT
            courses.*,
            directions.name AS direction_name
        FROM courses
        JOIN directions
            ON courses.direction_id = directions.id
        ORDER BY directions.name, courses.name
        """
    ).fetchall()

    groups = db.execute(
        """
        SELECT
            groups_list.*,
            directions.name AS direction_name,
            courses.name AS course_name
        FROM groups_list
        JOIN directions
            ON groups_list.direction_id = directions.id
        JOIN courses
            ON groups_list.course_id = courses.id
        ORDER BY directions.name, courses.name, groups_list.name
        """
    ).fetchall()

    users = db.execute(
        """
        SELECT
            users.*,
            groups_list.name AS group_name
        FROM users
        LEFT JOIN groups_list
            ON users.group_id = groups_list.id
        ORDER BY users.id DESC
        """
    ).fetchall()

    db.close()

    content = """
    <h1>Админ-панель</h1>

    <div class="grid">
        <div class="card">
            <div class="stat">""" + str(
                len(directions)
            ) + """</div>
            <div class="muted">Направлений</div>
        </div>

        <div class="card">
            <div class="stat">""" + str(
                len(groups)
            ) + """</div>
            <div class="muted">Групп</div>
        </div>

        <div class="card">
            <div class="stat">""" + str(
                len(users)
            ) + """</div>
            <div class="muted">Пользователей</div>
        </div>
    </div>

    <div class="card">
        <h2>Добавить направление</h2>

        <form method="post" action="/admin/direction">
            <input
                type="hidden"
                name="csrf_token"
                value="{{ csrf_token }}"
            >

            <label>
                Название
                <input name="name" required>
            </label>

            <button type="submit">
                Добавить
            </button>
        </form>
    </div>

    <div class="card">
        <h2>Добавить курс</h2>

        <form method="post" action="/admin/course">
            <input
                type="hidden"
                name="csrf_token"
                value="{{ csrf_token }}"
            >

            <label>
                Направление
                <select name="direction_id" required>
    """

    for direction in directions:
        content += """
                    <option value=\"""" + str(
                        direction["id"]
                    ) + """\">
                        """ + escape_html(
                            direction["name"]
                        ) + """
                    </option>
        """

    content += """
                </select>
            </label>

            <label>
                Название курса
                <input
                    name="name"
                    placeholder="1 курс"
                    required
                >
            </label>

            <button type="submit">
                Добавить
            </button>
        </form>
    </div>

    <div class="card">
        <h2>Добавить группу</h2>

        <form method="post" action="/admin/group">
            <input
                type="hidden"
                name="csrf_token"
                value="{{ csrf_token }}"
            >

            <label>
                Направление
                <select name="direction_id" required>
    """

    for direction in directions:
        content += """
                    <option value=\"""" + str(
                        direction["id"]
                    ) + """\">
                        """ + escape_html(
                            direction["name"]
                        ) + """
                    </option>
        """

    content += """
                </select>
            </label>

            <label>
                Курс
                <select name="course_id" required>
    """

    for course in courses:
        content += """
                    <option value=\"""" + str(
                        course["id"]
                    ) + """\">
                        """ + escape_html(
                            course["direction_name"]
                        ) + """
                        —
                        """ + escape_html(
                            course["name"]
                        ) + """
                    </option>
        """

    content += """
                </select>
            </label>

            <label>
                Название группы
                <input
                    name="name"
                    placeholder="МЭ-11"
                    required
                >
            </label>

            <button type="submit">
                Добавить
            </button>
        </form>
    </div>

    <div class="card">
        <h2>Создать пользователя</h2>

        <form method="post" action="/admin/user">
            <input
                type="hidden"
                name="csrf_token"
                value="{{ csrf_token }}"
            >

            <label>
                Имя / ФИО
                <input name="name" required>
            </label>

            <label>
                Логин
                <input name="username" required>
            </label>

            <label>
                Пароль
                <input
                    type="password"
                    name="password"
                    required
                >
            </label>

            <label>
                Роль
                <select name="role">
                    <option value="student">Студент</option>
                    <option value="leader">Староста</option>
                    <option value="admin">Администратор</option>
                </select>
            </label>

            <label>
                Группа
                <select name="group_id">
                    <option value="">Без группы</option>
    """

    for group in groups:
        content += """
                    <option value=\"""" + str(
                        group["id"]
                    ) + """\">
                        """ + escape_html(
                            group["name"]
                        ) + """
                        —
                        """ + escape_html(
                            group["direction_name"]
                        ) + """
                    </option>
        """

    content += """
                </select>
            </label>

            <button type="submit">
                Создать аккаунт
            </button>
        </form>
    </div>

    <div class="card">
        <h2>Направления</h2>

        <div class="table-wrap">
        <table>
            <tr>
                <th>ID</th>
                <th>Название</th>
            </tr>
    """

    for direction in directions:
        content += """
            <tr>
                <td>""" + str(
                    direction["id"]
                ) + """</td>
                <td>""" + escape_html(
                    direction["name"]
                ) + """</td>
            </tr>
        """

    content += """
        </table>
        </div>
    </div>

    <div class="card">
        <h2>Группы</h2>

        <div class="table-wrap">
        <table>
            <tr>
                <th>Группа</th>
                <th>Направление</th>
                <th>Курс</th>
            </tr>
    """

    for group in groups:
        content += """
            <tr>
                <td>""" + escape_html(
                    group["name"]
                ) + """</td>

                <td>""" + escape_html(
                    group["direction_name"]
                ) + """</td>

                <td>""" + escape_html(
                    group["course_name"]
                ) + """</td>
            </tr>
        """

    content += """
        </table>
        </div>
    </div>

    <div class="card">
        <h2>Пользователи</h2>

        <div class="table-wrap">
        <table>
            <tr>
                <th>Имя</th>
                <th>Логин</th>
                <th>Роль</th>
                <th>Группа</th>
                <th>Статус</th>
                <th></th>
            </tr>
    """

    role_names = {
        "admin": "Админ",
        "leader": "Староста",
        "student": "Студент",
    }

    for user in users:
        status = (
            '<span class="badge green">Активен</span>'
            if user["active"]
            else '<span class="badge red">Отключён</span>'
        )

        content += """
            <tr>
                <td>""" + escape_html(
                    user["name"]
                ) + """</td>

                <td>""" + escape_html(
                    user["username"]
                ) + """</td>

                <td>""" + role_names.get(
                    user["role"],
                    user["role"]
                ) + """</td>

                <td>""" + escape_html(
                    user["group_name"] or "—"
                ) + """</td>

                <td>""" + status + """</td>

                <td>
                    <div class="actions">
                        <a class="btn secondary"
                           href="/admin/user/""" + str(
                               user["id"]
                           ) + """/edit">
                            Изменить
                        </a>

                        <form method="post"
                              action="/admin/user/""" + str(
                                  user["id"]
                              ) + """/toggle">

                            <input
                                type="hidden"
                                name="csrf_token"
                                value="{{ csrf_token }}"
                            >

                            <button type="submit"
                                    class="btn secondary">
                                """ + (
                                    "Отключить"
                                    if user["active"]
                                    else "Включить"
                                ) + """
                            </button>
                        </form>
                    </div>
                </td>
            </tr>
        """

    content += """
        </table>
        </div>
    </div>

    <div class="card">
        <h2>Мероприятие</h2>

        <form method="post" action="/admin/event">
            <input
                type="hidden"
                name="csrf_token"
                value="{{ csrf_token }}"
            >

            <label>
                Название
                <input name="title" required>
            </label>

            <label>
                Дата
                <input
                    type="date"
                    name="event_date"
                    required
                >
            </label>

            <label>
                Описание
                <textarea name="description"></textarea>
            </label>

            <button type="submit">
                Добавить мероприятие
            </button>
        </form>
    </div>
    """

    html, status = page(
        "Админ-панель",
        content
    )

    html = render_template_string(
        html,
        csrf_token=csrf_token()
    )

    return html, status


# =========================================================
# ADMIN DIRECTION
# =========================================================

@app.route("/admin/direction", methods=["POST"])
@role_required("admin")
def admin_direction():
    if not check_csrf():
        return "CSRF error", 400

    name = request.form.get(
        "name",
        ""
    ).strip()

    if name:
        db = get_db()

        try:
            db.execute(
                "INSERT INTO directions (name) VALUES (?)",
                (name,)
            )
            db.commit()
        except sqlite3.IntegrityError:
            pass

        db.close()

    return redirect(url_for("admin"))


# =========================================================
# ADMIN COURSE
# =========================================================

@app.route("/admin/course", methods=["POST"])
@role_required("admin")
def admin_course():
    if not check_csrf():
        return "CSRF error", 400

    name = request.form.get(
        "name",
        ""
    ).strip()

    direction_id = safe_int(
        request.form.get("direction_id")
    )

    if name and direction_id:
        db = get_db()

        direction = db.execute(
            "SELECT id FROM directions WHERE id = ?",
            (direction_id,)
        ).fetchone()

        if direction:
            db.execute(
                """
                INSERT INTO courses
                (name, direction_id)
                VALUES (?, ?)
                """,
                (
                    name,
                    direction_id
                )
            )

        db.commit()
        db.close()

    return redirect(url_for("admin"))


# =========================================================
# ADMIN GROUP
# =========================================================

@app.route("/admin/group", methods=["POST"])
@role_required("admin")
def admin_group():
    if not check_csrf():
        return "CSRF error", 400

    name = request.form.get(
        "name",
        ""
    ).strip()

    direction_id = safe_int(
        request.form.get("direction_id")
    )

    course_id = safe_int(
        request.form.get("course_id")
    )

    if (
        name
        and direction_id
        and course_id
    ):
        db = get_db()

        direction = db.execute(
            "SELECT id FROM directions WHERE id = ?",
            (direction_id,)
        ).fetchone()

        course = db.execute(
            """
            SELECT id
            FROM courses
            WHERE id = ?
            AND direction_id = ?
            """,
            (
                course_id,
                direction_id
            )
        ).fetchone()

        if direction and course:
            db.execute(
                """
                INSERT INTO groups_list
                (
                    name,
                    direction_id,
                    course_id
                )
                VALUES (?, ?, ?)
                """,
                (
                    name,
                    direction_id,
                    course_id
                )
            )

        db.commit()
        db.close()

    return redirect(url_for("admin"))


# =========================================================
# ADMIN USER CREATE
# =========================================================

@app.route("/admin/user", methods=["POST"])
@role_required("admin")
def admin_user_create():
    if not check_csrf():
        return "CSRF error", 400

    name = request.form.get(
        "name",
        ""
    ).strip()

    username = request.form.get(
        "username",
        ""
    ).strip()

    password = request.form.get(
        "password",
        ""
    )

    role = request.form.get(
        "role",
        "student"
    )

    group_id_raw = request.form.get(
        "group_id",
        ""
    )

    group_id = safe_int(group_id_raw)

    if role not in (
        "student",
        "leader",
        "admin"
    ):
        role = "student"

    if not name or not username or not password:
        return redirect(url_for("admin"))

    db = get_db()

    existing = db.execute(
        "SELECT id FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    if not existing:
        if role != "leader":
            # Студенту группа тоже может быть назначена.
            pass

        if group_id:
            group = db.execute(
                "SELECT id FROM groups_list WHERE id = ?",
                (group_id,)
            ).fetchone()

            if not group:
                group_id = None

        db.execute(
            """
            INSERT INTO users
            (
                name,
                username,
                password_hash,
                role,
                group_id,
                active,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, 1, ?)
            """,
            (
                name,
                username,
                generate_password_hash(password),
                role,
                group_id,
                datetime.now().isoformat(
                    timespec="seconds"
                ),
            )
        )

        db.commit()

    db.close()

    return redirect(url_for("admin"))


# =========================================================
# ADMIN USER EDIT
# =========================================================

@app.route(
    "/admin/user/<int:user_id>/edit",
    methods=["GET", "POST"]
)
@role_required("admin")
def admin_user_edit(user_id):
    db = get_db()

    target = db.execute(
        "SELECT * FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()

    if not target:
        db.close()

        return page(
            "Ошибка",
            '<div class="alert error">Пользователь не найден.</div>',
            404
        )

    groups = db.execute(
        """
        SELECT
            groups_list.*,
            directions.name AS direction_name
        FROM groups_list
        JOIN directions
            ON groups_list.direction_id = directions.id
        ORDER BY directions.name, groups_list.name
        """
    ).fetchall()

    if request.method == "POST":
        if not check_csrf():
            db.close()
            return "CSRF error", 400

        name = request.form.get(
            "name",
            ""
        ).strip()

        username = request.form.get(
            "username",
            ""
        ).strip()

        role = request.form.get(
            "role",
            "student"
        )

        password = request.form.get(
            "password",
            ""
        )

        group_id = safe_int(
            request.form.get("group_id")
        )

        if role not in (
            "student",
            "leader",
            "admin"
        ):
            role = target["role"]

        if not name or not username:
            error = "Имя и логин обязательны."
        else:
            another = db.execute(
                """
                SELECT id
                FROM users
                WHERE username = ?
                AND id != ?
                """,
                (
                    username,
                    user_id
                )
            ).fetchone()

            if another:
                error = "Такой логин уже занят."
            else:
                db.execute(
                    """
                    UPDATE users
                    SET
                        name = ?,
                        username = ?,
                        role = ?,
                        group_id = ?
                    WHERE id = ?
                    """,
                    (
                        name,
                        username,
                        role,
                        group_id,
                        user_id
                    )
                )

                if password:
                    db.execute(
                        """
                        UPDATE users
                        SET password_hash = ?
                        WHERE id = ?
                        """,
                        (
                            generate_password_hash(
                                password
                            ),
                            user_id
                        )
                    )

                db.commit()
                db.close()

                return redirect(url_for("admin"))

    else:
        error = ""

    content = """
    <div class="card">
        <h2>Изменить пользователя</h2>

        """ + (
            '<div class="alert error">' +
            escape_html(error) +
            "</div>"
            if error
            else ""
        ) + """

        <form method="post">
            <input
                type="hidden"
                name="csrf_token"
                value="{{ csrf_token }}"
            >

            <label>
                Имя
                <input
                    name="name"
                    value=\"""" + escape_html(
                        target["name"]
                    ) + """\"
                    required
                >
            </label>

            <label>
                Логин
                <input
                    name="username"
                    value=\"""" + escape_html(
                        target["username"]
                    ) + """\"
                    required
                >
            </label>

            <label>
                Новый пароль
                <input
                    type="password"
                    name="password"
                    placeholder="Оставьте пустым, если менять не нужно"
                >
            </label>

            <label>
                Роль
                <select name="role">
    """

    roles = [
        ("student", "Студент"),
        ("leader", "Староста"),
        ("admin", "Администратор"),
    ]

    for role_value, role_name in roles:
        selected = (
            " selected"
            if target["role"] == role_value
            else ""
        )

        content += (
            '<option value="' +
            role_value +
            '"' +
            selected +
            ">" +
            role_name +
            "</option>"
        )

    content += """
                </select>
            </label>

            <label>
                Группа
                <select name="group_id">
                    <option value="">
                        Без группы
                    </option>
    """

    for group in groups:
        selected = (
            " selected"
            if target["group_id"] == group["id"]
            else ""
        )

        content += """
                    <option
                        value=\"""" + str(
                            group["id"]
                        ) + """\"
                        """ + selected + """>
                        """ + escape_html(
                            group["name"]
                        ) + """
                        —
                        """ + escape_html(
                            group["direction_name"]
                        ) + """
                    </option>
        """

    content += """
                </select>
            </label>

            <button type="submit">
                Сохранить
            </button>
        </form>
    </div>
    """

    db.close()

    html, status = page(
        "Изменить пользователя",
        content
    )

    html = render_template_string(
        html,
        csrf_token=csrf_token()
    )

    return html, status


# =========================================================
# ADMIN USER TOGGLE
# =========================================================

@app.route(
    "/admin/user/<int:user_id>/toggle",
    methods=["POST"]
)
@role_required("admin")
def admin_user_toggle(user_id):
    if not check_csrf():
        return "CSRF error", 400

    current = current_user()

    db = get_db()

    target = db.execute(
        "SELECT * FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()

    if not target:
        db.close()
        return redirect(url_for("admin"))

    # Нельзя отключить самого себя
    if target["id"] == current["id"]:
        db.close()

        return page(
            "Ошибка",
            """
            <div class="alert error">
                Нельзя отключить собственный аккаунт.
            </div>
            """,
            400
        )

    # Нельзя отключить последнего активного админа
    if (
        target["role"] == "admin"
        and target["active"]
    ):
        count = db.execute(
            """
            SELECT COUNT(*) AS count
            FROM users
            WHERE role = 'admin'
            AND active = 1
            """
        ).fetchone()["count"]

        if count <= 1:
            db.close()

            return page(
                "Ошибка",
                """
                <div class="alert error">
                    Нельзя отключить последнего
                    активного администратора.
                </div>
                """,
                400
            )

    db.execute(
        """
        UPDATE users
        SET active = CASE
            WHEN active = 1 THEN 0
            ELSE 1
        END
        WHERE id = ?
        """,
        (user_id,)
    )

    db.commit()
    db.close()

    return redirect(url_for("admin"))


# =========================================================
# ADMIN EVENT
# =========================================================

@app.route("/admin/event", methods=["POST"])
@role_required("admin")
def admin_event():
    if not check_csrf():
        return "CSRF error", 400

    title = request.form.get(
        "title",
        ""
    ).strip()

    event_date = request.form.get(
        "event_date",
        ""
    ).strip()

    description = request.form.get(
        "description",
        ""
    ).strip()

    if title and event_date:
        db = get_db()

        db.execute(
            """
            INSERT INTO events
            (
                title,
                event_date,
                description
            )
            VALUES (?, ?, ?)
            """,
            (
                title,
                event_date,
                description
            )
        )

        db.commit()
        db.close()

    return redirect(url_for("admin"))


# =========================================================
# API SCHEDULE
# =========================================================

@app.route("/api/schedule/<int:group_id>")
def api_schedule(group_id):
    db = get_db()

    group = db.execute(
        """
        SELECT id
        FROM groups_list
        WHERE id = ?
        """,
        (group_id,)
    ).fetchone()

    if not group:
        db.close()
        return jsonify({
            "error": "group_not_found"
        }), 404

    lessons = db.execute(
        """
        SELECT
            id,
            day,
            start_time,
            end_time,
            subject,
            teacher,
            room
        FROM schedule
        WHERE group_id = ?
        ORDER BY day, start_time
        """,
        (group_id,)
    ).fetchall()

    db.close()

    return jsonify([
        dict(lesson)
        for lesson in lessons
    ])


# =========================================================
# HEALTH
# =========================================================

@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "app": "InGGU Student"
    })


# =========================================================
# START
# =========================================================

init_db()


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )