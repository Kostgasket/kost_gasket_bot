import os
import sqlite3
from pathlib import Path
from datetime import datetime
from functools import wraps
from flask import (
    Flask, request, redirect, url_for, render_template_string,
    session, send_from_directory, flash
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# ---------------------
# Конфигурация
# ---------------------
APP_ROOT = Path(__file__).parent.resolve()
DB_PATH = APP_ROOT / "app.db"
UPLOAD_ROOT = APP_ROOT / "uploads"
UPLOAD_ROOT.mkdir(exist_ok=True)

MAX_CONTENT_LENGTH = 1024 * 1024 * 100  # 100 MB
ALLOWED_OVERWRITE = True

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH


# ---------------------
# База данных
# ---------------------
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
    print("DB ready")

init_db()


# ---------------------
# Авторизация
# ---------------------
def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

def current_user():
    if "user_id" not in session:
        return None
    with db() as conn:
        return conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()

def user_root(user_id: int) -> Path:
    p = UPLOAD_ROOT / str(user_id)
    p.mkdir(parents=True, exist_ok=True)
    return p

def safe_join_user_path(base: Path, rel: str) -> Path:
    rel = rel.strip().lstrip("/").replace("\\", "/")
    target = (base / rel).resolve()
    if not str(target).startswith(str(base.resolve())):
        raise ValueError("Недопустимый путь")
    return target

def list_dir(path: Path):
    files, dirs = [], []
    for entry in sorted(path.iterdir(), key=lambda p: (p.is_file(), p.name.lower())):
        stat = entry.stat()
        info = {
            "name": entry.name,
            "is_file": entry.is_file(),
            "size": stat.st_size,
            "mtime": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
        }
        (files if entry.is_file() else dirs).append(info)
    return dirs, files


# ---------------------
# Роуты
# ---------------------
@app.route("/", methods=["GET"])
def index():
    return redirect(url_for("login") if "user_id" not in session else url_for("dashboard"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with db() as conn:
            user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            return redirect(url_for("dashboard"))
        flash("Неверный логин или пароль", "error")

    return render_template_string(TPL_LOGIN, title="Вход", TPL_BASE=TPL_BASE)

@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    if not username or not password:
        flash("Укажите логин и пароль", "error")
        return redirect(url_for("login"))
    with db() as conn:
        try:
            conn.execute(
                "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                (username, generate_password_hash(password), datetime.utcnow().isoformat())
            )
            user_id = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()["id"]
        except sqlite3.IntegrityError:
            flash("Логин уже занят", "error")
            return redirect(url_for("login"))
    user_root(user_id)
    flash("Успешная регистрация. Войдите.", "ok")
    return redirect(url_for("login"))

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/dashboard", methods=["GET"])
@login_required
def dashboard():
    user = current_user()
    root = user_root(user["id"])
    rel = request.args.get("path", "").strip()
    try:
        cur_dir = safe_join_user_path(root, rel)
    except ValueError:
        flash("Недопустимый путь", "error")
        return redirect(url_for("dashboard"))

    rel_norm = os.path.relpath(cur_dir, root)
    rel_norm = "" if rel_norm == "." else rel_norm

    dirs, files = list_dir(cur_dir)
    breadcrumbs = make_breadcrumbs(rel_norm)

    return render_template_string(
        TPL_DASH,
        title="Мой кабинет",
        username=user["username"],
        cur_rel=rel_norm,
        breadcrumbs=breadcrumbs,
        dirs=dirs,
        files=files,
        TPL_BASE=TPL_BASE
    )

def make_breadcrumbs(rel_path: str):
    crumbs = [{"name": "root", "href": url_for("dashboard")}]
    if not rel_path:
        return crumbs
    parts, acc = rel_path.split("/"), []
    for part in parts:
        acc.append(part)
        href = url_for("dashboard") + f"?path={'/'.join(acc)}"
        crumbs.append({"name": part, "href": href})
    return crumbs


# ---------------------
# Шаблоны (inline)
# ---------------------
TPL_BASE = """
<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <title>{{ title or "Хранилище файлов" }}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body { font-family: system-ui, sans-serif; background:#0e0f12; color:#e6e6e6; margin:0; padding:40px; }
    .card { background:#16181d; border-radius:10px; padding:20px; max-width:960px; margin:auto; box-shadow:0 10px 25px rgba(0,0,0,.4); }
    input, button { padding:10px; margin:5px; border-radius:6px; border:none; }
    input { width:250px; background:#0f1116; color:white; border:1px solid #333; }
    button { background:#1a64ff; color:white; cursor:pointer; }
    .btn.ok { background:#53d769; color:#000; }
    .flash.error { color:#ff6a6a; }
    .flash.ok { color:#53d769; }
  </style>
</head>
<body>
  <div class="card">
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% for cat, msg in messages %}
        <div class="flash {{ cat }}">{{ msg }}</div>
      {% endfor %}
    {% endwith %}
    {% block content %}{% endblock %}
  </div>
</body>
</html>
"""

TPL_LOGIN = """
{% extends TPL_BASE %}
{% block content %}
<h2>Вход в систему</h2>
<form method="post">
  <input name="username" placeholder="Логин" required><br>
  <input type="password" name="password" placeholder="Пароль" required><br>
  <button type="submit">Войти</button>
</form>
<hr>
<h3>Регистрация</h3>
<form method="post" action="{{ url_for('register') }}">
  <input name="username" placeholder="Логин" required><br>
  <input type="password" name="password" placeholder="Пароль" required><br>
  <button class="btn ok" type="submit">Создать аккаунт</button>
</form>
{% endblock %}
"""

TPL_DASH = """
{% extends TPL_BASE %}
{% block content %}
<h2>Кабинет — {{ username }}</h2>
<p>Добро пожаловать! Здесь вы можете загружать и управлять своими файлами.</p>
{% endblock %}
"""


# ---------------------
# Точка входа
# ---------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
