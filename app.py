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
UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024 * 100  # 100 MB

# ---------------------
# База данных SQLite
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
# Хелперы аутентификации
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
        info = {
            "name": entry.name,
            "is_file": entry.is_file(),
            "size": entry.stat().st_size,
            "mtime": datetime.fromtimestamp(entry.stat().st_mtime).strftime("%Y-%m-%d %H:%M"),
        }
        (files if entry.is_file() else dirs).append(info)
    return dirs, files

# ---------------------
# Шаблоны
# ---------------------
TPL_BASE = """
<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <title>{{ title or "Хранилище файлов" }}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root { --bg:#0e0f12; --card:#16181d; --text:#e6e6e6; --muted:#9aa0aa; --accent:#6aa3ff; --danger:#ff6a6a; --ok:#53d769; }
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial; background: var(--bg); color: var(--text); margin:0; padding:40px; }
    .card { background: var(--card); border-radius: 14px; padding: 24px; max-width: 900px; margin:auto; box-shadow:0 10px 25px rgba(0,0,0,.4); }
    .btn { background: var(--accent); color:white; border:none; padding:10px 18px; border-radius:8px; cursor:pointer; }
    .btn.danger { background: var(--danger); }
    .btn.ok { background: var(--ok); color:#000; }
    .input { width:100%; padding:10px; margin:8px 0; border-radius:6px; border:1px solid #333; background:#0f1116; color:#fff; }
    .muted { color:var(--muted); }
    table { width:100%; border-collapse:collapse; margin-top:10px; }
    th,td { padding:10px; border-bottom:1px solid #333; }
    .right { text-align:right; }
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

TPL_LOGIN = """{% extends TPL_BASE %}{% block content %}
<h1>Файловое хранилище</h1>
<p class="muted">Войдите или зарегистрируйтесь</p>
<form method="post">
  <input class="input" name="username" placeholder="Логин" required>
  <input class="input" type="password" name="password" placeholder="Пароль" required>
  <button class="btn" type="submit">Войти</button>
</form>
<form method="post" action="{{ url_for('register') }}">
  <input class="input" name="username" placeholder="Новый логин" required>
  <input class="input" type="password" name="password" placeholder="Пароль" required>
  <button class="btn ok" type="submit">Создать аккаунт</button>
</form>
{% endblock %}
"""

TPL_DASH = """{% extends TPL_BASE %}{% block content %}
<h1>Кабинет {{ username }}</h1>
<form method="post" action="{{ url_for('logout') }}">
  <button class="btn danger" type="submit">Выйти</button>
</form>
<hr>
<form method="post" action="{{ url_for('upload') }}" enctype="multipart/form-data">
  <input type="hidden" name="path" value="{{ cur_rel }}">
  <input class="input" type="file" name="file">
  <button class="btn ok" type="submit">Загрузить</button>
</form>
<h3>Файлы</h3>
<table>
  <thead><tr><th>Имя</th><th>Размер</th><th>Изменён</th><th class="right">Действия</th></tr></thead>
  <tbody>
  {% for f in files %}
  <tr>
    <td>{{ f.name }}</td><td>{{ f.size }} B</td><td>{{ f.mtime }}</td>
    <td class="right">
      <a class="btn" href="{{ url_for('download') }}?path={{ cur_rel }}&name={{ f.name }}">Скачать</a>
      <form method="post" action="{{ url_for('delete') }}" style="display:inline;">
        <input type="hidden" name="path" value="{{ cur_rel }}">
        <input type="hidden" name="name" value="{{ f.name }}">
        <button class="btn danger" type="submit">Удалить</button>
      </form>
    </td>
  </tr>
  {% endfor %}
  </tbody>
</table>
{% endblock %}
"""

# ---------------------
# Маршруты
# ---------------------
@app.route("/", methods=["GET"])
def index():
    return redirect(url_for("login") if "user_id" not in session else url_for("dashboard"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username, password = request.form["username"], request.form["password"]
        with db() as conn:
            user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            return redirect(url_for("dashboard"))
        flash("Неверный логин или пароль", "error")
    return render_template_string(TPL_LOGIN, TPL_BASE=TPL_BASE, title="Вход")

@app.route("/register", methods=["POST"])
def register():
    username, password = request.form["username"], request.form["password"]
    if not username or not password:
        flash("Введите логин и пароль", "error")
        return redirect(url_for("login"))
    with db() as conn:
        try:
            conn.execute("INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                         (username, generate_password_hash(password), datetime.utcnow().isoformat()))
            user_id = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()["id"]
            user_root(user_id)
            flash("Регистрация успешна, войдите!", "ok")
        except sqlite3.IntegrityError:
            flash("Такой логин уже существует", "error")
    return redirect(url_for("login"))

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    root = user_root(user["id"])
    dirs, files = list_dir(root)
    return render_template_string(TPL_DASH, TPL_BASE=TPL_BASE,
                                  title="Кабинет", username=user["username"],
                                  dirs=dirs, files=files, cur_rel="")

@app.route("/upload", methods=["POST"])
@login_required
def upload():
    user = current_user()
    root = user_root(user["id"])
    f = request.files.get("file")
    if not f:
        flash("Файл не выбран", "error")
        return redirect(url_for("dashboard"))
    filename = secure_filename(f.filename)
    f.save(root / filename)
    flash("Файл загружен", "ok")
    return redirect(url_for("dashboard"))

@app.route("/delete", methods=["POST"])
@login_required
def delete():
    user = current_user()
    root = user_root(user["id"])
    name = request.form["name"]
    target = root / name
    if target.exists():
        target.unlink()
        flash("Удалено", "ok")
    return redirect(url_for("dashboard"))

@app.route("/download")
@login_required
def download():
    user = current_user()
    root = user_root(user["id"])
    name = request.args.get("name")
    return send_from_directory(root, name, as_attachment=True)

# ---------------------
# Запуск
# ---------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
