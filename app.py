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

MAX_CONTENT_LENGTH = 1024 * 1024 * 100  # 100 MB на запрос
ALLOWED_OVERWRITE = True  # Разрешаем перезапись файлов при «замене»

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH


# ---------------------
# База (SQLite)
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
        row = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    return row

def user_root(user_id: int) -> Path:
    p = UPLOAD_ROOT / str(user_id)
    p.mkdir(parents=True, exist_ok=True)
    return p

def safe_join_user_path(base: Path, rel: str) -> Path:
    # Нормализуем относительный путь внутри корня пользователя
    rel = rel.strip().lstrip("/").replace("\\", "/")
    target = (base / rel).resolve()
    if not str(target).startswith(str(base.resolve())):
        raise ValueError("Недопустимый путь")
    return target

def list_dir(path: Path):
    files = []
    dirs = []
    for entry in sorted(path.iterdir(), key=lambda p: (p.is_file(), p.name.lower())):
        stat = entry.stat()
        info = {
            "name": entry.name,
            "is_file": entry.is_file(),
            "size": stat.st_size,
            "mtime": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
        }
        if entry.is_file():
            files.append(info)
        else:
            dirs.append(info)
    return dirs, files


# ---------------------
# Маршруты: аутентификация
# ---------------------
@app.route("/", methods=["GET"])
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

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

    return render_template_string(TPL_LOGIN, title="Вход")

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
    # создадим корневую папку пользователя
    user_root(user_id)
    flash("Успешная регистрация. Войдите под своими данными.", "ok")
    return redirect(url_for("login"))

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------
# Маршруты: файловый кабинет
# ---------------------
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
        files=files
    )

def make_breadcrumbs(rel_path: str):
    crumbs = [{"name": "root", "href": url_for("dashboard")}]
    if not rel_path:
        return crumbs
    parts = [p for p in rel_path.split("/") if p]
    acc = []
    for part in parts:
        acc.append(part)
        href = url_for("dashboard") + f"?path={'/'.join(acc)}"
        crumbs.append({"name": part, "href": href})
    return crumbs

@app.route("/mkdir", methods=["POST"])
@login_required
def mkdir():
    user = current_user()
    root = user_root(user["id"])
    rel = request.form.get("path", "")
    folder_name = request.form.get("folder_name", "").strip()
    try:
        base = safe_join_user_path(root, rel)
        if not folder_name:
            raise ValueError("Пустое имя папки")
        target = safe_join_user_path(base, folder_name)
        target.mkdir(exist_ok=False)
        flash("Папка создана", "ok")
    except FileExistsError:
        flash("Такая папка уже есть", "error")
    except Exception as e:
        flash(f"Ошибка: {e}", "error")
    return redirect(url_for("dashboard", path=rel))

@app.route("/upload", methods=["POST"])
@login_required
def upload():
    user = current_user()
    root = user_root(user["id"])
    rel = request.form.get("path", "")
    try:
        base = safe_join_user_path(root, rel)
        f = request.files.get("file")
        if not f or f.filename == "":
            flash("Файл не выбран", "error")
            return redirect(url_for("dashboard", path=rel))
        filename = secure_filename(f.filename)
        dest = base / filename
        if dest.exists() and not ALLOWED_OVERWRITE:
            flash("Файл уже существует. Используйте замену.", "error")
        else:
            f.save(dest)
            flash("Файл загружен", "ok")
    except Exception as e:
        flash(f"Ошибка: {e}", "error")
    return redirect(url_for("dashboard", path=rel))

@app.route("/replace", methods=["POST"])
@login_required
def replace():
    user = current_user()
    root = user_root(user["id"])
    rel = request.form.get("path", "")
    target_name = request.form.get("target_name", "")
    try:
        base = safe_join_user_path(root, rel)
        f = request.files.get("file")
        if not f or f.filename == "":
            flash("Файл не выбран", "error")
            return redirect(url_for("dashboard", path=rel))
        if not target_name:
            flash("Не указано имя заменяемого файла", "error")
            return redirect(url_for("dashboard", path=rel))
        target = safe_join_user_path(base, target_name)
        if not target.exists() or not target.is_file():
            flash("Целевой файл для замены не найден", "error")
        else:
            f.save(target)
            flash("Файл заменён", "ok")
    except Exception as e:
        flash(f"Ошибка: {e}", "error")
    return redirect(url_for("dashboard", path=rel))

@app.route("/delete", methods=["POST"])
@login_required
def delete():
    user = current_user()
    root = user_root(user["id"])
    rel = request.form.get("path", "")
    name = request.form.get("name", "")
    try:
        base = safe_join_user_path(root, rel)
        target = safe_join_user_path(base, name)
        if target.is_file():
            target.unlink()
            flash("Файл удалён", "ok")
        elif target.is_dir():
            # удаляем только пустые папки
            target.rmdir()
            flash("Папка удалена (если была пустой)", "ok")
        else:
            flash("Ничего не найдено", "error")
    except OSError:
        flash("Папка не пуста", "error")
    except Exception as e:
        flash(f"Ошибка: {e}", "error")
    return redirect(url_for("dashboard", path=rel))

@app.route("/download", methods=["GET"])
@login_required
def download():
    user = current_user()
    root = user_root(user["id"])
    rel = request.args.get("path", "")
    name = request.args.get("name", "")
    try:
        base = safe_join_user_path(root, rel)
        target = safe_join_user_path(base, name)
        if not target.exists() or not target.is_file():
            flash("Файл не найден", "error")
            return redirect(url_for("dashboard", path=rel))
        return send_from_directory(directory=str(base), path=target.name, as_attachment=True)
    except Exception as e:
        flash(f"Ошибка: {e}", "error")
        return redirect(url_for("dashboard", path=rel))


# ---------------------
# Шаблоны (Jinja2 inline)
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
    * { box-sizing: border-box; }
    body { margin:0; font-family: system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, "Helvetica Neue", Arial; background: var(--bg); color: var(--text);}
    a { color: var(--accent); text-decoration: none; }
    .container { max-width: 980px; margin: 0 auto; padding: 24px;}
    .card { background: var(--card); border: 1px solid #242833; border-radius: 14px; padding: 20px; box-shadow: 0 10px 30px rgba(0,0,0,.3);}
    h1, h2, h3 { margin: 0 0 12px; }
    .row { display: flex; gap: 16px; flex-wrap: wrap; }
    .col { flex: 1 1 320px; }
    .input, .btn, select { width: 100%; padding: 12px 14px; border-radius: 10px; border: 1px solid #2a2f3a; background: #0f1116; color: var(--text); }
    .btn { background: #1a64ff; border-color: #1a64ff; cursor: pointer; font-weight: 600; }
    .btn.secondary { background: #2a2f3a; }
    .btn.danger { background: var(--danger); border-color: var(--danger); }
    .btn.ok { background: var(--ok); border-color: var(--ok); color: #0b0c0e; }
    .muted { color: var(--muted); }
    .toolbar { display:flex; gap:8px; align-items:center; margin: 8px 0 16px;}
    .list { width: 100%; border-collapse: collapse; }
    .list th, .list td { padding: 10px 8px; border-bottom: 1px solid #242833; }
    .badge { font-size: 12px; padding: 4px 8px; border-radius: 999px; background: #24314a; color:#a9c7ff;}
    .breadcrumbs a { margin-right: 6px; }
    .flash { padding: 10px 12px; border-radius: 10px; margin: 10px 0; }
    .flash.error { background: #3a1216; color: #ffb3b3; border: 1px solid #5a1a20; }
    .flash.ok { background: #163a1a; color: #c6ffd2; border: 1px solid #1e5a27; }
    form.inline { display:inline; }
    .right { text-align:right; }
  </style>
</head>
<body>
  <div class="container">
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        {% for cat, msg in messages %}
          <div class="flash {{cat}}">{{ msg }}</div>
        {% endfor %}
      {% endif %}
    {% endwith %}
    <div class="card">
      {% block content %}{% endblock %}
    </div>
    <p class="muted" style="margin-top:12px;">Пример демо-приложения — не используйте в продакшене без доработок (CSRF, лимиты типов, антивирус и т.д.).</p>
  </div>
</body>
</html>
"""

TPL_LOGIN = """
{% extends TPL_BASE %}
{% block content %}
<h1>Хранилище файлов</h1>
<p class="muted">Войдите или зарегистрируйтесь</p>

<div class="row">
  <div class="col">
    <h3>Вход</h3>
    <form method="post">
      <input class="input" name="username" placeholder="Логин" required>
      <div style="height:8px"></div>
      <input class="input" type="password" name="password" placeholder="Пароль" required>
      <div style="height:12px"></div>
      <button class="btn" type="submit">Войти</button>
    </form>
  </div>
  <div class="col">
    <h3>Регистрация</h3>
    <form method="post" action="{{ url_for('register') }}">
      <input class="input" name="username" placeholder="Логин" required>
      <div style="height:8px"></div>
      <input class="input" type="password" name="password" placeholder="Пароль" required>
      <div style="height:12px"></div>
      <button class="btn ok" type="submit">Создать аккаунт</button>
    </form>
  </div>
</div>
{% endblock %}
"""

TPL_DASH = """
{% extends TPL_BASE %}
{% block content %}
<div style="display:flex; justify-content:space-between; align-items:center; gap:12px;">
  <h1>Кабинет</h1>
  <form method="post" action="{{ url_for('logout') }}">
    <button class="btn secondary" type="submit">Выйти</button>
  </form>
</div>
<p class="muted">Пользователь: <b>{{ username }}</b></p>

<div class="breadcrumbs">
  {% for c in breadcrumbs %}
    <a href="{{ c.href }}">{{ c.name }}</a>
    {% if not loop.last %}<span class="muted">/</span>{% endif %}
  {% endfor %}
</div>

<div class="toolbar">
  <form method="post" action="{{ url_for('mkdir') }}">
    <input type="hidden" name="path" value="{{ cur_rel }}">
    <input class="input" style="width:260px" name="folder_name" placeholder="Новая папка">
    <button class="btn" type="submit">Создать папку</button>
  </form>

  <form method="post" action="{{ url_for('upload') }}" enctype="multipart/form-data">
    <input type="hidden" name="path" value="{{ cur_rel }}">
    <input class="input" type="file" name="file" style="width:260px">
    <button class="btn" type="submit">Загрузить</button>
  </form>

  <form method="post" action="{{ url_for('replace') }}" enctype="multipart/form-data" title="Заменить существующий файл">
    <input type="hidden" name="path" value="{{ cur_rel }}">
    <input class="input" type="text" name="target_name" placeholder="Имя существующего файла" style="width:220px">
    <input class="input" type="file" name="file" style="width:220px">
    <button class="btn" type="submit">Заменить</button>
  </form>
</div>

<h3>Папки</h3>
<table class="list">
  <thead><tr><th>Имя</th><th class="right">Действия</th></tr></thead>
  <tbody>
  {% if not dirs %}
    <tr><td class="muted" colspan="2">Папок нет</td></tr>
  {% else %}
    {% for d in dirs %}
      <tr>
        <td>
          <span class="badge">DIR</span>
          <a href="{{ url_for('dashboard') }}?path={{ (cur_rel ~ '/' if cur_rel else '') ~ d.name }}">{{ d.name }}</a>
          <span class="muted">— {{ d.mtime }}</span>
        </td>
        <td class="right">
          <form class="inline" method="post" action="{{ url_for('delete') }}" onsubmit="return confirm('Удалить пустую папку?')">
            <input type="hidden" name="path" value="{{ cur_rel }}">
            <input type="hidden" name="name" value="{{ d.name }}">
            <button class="btn danger" type="submit">Удалить</button>
          </form>
        </td>
      </tr>
    {% endfor %}
  {% endif %}
  </tbody>
</table>

<h3>Файлы</h3>
<table class="list">
  <thead><tr><th>Имя</th><th>Размер</th><th>Изменён</th><th class="right">Действия</th></tr></thead>
  <tbody>
  {% if not files %}
    <tr><td class="muted" colspan="4">Файлов нет</td></tr>
  {% else %}
    {% for f in files %}
      <tr>
        <td>{{ f.name }}</td>
        <td>{{ "{:,}".format(f.size).replace(",", " ") }} B</td>
        <td>{{ f.mtime }}</td>
        <td class="right">
          <a class="btn secondary" href="{{ url_for('download') }}?path={{ cur_rel }}&name={{ f.name }}">Скачать</a>
          <form class="inline" method="post" action="{{ url_for('delete') }}" onsubmit="return confirm('Удалить файл?')">
            <input type="hidden" name="path" value="{{ cur_rel }}">
            <input type="hidden" name="name" value="{{ f.name }}">
            <button class="btn danger" type="submit">Удалить</button>
          </form>
        </td>
      </tr>
    {% endfor %}
  {% endif %}
  </tbody>
</table>
{% endblock %}
"""

# даём шаблонам доступ к базе
app.jinja_env.globals["TPL_BASE"] = TPL_BASE

if __name__ == "__main__":
    import os
port = int(os.environ.get("PORT", 5000))
app.run(host="0.0.0.0", port=port)



