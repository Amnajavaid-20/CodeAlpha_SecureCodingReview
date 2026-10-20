"""
Remediated version of vulnerable_app.py. Each fix is tagged with the finding ID (V1-V9).
"""
import json
import os
import re
import secrets
import sqlite3
import subprocess
from pathlib import Path

from flask import Flask, abort, request, render_template_string, send_from_directory
from markupsafe import escape
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)     # V1: from env, never hardcoded
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
DB = "users.db"
UPLOAD_DIR = Path("uploads").resolve()
HOST_RE = re.compile(r"^[A-Za-z0-9.\-]{1,253}$")


def get_db():
    return sqlite3.connect(DB)


@app.route("/register", methods=["POST"])
def register():
    username = request.form["username"].strip()
    password = request.form["password"]
    if not (3 <= len(username) <= 32) or len(password) < 10:               # input validation
        abort(400)
    hashed = generate_password_hash(password)                              # V2: salted, slow hash
    db = get_db()
    db.execute("INSERT INTO users (username, password) VALUES (?, ?)",     # V3: parameterised query
               (username, hashed))
    db.commit()
    return "Registered"


@app.route("/login", methods=["POST"])
def login():
    db = get_db()
    row = db.execute("SELECT password FROM users WHERE username = ?",      # V3
                     (request.form["username"],)).fetchone()
    if row and check_password_hash(row[0], request.form["password"]):
        return "Welcome!"
    return "Invalid credentials", 401      # V9: add Flask-Limiter in production for rate limiting


@app.route("/hello")
def hello():
    name = request.args.get("name", "guest")
    return render_template_string("<h1>Hello {{ name }}</h1>", name=name)  # V4: auto-escaped variable


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    if not HOST_RE.match(host):                                            # V5: allow-list validation
        abort(400)
    result = subprocess.run(["ping", "-c", "1", host],                     # V5: no shell, arg list
                            capture_output=True, text=True, timeout=5)
    return escape(result.stdout)


@app.route("/download")
def download():
    filename = request.args.get("file", "")
    return send_from_directory(UPLOAD_DIR, filename)                       # V6: blocks path traversal


@app.route("/load_session", methods=["POST"])
def load_session():
    try:
        return str(json.loads(request.form["data"]))                       # V7: JSON instead of pickle
    except ValueError:
        abort(400)


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=False)                                 # V8
