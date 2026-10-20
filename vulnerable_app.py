"""
INTENTIONALLY VULNERABLE demo app (Flask) - audit target for the secure coding review.
DO NOT deploy. Every flaw here is deliberate and documented in SECURITY_REVIEW.md.
"""
import hashlib
import os
import pickle
import sqlite3
import base64

from flask import Flask, request, render_template_string, send_file

app = Flask(__name__)
app.secret_key = "supersecret123"          # V1: hardcoded secret
DB = "users.db"


def get_db():
    return sqlite3.connect(DB)


@app.route("/register", methods=["POST"])
def register():
    username = request.form["username"]
    password = request.form["password"]
    hashed = hashlib.md5(password.encode()).hexdigest()      # V2: weak hash, no salt
    db = get_db()
    db.execute(f"INSERT INTO users (username, password) VALUES ('{username}', '{hashed}')")  # V3: SQLi
    db.commit()
    return "Registered"


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = hashlib.md5(request.form["password"].encode()).hexdigest()
    db = get_db()
    query = "SELECT * FROM users WHERE username='%s' AND password='%s'" % (username, password)  # V3: SQLi
    user = db.execute(query).fetchone()
    return "Welcome!" if user else "Invalid credentials"      # no rate limiting (V9)


@app.route("/hello")
def hello():
    name = request.args.get("name", "guest")
    return render_template_string("<h1>Hello " + name + "</h1>")   # V4: XSS / SSTI


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    return os.popen("ping -c 1 " + host).read()                  # V5: command injection


@app.route("/download")
def download():
    filename = request.args.get("file")
    return send_file("uploads/" + filename)                      # V6: path traversal


@app.route("/load_session", methods=["POST"])
def load_session():
    data = base64.b64decode(request.form["data"])
    return str(pickle.loads(data))                               # V7: insecure deserialization


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)                          # V8: debug mode + bind all interfaces
