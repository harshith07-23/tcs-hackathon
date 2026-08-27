"""
DEMO ONLY — intentionally vulnerable Flask app used to demonstrate VibeGuard.

Do NOT deploy this. Every credential here is fictional and every
vulnerability is deliberate, for scanning demonstration purposes only.
"""

import hashlib
import sqlite3
import subprocess

from flask import Flask, request
from flask_cors import CORS

app = Flask(__name__)

# --- Insecure CORS: allows any origin -----------------------------------
CORS(app, resources={r"/*": {"origins": "*"}})

# --- Hardcoded secret (fictional demo value) -----------------------------
DEMO_API_KEY = "sk_demo_1234567890ABCDEFGHIJ"
DATABASE_PASSWORD = "demo_password_not_real"

app.config["DEBUG"] = True  # security misconfiguration: debug mode in "prod"


@app.route("/login")
def login():
    # --- SQL Injection: string concatenation into a query -----------------
    username = request.args.get("username", "")
    conn = sqlite3.connect("demo.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username='" + username + "'"
    cursor.execute(query)
    return {"result": "ok"}


@app.route("/hash-password")
def hash_password():
    # --- Weak cryptography: MD5 for password hashing ----------------------
    pw = request.args.get("password", "")
    hashed = hashlib.md5(pw.encode()).hexdigest()
    return {"hash": hashed}


@app.route("/ping")
def ping():
    # --- Command injection: shell=True with user input ---------------------
    host = request.args.get("host", "localhost")
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)
    return {"output": result.stdout.decode(errors="ignore")}


@app.route("/render")
def render_template_unsafely():
    # --- Unsafe eval of user-controlled expression -------------------------
    expr = request.args.get("expr", "1+1")
    return {"result": eval(expr)}


if __name__ == "__main__":
    app.run(debug=True)
