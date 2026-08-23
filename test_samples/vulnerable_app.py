"""
Intentionally vulnerable sample code - for testing the tool only.
Do NOT use this code in production!
"""
import subprocess
import hashlib
import sqlite3
import yaml
from flask import Flask, request

app = Flask(__name__)

# --- Exposed secret (for detect-secrets to catch) ---
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
DATABASE_PASSWORD = "Sup3rS3cretP@ss2026!"


# --- SQL Injection (for bandit B608 to catch) ---
def get_user(user_id):
    conn = sqlite3.connect("app.db")
    query = "SELECT * FROM users WHERE id = " + user_id
    return conn.execute(query).fetchone()


# --- Command Injection (for bandit B602 to catch) ---
def ping_host(hostname):
    subprocess.call(f"ping -c 1 {hostname}", shell=True)


# --- Weak cryptography (for bandit B303/B324 to catch) ---
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


# --- Unsafe YAML loading (for bandit B506 to catch) ---
def load_config(yaml_string):
    return yaml.load(yaml_string)


# --- Flask with debug=True (for bandit B201 to catch) ---
@app.route("/search")
def search():
    term = request.args.get("q")
    result = eval(f"'{term}' in database")  # dangerous use of eval
    return str(result)


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
