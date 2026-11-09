"""Hardened version of vulnerable_app.py with fixes applied."""
import hmac, os, secrets, sqlite3, subprocess, ipaddress
from pathlib import Path
import yaml
from flask import Flask, request, abort
from werkzeug.security import check_password_hash

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]                    # from environment / vault
UPLOADS = Path("uploads").resolve()

def db():
    return sqlite3.connect("portal.db")

@app.route("/login", methods=["POST"])
def login():
    row = db().execute("SELECT pw FROM users WHERE name = ?", (request.form["user"],)).fetchone()  # parameterised
    ok = row and check_password_hash(row[0], request.form["pwd"])   # salted scrypt/pbkdf2 hash
    return ("ok", 200) if ok else ("denied", 401)

@app.route("/ping")
def ping():
    try:
        host = str(ipaddress.ip_address(request.args.get("host", "")))   # strict validation
    except ValueError:
        abort(400)
    return subprocess.check_output(["ping", "-c", "1", host], shell=False, timeout=5)

@app.route("/read")
def read():
    p = (UPLOADS / request.args.get("f", "")).resolve()
    if UPLOADS not in p.parents or not p.is_file():          # block ../ traversal
        abort(404)
    return p.read_text()

@app.route("/load", methods=["POST"])
def load():
    import json
    return str(json.loads(request.data))                     # data-only format, never pickle

@app.route("/config", methods=["POST"])
def config():
    return str(yaml.safe_load(request.data))

@app.route("/reset")
def reset():
    return secrets.token_urlsafe(32)                         # CSPRNG token

if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=False)
