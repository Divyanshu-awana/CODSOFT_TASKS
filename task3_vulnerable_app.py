"""Sample 'Student Portal' app, intentionally insecure, used as the assessment target."""
import hashlib, os, pickle, random, sqlite3, subprocess
import yaml
from flask import Flask, request

app = Flask(__name__)
app.secret_key = "super-secret-123"            # V1 hardcoded secret
DB_PASSWORD = "admin@1234"                      # V1 hardcoded credential

def db():
    return sqlite3.connect("portal.db")

@app.route("/login", methods=["POST"])
def login():
    user, pwd = request.form["user"], request.form["pwd"]
    hashed = hashlib.md5(pwd.encode()).hexdigest()          # V2 weak hash
    q = "SELECT * FROM users WHERE name='%s' AND pw='%s'" % (user, hashed)   # V3 SQL injection
    return "ok" if db().execute(q).fetchone() else "denied"

@app.route("/ping")
def ping():
    host = request.args.get("host")
    return subprocess.check_output("ping -c 1 " + host, shell=True)   # V4 command injection

@app.route("/read")
def read():
    return open("uploads/" + request.args.get("f")).read()   # V5 path traversal

@app.route("/load", methods=["POST"])
def load():
    return str(pickle.loads(request.data))                   # V6 insecure deserialization

@app.route("/config", methods=["POST"])
def config():
    return str(yaml.load(request.data, Loader=yaml.Loader))  # V7 unsafe YAML

@app.route("/reset")
def reset():
    return str(random.randint(100000, 999999))               # V8 predictable reset token

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)                      # V9 debug + all interfaces
