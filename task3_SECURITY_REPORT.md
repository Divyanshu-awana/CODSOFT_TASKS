# Task 3 – Secure Code Assessment Report
**Target:** `vulnerable_app.py` (Flask "Student Portal", Python) · **Method:** static analysis with **Bandit** + manual review mapped to **OWASP Top 10 (2021)** · **Fixed version:** `secure_app.py`

## Summary
Bandit flagged **11 issues (3 High, 4 Medium, 4 Low)** in the original. Manual review found one more that no tool caught (path traversal, V5). After fixes Bandit reports **0 High / 0 Medium** (3 informational Low notes, see end).

| ID | Vulnerability | Where | Severity | OWASP | Bandit |
|----|---------------|-------|----------|-------|--------|
| V1 | Hardcoded secret key & DB password | L7–8 | High (impact) | A02/A05 | B105 |
| V2 | Weak, unsalted MD5 password hashing | `/login` | High | A02 Crypto failures | B324 |
| V3 | SQL injection (string formatting) | `/login` | Critical | A03 Injection | B608 |
| V4 | OS command injection (`shell=True`) | `/ping` | Critical | A03 Injection | B602 |
| V5 | Path traversal (`../../etc/passwd`) | `/read` | High | A01 Broken access control | *missed – manual* |
| V6 | Insecure deserialization (`pickle.loads`) | `/load` | Critical (RCE) | A08 Integrity failures | B301/B403 |
| V7 | Unsafe `yaml.load` | `/config` | High | A08 | B506 |
| V8 | Predictable reset token (`random`) | `/reset` | Medium | A07 Auth failures | B311 |
| V9 | `debug=True` + bind `0.0.0.0` | startup | High | A05 Misconfiguration | B201/B104 |

## Findings and fixes
**V1 Hardcoded secrets** – anyone with repo access owns the app. *Fix:* read from environment/secret manager (`os.environ["SECRET_KEY"]`), rotate leaked values, add secret scanning (e.g. gitleaks) in CI.

**V2 MD5 passwords** – fast to brute-force, no salt, rainbow-table friendly. *Fix:* `werkzeug.security.generate_password_hash` / `check_password_hash` (scrypt/PBKDF2) or argon2.

**V3 SQL injection** – input `' OR '1'='1' --` bypasses login. *Fix:* parameterised queries: `execute("... WHERE name = ?", (user,))`.

**V4 Command injection** – `host=8.8.8.8; cat /etc/passwd` runs extra commands. *Fix:* no shell, argument list, validate with `ipaddress.ip_address`, add timeout.

**V5 Path traversal** – `f=../../etc/passwd` reads arbitrary files. *Fix:* `Path.resolve()` and confirm the result stays inside the uploads directory; allow-list file names.

**V6 Pickle** – crafted payload executes code on load. *Fix:* use JSON (data-only) and validate schema; never unpickle untrusted data.

**V7 yaml.load** – object instantiation → RCE. *Fix:* `yaml.safe_load`.

**V8 Weak randomness** – tokens guessable from PRNG state. *Fix:* `secrets.token_urlsafe(32)`, store hashed, set short expiry, single use.

**V9 Debug / bind all** – Werkzeug debugger allows code execution. *Fix:* `debug=False`, bind `127.0.0.1` behind a reverse proxy with TLS, run under gunicorn.

## Additional recommendations
Add authentication and authorisation checks on every route (the original has none beyond login), CSRF protection (Flask-WTF), rate limiting on `/login`, security headers (CSP, HSTS), input validation, dependency scanning (`pip-audit`), logging without secrets, and Bandit/Semgrep in the CI pipeline.

## Verification
`bandit_before.txt` (11 issues) vs `bandit_after.txt` (0 High/Medium). Remaining Low notes are expected: B404/B603/B607 are advisory notes for the `subprocess` import, call and the bare `ping` executable name, which is now safe because `shell=False` and the input is strictly validated.

*Limitations:* static analysis gives false positives/negatives (it missed V5); findings should be confirmed with dynamic testing (e.g. OWASP ZAP) in a safe lab.
