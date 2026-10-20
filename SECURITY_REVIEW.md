# Secure Code Review Report

**Target:** `vulnerable_app.py` (Python / Flask, ~68 lines, 50 LOC as counted by Bandit)
**Methods:** Manual inspection + static analysis with **Bandit 1.9.4**
**Reviewer:** Amna Javaid | **Date:** Oct 20, 2026
**Scope note:** The target is a deliberately vulnerable demo app written for this review.

## 1. Executive summary
Manual review found **9 vulnerabilities** (3 Critical, 5 High, 1 Medium). Bandit independently flagged **10 issues (4 High, 4 Medium, 2 Low)**.
After remediation (`secure_app.py`), Bandit reports **0 High / 0 Medium** and 3 Low items (subprocess-related: B404, B603, B607), which are mitigated by input validation, an argument list with no shell, and a timeout.

| Bandit run | High | Medium | Low |
|---|---|---|---|
| vulnerable_app.py | 4 | 4 | 2 |
| secure_app.py | 0 | 0 | 3 |

Screenshots of both runs are in the `screenshots/` folder.

## 2. Findings

| ID | Vulnerability | Location | Severity | CWE | OWASP 2021 | Found by |
|---|---|---|---|---|---|---|
| V1 | Hardcoded secret key | `app.secret_key` | High | CWE-798 | A02 | Bandit B105 + manual |
| V2 | Weak password hashing (unsalted MD5) | `/register`, `/login` | High | CWE-328 / CWE-759 | A02 | Bandit B324 |
| V3 | SQL injection (string-built queries) | `/register`, `/login` | Critical | CWE-89 | A03 | Bandit B608 + manual |
| V4 | XSS / template injection | `/hello` | High | CWE-79 / CWE-1336 | A03 | Manual |
| V5 | OS command injection | `/ping` | Critical | CWE-78 | A03 | Bandit B605 |
| V6 | Path traversal | `/download` | High | CWE-22 | A01 | Manual |
| V7 | Insecure deserialization (pickle) | `/load_session` | Critical | CWE-502 | A08 | Bandit B301 / B403 |
| V8 | Debug mode on + binds 0.0.0.0 | `app.run` | High | CWE-94 / CWE-605 | A05 | Bandit B201 / B104 |
| V9 | No rate limiting / brute-force protection | `/login` | Medium | CWE-307 | A07 | Manual |

*Severity reflects my manual risk assessment (impact and exploitability). Bandit's own severity ratings are lower for some items, e.g. B105 is rated Low and B608 is rated Medium.*

## 3. Details and remediation

### V1 Hardcoded secret key
- **Issue:** `app.secret_key = "supersecret123"`. Anyone with repo access can forge session cookies.
- **Fix:** Load it from an environment variable or secrets manager and rotate it if leaked: `os.environ.get("SECRET_KEY")`.

### V2 Weak password hashing
- **Issue:** MD5 is fast and unsalted, so passwords fall to rainbow tables or GPU cracking in seconds.
- **Fix:** Use `werkzeug.security.generate_password_hash` / `check_password_hash` (salted, slow). bcrypt or argon2 are also good.

### V3 SQL injection
- **Issue:** User input is concatenated directly into SQL queries.
- **Example input:** username `admin' --` bypasses the password check.
- **Fix:** Use parameterised queries: `db.execute("... WHERE username = ?", (username,))`.

### V4 Cross-site scripting / SSTI
- **Issue:** `name` is concatenated into the template string. `<script>` payloads run in the victim's browser, and `{{ }}` expressions are evaluated server-side.
- **Fix:** Pass data as a template variable (`{{ name }}`) so Jinja2 auto-escapes it. Add a Content-Security-Policy header.

### V5 Command injection
- **Issue:** `os.popen("ping -c 1 " + host)` means `host=8.8.8.8; cat /etc/passwd` runs extra commands.
- **Fix:** Validate with an allow-list regex, use `subprocess.run([...])` with an argument list and no shell, and set a timeout.

### V6 Path traversal
- **Issue:** `file=../../etc/passwd` escapes the uploads folder.
- **Fix:** Use `send_from_directory(UPLOAD_DIR, filename)`, which rejects traversal. Also keep an allow-list of file extensions.

### V7 Insecure deserialization
- **Issue:** `pickle.loads` on user data allows arbitrary code execution.
- **Fix:** Use JSON for untrusted data. Never unpickle data you did not create. Sign data with `itsdangerous` if integrity is needed.

### V8 Debug mode and exposure
- **Issue:** The Werkzeug debugger allows remote code execution, and binding to `0.0.0.0` exposes the app to the whole network.
- **Fix:** Set `debug=False`, bind to `127.0.0.1`, and serve with gunicorn behind a reverse proxy in production.

### V9 No brute-force protection
- **Issue:** Unlimited login attempts are allowed.
- **Fix:** Use Flask-Limiter (e.g. 5 per minute per IP), account lockout or backoff, and MFA.

## 4. General secure-coding best practices
1. Validate all input on the server (allow-lists beat block-lists).
2. Use parameterised queries or an ORM.
3. Encode output by context (HTML, JS, URL).
4. Store secrets outside source code and rotate them.
5. Use modern password hashing (argon2/bcrypt).
6. Apply least privilege and fail securely, with generic error messages.
7. Keep dependencies updated (`pip-audit`, Dependabot).
8. Add CSRF protection (Flask-WTF), secure cookie flags, and HTTPS.
9. Automate checks: run Bandit/Semgrep in CI on each commit.
10. Do peer code reviews with a security checklist (OWASP ASVS).

## 5. Tools and reproduction
```bash
pip install bandit
bandit -r vulnerable_app.py     # before
bandit -r secure_app.py         # after
```
Raw outputs: `bandit_vulnerable_report.txt`, `bandit_secure_report.txt`.
Screenshots: `Screenshots/bandit_vulnerable.PNG`, `Screenshots/bandit_secure.PNG`.

## 6. Residual risk
The remaining Bandit Low findings concern `subprocess`; they are mitigated by regex validation, no shell, and a timeout. Rate limiting (V9) is documented but still needs Flask-Limiter wired in for production, and CSRF protection is still to be added.