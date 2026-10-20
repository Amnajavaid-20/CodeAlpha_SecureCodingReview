# CodeAlpha_SecureCodingReview

**Task 3 of the CodeAlpha Cyber Security Internship: Secure Coding Review of a Flask application.**
Author: Amna Javaid | Date: Oct 20, 2026

## What this project does
I audited a deliberately vulnerable Flask app using manual code inspection and static analysis (Bandit 1.9.4), documented 9 vulnerabilities with CWE/OWASP mapping, and wrote a remediated version.

## Results

| Bandit run | High | Medium | Low |
|---|---|---|---|
| vulnerable_app.py | 4 | 4 | 2 |
| secure_app.py | 0 | 0 | 3 |

The 3 remaining Low findings (B404, B603, B607) concern `subprocess` and are mitigated by input validation, an argument list with no shell, and a timeout.

## Files
- [`SECURITY_REVIEW.md`](SECURITY_REVIEW.md): full findings, CWE/OWASP mapping, fixes
- `vulnerable_app.py`: audit target (intentionally insecure, never deploy)
- `secure_app.py`: remediated version
- `bandit_vulnerable_report.txt` / `bandit_secure_report.txt`: static analysis output (before/after)
- `Screenshots/`: Bandit scan screenshots
- `requirements.txt`: dependencies

## Reproduce
```bash
pip install bandit
bandit -r vulnerable_app.py
bandit -r secure_app.py
```