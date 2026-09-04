# HTTP Parameter Pollution Detector

A real, no-mock-data security auditing tool that issues a single, **passive** HTTP GET request to a URL you authorize, appending one harmless, uniquely-marked query parameter **twice** (e.g. `?hppcheck=A1b2&hppcheck=C3d4`), and inspects the **actual live response** — body, redirect `Location` header, and `Set-Cookie` header — to reveal how the application really resolves duplicate parameters: first-value-wins, last-value-wins, array-style collection, or reflection into a dangerous sink.

Available as both a **command-line tool** and a **full multi-page web application**.

Developed by **Karanam Shrivasta**
GitHub: https://github.com/mrshrivasta
LinkedIn: https://www.linkedin.com/in/karanam-shrivasta

---

## ⚠️ Disclaimer (read before use)

This tool sends **real HTTP requests** to whatever URL you provide it. It does not use sample data, fixtures, or simulated responses — every finding is derived from an actual response received from the target server at scan time.

- **Non-destructive by design.** Each scan is exactly one standard, idempotent GET request. The only modification made to your URL is appending one extra, harmless, uniquely-marked query parameter twice — every existing parameter and value you provide is sent completely unmodified. No exploit payloads (script tags, SQL syntax, path traversal, etc.) are ever sent, and no repeated/high-volume requests are made. This is the same non-destructive technique used by well-known scanners (OWASP ZAP, Burp Suite passive/light-active scans).
- **Authorized use only.** Only scan URLs and systems that you own, or that you have explicit, contractual, written authorization to test. Sending requests to third-party systems without authorization may violate the Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK), similar computer-crime laws in other jurisdictions, and the target's Terms of Service — even a single, harmless-looking GET request with an extra parameter.
- **No warranty.** This software is provided **"AS IS"**, without warranty of any kind, express or implied, including but not limited to warranties of merchantability, fitness for a particular purpose, and non-infringement.
- **No liability.** The author, Karanam Shrivasta, accepts no liability for any damage, data loss, downtime, legal consequences, financial loss, or any other harm arising from the use, misuse, or inability to use this software.
- **Not a professional audit.** This tool is an educational and productivity aid. A finding here is a reconnaissance signal, not proof of an exploitable vulnerability. It does not replace a certified penetration test, a compliance audit, or a professional security assessment.
- **You are responsible.** By using this tool you accept full responsibility for how you use it and for obtaining any necessary authorization before scanning a target.

---

## Who should use this project

- Web developers and API engineers who want to understand how their own routing/query-parsing layer handles duplicate parameters.
- AppSec engineers doing safe, non-intrusive reconnaissance for HPP-adjacent reflection issues before a deeper, authorized manual assessment.
- QA and security teams verifying that redirect targets and cookie values are never influenced by unsanitized query-parameter data.
- Students and educators studying real-world HTTP Parameter Pollution mechanics with a genuine, working, non-destructive tool.

## Why use this project

HTTP Parameter Pollution (HPP) abuses the fact that different components in the same stack (a WAF, a front-end framework, a back-end service) can disagree about how to resolve a duplicated query parameter — one might use the first value, another the last, another might silently build an array. That disagreement has enabled real filter bypasses, open redirects, and reflected-injection issues. This tool automates the reconnaissance step safely: it appends one inert marker parameter twice and observes exactly how the live application reflects it, with clear severities, a full audit trail (scan logs, alerts, incidents), CSV reporting, and six chart types for trend visibility.

---

## Detection Rules

Every rule below is evaluated against the **actual response** to the one real, passive request (original URL + one appended duplicate marker parameter).

| Rule ID | Name | Severity | What it checks |
|---|---|---|---|
| HPP-001 | Duplicate Parameter Marker Reflected in Response Body | Medium | One or both injected marker values appear verbatim in the response body — confirms the app echoes this parameter into output. |
| HPP-002 | Duplicate Parameters Resolved as 'Last Value Wins' | Low (informational) | Only the second marker value was reflected — discloses the app's duplicate-parameter resolution order. |
| HPP-003 | Duplicate Parameters Resolved as 'First Value Wins' | Low (informational) | Only the first marker value was reflected — the mirror image of HPP-002. |
| HPP-004 | Injected Marker Reflected in Redirect Location Header | High | A redirect's `Location` header contains the injected marker — a real open-redirect risk pattern if a genuine parameter reaches this sink. |
| HPP-005 | Injected Marker Reflected in Set-Cookie Header | **Critical** | A `Set-Cookie` value contains the injected marker — query data flowing directly into a cookie value, a serious injection/fixation-adjacent pattern. |
| HPP-006 | Both Duplicate Parameter Values Reflected (Array-Style Handling) | Medium | Both marker values appear together — the app collects duplicates into an array/list rather than picking one. |
| HPP-000 | Target Unreachable | Low (informational) | The target could not be reached (DNS failure, connection refused/timeout, TLS error, network policy block). Not an HPP finding — an operational note. |

---

## Architecture

```
http-parameter-pollution-detector/
├── Authentication        # app/auth — register/login/logout, Flask-Login sessions, hashed passwords
├── Dashboard              # app/dashboard — run a real scan, view live counters and recent scans
├── Security Engine        # app/security_engine — issues one real GET with an appended duplicate marker param
├── Detection Rules        # app/detection_rules — 6 pure functions evaluating the real reflected response
├── Logs                   # app/logs — full scan history / audit trail, per-scan detail view
├── Alerts                 # app/alerts — generated from findings by severity threshold
├── Incident Management    # app/incident_management — track/triage/resolve alert-driven incidents
├── Analytics               # app/analytics — 6 real chart types (pie, bar, line, radar, doughnut, polar area)
├── Reports                 # app/reports — CSV export of findings
├── Settings                 # app/settings — per-user alert threshold and notification preferences
├── Database                 # app/database/models.py — SQLAlchemy models (SQLite by default)
├── CLI                       # cli/main.py — standalone command-line scanner
├── Web Application            # app/ (Flask app factory, blueprints, templates, static assets)
├── Tests                       # tests/ — rule-level unit tests + real local-server engine tests
├── Documentation                # this README
└── README.md
```

---

## Setup & Run

### Requirements
- Python 3.9+
- pip

### Install

```bash
cd http-parameter-pollution-detector
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Run the web application

```bash
python3 run.py
```

Then open `http://127.0.0.1:5000` in your browser, register an account, and run your first scan from the Dashboard by entering a URL you are authorized to test.

### Run the CLI

```bash
# Basic scan
python3 cli/main.py scan https://your-authorized-target.example.com

# Scan a URL that already has query parameters -- they are preserved untouched
python3 cli/main.py scan "https://your-authorized-target.example.com/search?q=shoes"

# JSON output (for piping into other tools)
python3 cli/main.py scan https://your-authorized-target.example.com --json

# Export findings to CSV
python3 cli/main.py scan https://your-authorized-target.example.com --csv findings.csv

# List all detection rules
python3 cli/main.py rules
```

The CLI exits with status code `1` if any findings were produced (CI/CD friendly) and `0` on a clean scan.

### Run the tests

```bash
PYTHONPATH=. python3 -m pytest tests/ -v
```

Tests include rule-level unit tests against synthetic-but-realistic response dicts, and genuine end-to-end tests that boot a real local HTTP server on an ephemeral `127.0.0.1` port that reflects the duplicate parameters it receives, then perform an actual HTTP request against it via the real Security Engine — no third-party network calls are made during testing, and no exploit payloads are ever sent.

---

## Frequently Asked Questions

**What does the HTTP Parameter Pollution Detector check?**
It issues a single, passive real HTTP GET request that appends one harmless, uniquely-marked duplicate query parameter to the URL you authorize, then inspects the real response body, redirect Location header, and Set-Cookie header for reflection of that marker, revealing whether the application uses first-value-wins, last-value-wins, or array-style handling for duplicate parameters — never sample data, and never an exploit payload.

**Who should use the HTTP Parameter Pollution Detector?**
Web developers and security engineers auditing how their applications resolve duplicate query parameters on sites and applications they own or are explicitly authorized to test.

**Is the HTTP Parameter Pollution Detector a replacement for a professional security audit?**
No. It is an educational and productivity aid only. A finding here is a reconnaissance signal that duplicate-parameter handling exists and behaves a certain way — not proof of an exploitable vulnerability. It does not replace a certified penetration test, compliance audit, or professional security assessment.

**Could appending this extra parameter change anything on the target site?**
The appended parameter uses an unlikely, uniquely-generated name (`hppcheck`) and random marker values, and every existing parameter you provide is left completely untouched. For any application following standard REST/idempotent-GET semantics, an unrecognized extra query parameter is expected to be ignored safely — the same assumption underlying all passive web security scanners.

**Does this tool send more than one request per scan?**
No. Each scan is exactly one HTTP GET request.

---

## License & Attribution

Developed by **Karanam Shrivasta**.
GitHub: https://github.com/mrshrivasta · LinkedIn: https://www.linkedin.com/in/karanam-shrivasta

Provided for authorized security auditing and educational use only. See the Disclaimer section above. No warranty of any kind is provided.
