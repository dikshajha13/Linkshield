# LinkShield - Suspicious URL Analyzer

**Think Before You Click.** LinkShield is a Web Technology mini project that analyzes the *text* of a URL, scores it with transparent rules and explains every finding in plain language.

## Objective
Teach users to spot common phishing patterns in links, and demonstrate a full client-server web application: HTML/CSS/JavaScript front end, Flask REST-style API, SQLite persistence.

## Features
- Rule-based analysis (20 documented rules, weights shown in the "How It Works" section)
- Risk score 0-100 with Low / Medium / High levels
- Plain-language explanation for each indicator, plus positive observations and advice
- Validation in both the browser and the server
- Scan history stored in SQLite: revisit past results, clear with confirmation
- Responsive, accessible dark UI; no frameworks, no external CDN
- Safe by design: the server **never fetches or opens** a submitted URL (no SSRF)

## Technology stack
HTML5, CSS3, vanilla JavaScript - Python 3 + Flask - SQLite (`sqlite3` module). Only one dependency: Flask.

## Setup
```bash
cd linkshield
python -m venv venv
# Windows (PowerShell):  venv\Scripts\Activate.ps1      (cmd: venv\Scripts\activate.bat)
# macOS / Linux:         source venv/bin/activate
pip install -r requirements.txt
python app.py
```
Open **http://127.0.0.1:5000** in your browser. Stop the server with `Ctrl+C`.
The database file `linkshield.db` is created automatically next to `app.py`.

Run the tests: `python -m unittest discover -s tests -v`

## API
| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/` , `/history` | Pages |
| POST | `/api/scan` | Body `{"url": "..."}` -> validated, analyzed, saved |
| GET | `/api/history?limit=20` | Recent scans (newest first) |
| GET | `/api/history/<id>` | Full stored result of one scan |
| DELETE | `/api/history` | Clear all history |

Responses are JSON: `{"ok": true, ...}` or `{"ok": false, "error": "message"}` with a 4xx status.

## Methodology
1. Validate the string (http/https only, length <= 2048, no spaces, valid hostname).
2. Parse with `urllib.parse.urlsplit`; classify host as domain / IP / obfuscated IP.
3. Apply each rule; every match adds its fixed weight. Score = min(100, sum).
4. Bands: 0-24 Low, 25-59 Medium, 60-100 High. A single weak signal (HTTP, long URL, odd port) cannot reach High.
5. Save to SQLite and return the explanation as JSON; the browser renders it with `textContent` (no HTML injection).

## Security notes
Parameterized SQL, 8 KB request limit, CSP and other headers, escaped output, no IP addresses or cookies stored, history capped at 500 rows.

## Limitations
- Looks only at URL text: no reputation lists, page content, DNS/WHOIS or certificate checks.
- A brand-new phishing site on a clean-looking domain can score Low; a legitimate site with an odd URL can score higher.
- The brand, shortener and TLD lists are small hand-written samples.
- The score is a heuristic, not a probability. Never use it as your only protection.

## Future enhancements
Larger or configurable rule lists, optional reputation-API integration (with SSRF protections), browser extension, user-adjustable weights, CSV export of history, comparison with a machine-learning model.

## Project structure
```
linkshield/
  app.py  analyzer.py  database.py  requirements.txt  README.md
  templates/ index.html history.html
  static/ css/style.css  js/app.js  images/logo.svg
  tests/test_linkshield.py
  docs/REPORT.md        (abstract, diagrams, viva Q&A)
```


## Deploy on Render
1. Push this `linkshield` folder to a GitHub repository.
2. In Render, choose **New → Blueprint** and select the repository containing `render.yaml`, or create a **Web Service** manually.
3. For a manual service, use the root directory `linkshield` if the repository contains this folder, build command `pip install -r requirements.txt`, and start command `gunicorn app:app --bind 0.0.0.0:$PORT`.
4. Deploy, then open the public `onrender.com` URL provided by Render.

Note: SQLite data on a free instance may not persist across restarts/redeploys. For persistent scan history, configure a persistent disk or use a hosted database.
