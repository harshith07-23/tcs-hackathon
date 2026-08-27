# VibeGuard (Backend) — AI-Generated Code Security Scanner

> AI can generate software quickly. VibeGuard helps make sure that software is safe before it reaches production.

VibeGuard scans a project (Python / JavaScript / TypeScript) for security issues using deterministic static analysis, secret detection, and dependency checks — then uses **Google Gemini** to explain findings, describe potential attack paths, and suggest fixes. The numeric security score is always deterministic and never depends on Gemini.

This package is the **backend only** (FastAPI + PostgreSQL). It exposes a REST API that a frontend (or `curl` / Postman / the interactive `/docs` page) can call.

---

## 1. Architecture

```
Deterministic Security Analysis  (semgrep / bandit / built-in pattern rules)
              +
   Secret Scanning (gitleaks / built-in patterns, values always masked)
              +
   Dependency Analysis (requirements.txt / package.json vs known advisories)
              +
        Risk Scoring Engine (0-100, fully reproducible)
              +
        Gemini Reasoning Layer (explanation, attack path, remediation)
              =
           VibeGuard Report  →  PostgreSQL
```

Gemini is never the sole source of truth — if it is unavailable, misconfigured, or returns malformed output, the scan still completes and returns the deterministic findings.

```
vibeguard/
├── backend/
│   ├── main.py                  FastAPI app, startup DB init, CORS
│   ├── api/                     health.py, scans.py, reports.py
│   ├── database/                connection.py, models.py, init_db.py
│   ├── services/
│   │   ├── scanner.py           SAST (semgrep + bandit + built-in rules)
│   │   ├── secret_scanner.py    secret detection (gitleaks + patterns)
│   │   ├── dependency_scanner.py
│   │   ├── risk_engine.py       deterministic 0-100 scoring
│   │   ├── gemini_service.py    Gemini explanation layer
│   │   └── scan_orchestrator.py ties the pipeline together
│   ├── schemas/                 Pydantic request/response models
│   └── utils/
│       ├── file_safety.py       safe ZIP extraction, path-traversal guards
│       └── framework_detector.py
├── demo_vulnerable_app/         intentionally vulnerable demo project
├── demo_vulnerable_app.zip      pre-zipped, ready to upload to /api/scan
├── .env.example
├── .gitignore
└── requirements.txt
```

---

## 2. Prerequisites (Windows)

- Python 3.11+ ([python.org](https://www.python.org/downloads/))
- PostgreSQL 15+ (includes pgAdmin) — see step 3 below
- A Gemini API key from [Google AI Studio](https://aistudio.google.com/apikey) (optional — the scanner works without it, just without AI explanations)

---

## 3. Installing PostgreSQL on Windows

1. Download the Windows installer from **https://www.postgresql.org/download/windows/** (via EDB).
2. Run the installer. When prompted:
   - Choose components: keep **PostgreSQL Server**, **pgAdmin 4**, and **Command Line Tools** checked.
   - Set a password for the `postgres` superuser — **remember this password**, you'll need it in `.env`.
   - Keep the default port `5432` unless it's already in use.
3. Finish the installer. PostgreSQL now runs as a Windows service in the background.

> **PostgreSQL** is the actual database server that stores your data.
> **pgAdmin** is a graphical tool used to inspect and manage that database — it does not store data itself.

---

## 4. Opening pgAdmin

1. Open the Start Menu → **pgAdmin 4**.
2. On first launch, pgAdmin asks you to set a master password (for pgAdmin itself, separate from the PostgreSQL password).
3. In the left sidebar, expand **Servers → PostgreSQL 15** (or your version). Enter the `postgres` user password you set during installation when prompted.

---

## 5. Creating the `vibeguard` database

1. In pgAdmin's left sidebar, right-click **Databases** → **Create** → **Database...**
2. Set **Database name** to:
   ```
   vibeguard
   ```
3. Leave the owner as `postgres` and click **Save**.

You should now see `vibeguard` listed under Databases.

---

## 6. Creating your `.env` file

In the project root (next to `requirements.txt`), create a file named `.env` (copy `.env.example` and fill in your real values):

```
DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@localhost:5432/vibeguard
GEMINI_API_KEY=YOUR_GEMINI_API_KEY
```

Replace `YOUR_PASSWORD` with the PostgreSQL password you set in step 3, and `YOUR_GEMINI_API_KEY` with your Gemini key. **Never commit this file** — it's already listed in `.gitignore`.

`.env.example` (already included) contains placeholders only — do not put real credentials there.

---

## 7. Installing dependencies (Windows PowerShell / cmd)

```bat
cd vibeguard
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

This installs FastAPI, SQLAlchemy, `psycopg2-binary`, `python-dotenv`, the `google-generativeai` SDK, and the security scanning dependencies (`semgrep`, `bandit`). VibeGuard's built-in pattern-based rules and secret patterns work even if `semgrep`/`bandit`/`gitleaks` are not installed or fail to run — they are optional enhancements, not hard requirements.

---

## 8. Initializing the database (optional explicit step)

The backend creates missing tables automatically on startup, but you can also run this explicitly — it's safe to run multiple times and never deletes existing data:

```bat
python -m backend.database.init_db
```

---

## 9. Starting the backend

```bat
python -m uvicorn backend.main:app --reload
```

The API will be available at **http://localhost:8000**, with interactive docs at **http://localhost:8000/docs**.

Check health:

```bat
curl http://localhost:8000/api/health
```

Expected (healthy) response:

```json
{"status": "healthy", "database": "connected", "ml_model": "loaded"}
```

If `GEMINI_API_KEY` is not set, `ml_model` will show `"unavailable"` but the rest of the API still works.

---

## 10. Running a demo scan

A ready-to-use vulnerable demo project is included as `demo_vulnerable_app.zip`. Upload it via `/docs`, or:

```bat
curl -X POST http://localhost:8000/api/scan ^
  -F "project_name=DemoApp" ^
  -F "file=@demo_vulnerable_app.zip"
```

This returns a full `ReportDetailOut` JSON payload with the security score, findings, attack paths, and remediation.

---

## 11. Verifying tables were created (pgAdmin)

1. Open **pgAdmin** → expand **Servers → PostgreSQL → Databases → vibeguard → Schemas → public → Tables**.
2. You should see:
   - `reports`
   - `findings`
   - `scan_metadata`
3. Right-click any table → **View/Edit Data → All Rows** to inspect stored scan results.

---

## 12. Viewing reports in pgAdmin (step by step)

1. Open pgAdmin.
2. Connect to your PostgreSQL server (enter the `postgres` password if prompted).
3. Expand **Databases → vibeguard → Schemas → public → Tables**.
4. Click on `reports` → **View/Edit Data → All Rows** to see each scan's score and counts.
5. Click on `findings` → **View/Edit Data → All Rows** to see individual vulnerabilities (`report_id` links back to `reports.id`).
6. Click on `scan_metadata` → **View/Edit Data → All Rows** to see file counts, detected frameworks, and scan duration.

---

## 13. API reference

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/scan` | Upload a ZIP project (`project_name`, `file` form fields) and run a full scan |
| `GET` | `/api/reports` | List all past reports (summary) |
| `GET` | `/api/reports/{report_id}` | Full report detail, including findings and scan metadata |
| `GET` | `/api/reports/{report_id}/findings` | Findings only, for a given report |
| `PATCH` | `/api/findings/{finding_id}/status` | Mark a finding as `OPEN` / `FIXED` / `IGNORED` / `FALSE_POSITIVE` (findings are never deleted) |
| `GET` | `/api/health` | Database + Gemini availability status |

---

## 14. Security notes

- Secrets are **masked** before storage/display (e.g. `AKIA************9XYZ`) — full values are never persisted or sent to Gemini.
- Uploaded projects are **never executed** — only read as text for static analysis.
- ZIP extraction is guarded against path traversal (zip-slip), zip bombs, and oversized/oversized-file-count archives.
- CORS is restricted to an explicit allowlist (`ALLOWED_ORIGINS` env var), not a wildcard.
- Database and Gemini credentials are read only from environment variables and are never logged or returned in API error messages.
- The risk score is a **pure, reproducible function** of deterministic findings — Gemini never influences it.
- Attack paths are always labeled **"Potential Attack Path"** — VibeGuard performs static analysis only and never claims verified exploitation.

---

## 15. Troubleshooting

**"Unable to connect to PostgreSQL"** — Confirm the PostgreSQL service is running (Services app → `postgresql-x64-15`) and that `DATABASE_URL` in `.env` has the right password/port/database name.

**`ml_model: unavailable` at `/api/health`** — `GEMINI_API_KEY` is missing or invalid. The scanner still works; you'll just see deterministic findings without AI explanations.

**`semgrep`/`bandit`/`gitleaks` not found** — These are optional. VibeGuard's built-in pattern rules run regardless and cover the core vulnerability categories in the spec.
