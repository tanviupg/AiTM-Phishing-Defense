# Module 4: SOC Dashboard & User-Training Module

**Owner:** Josna  
**Branch:** `josna/dashboard-training`  
**Platform:** AiTM-Phishing-Defense (DeepCytes Cyber Labs UK Fellowship — Track H)

---

## 1. Introduction

Module 4 delivers the **Security Operations Center (SOC) Dashboard** and **Interactive User Awareness Training & Quiz Module** for the **AiTM-Phishing-Defense** platform. It unifies telemetry from **Module 1 (Event Simulation)**, **Module 2 (Detection & Risk-Scoring Engine)**, and **Module 3 (FIDO2/Passkey Hardening & Containment)** into an enterprise dark-themed monitoring console and beginner-friendly training experience.

---

## 2. Key Features

### SOC Operations Dashboard
- **Dashboard Overview Cards:** Total monitored events, total phishing alerts, high-risk incidents, medium-risk incidents, low-risk incidents, and suspicious/revoked sessions.
- **Threat Analysis Panel:** Groups real Module 2 indicators across TLS/certificate anomalies, suspicious redirect chains, session-context anomalies, and simulated token-replay indicators with exact explanations.
- **Interactive Analytics & Charts:**
  - Threat severity distribution (SVG donut chart)
  - Risk-score distribution buckets (`0-29`, `30-59`, `60-79`, `80-100`)
  - Phishing events & alerts over time (SVG time-series chart)
  - Detection category distribution
  - Incident status statistics
- **Security Event Monitoring:** Searchable, multi-filterable, and column-sortable table displaying `Event ID`, `Timestamp`, `Session ID`, `Risk Score`, `Threat Severity`, `Detection Reason`, `Incident Status`, and JSON telemetry inspection.
- **Incident Management:** Search incidents, filter by severity and status, inspect `R = 30D + 20C + 25S + 15E + 10A` formula breakdowns and timelines, update triage statuses (`Open`, `Investigating`, `Resolved`), and trigger Module 3 session revocation (`HTTP 401` containment proof).
- **FIDO2 & Hardening Integration:** Displays Module 3's 11-factor Authentication Resistance Matrix, WebAuthn origin-binding walkthrough, OAuth 2.0 DPoP token-binding summary, synthetic session containment, and editable CISA/NIST Hardening Checklist.

### User-Training & Phishing-Awareness Quiz
- **9 Structured Beginner-Friendly Lessons:**
  1. What is AiTM phishing?
  2. How reverse-proxy phishing works
  3. How attackers attempt session-token theft
  4. Why traditional URL blocklists can fail
  5. How to identify fake login pages
  6. How to recognize suspicious redirects
  7. Why traditional MFA may not stop every AiTM attack
  8. How FIDO2 and passkeys protect users
  9. Best practices for account protection
  *(Each includes Simple Explanation, Practical Example, Warning Signs, Prevention Techniques, and Module 3 Takeaway.)*
- **12-Question Interactive Quiz:** Reuses Module 3's 8 certification questions (`Q-01`–`Q-08`) and extends with 4 additional awareness questions (`Q-09`–`Q-12`), featuring 4 options per question, immediate correct/incorrect feedback with explanations, final score & percentage calculation, pass/fail status (`>= 75%`), and Restart Quiz support.

---

## 3. Architecture & Directory Layout

```text
module4_soc_dashboard/
├── __init__.py
├── run_dashboard.py                 # Standalone launcher (http://127.0.0.1:8004)
├── README.md
├── backend/
│   ├── __init__.py
│   ├── app.py                       # FastAPI server (/api/m4/* + static frontend)
│   ├── schemas.py                   # Pydantic request/validation models
│   ├── integration_service.py       # Adapter connecting Modules 1, 2 & 3
│   ├── analytics_service.py         # KPI, threat indicator & chart aggregation
│   ├── training_service.py          # 9 lessons & 12-question quiz service
│   └── mock_fallback.py             # Clearly labelled fallback demo records
├── frontend/
│   ├── index.html                   # Responsive dark SOC shell & sidebar
│   ├── app.js                       # SPA router & provenance status controller
│   ├── styles/
│   │   └── soc-theme.css            # Enterprise dark SOC theme & responsive CSS
│   ├── services/
│   │   └── apiClient.js             # Fetch wrapper for /api/m4/*
│   ├── components/
│   │   ├── charts.js                # Zero-dependency interactive SVG charts
│   │   ├── incidentDetail.js        # Formula R, timeline & triage renderer
│   │   └── utils.js                 # Escaping, badges, modal & toast helpers
│   └── pages/
│       ├── dashboardPage.js         # Overview KPIs, Threat Analysis & Charts
│       ├── eventsPage.js            # Searchable/sortable Event Monitoring
│       ├── incidentsPage.js         # Incident Queue & Triage Management
│       ├── hardeningPage.js         # FIDO2 Matrix, Sessions & Checklist
│       ├── trainingPage.js          # 9-Lesson Interactive Training Course
│       └── quizPage.js              # 12-Question Interactive Quiz
└── tests/
    ├── __init__.py
    ├── test_soc_dashboard_api.py    # Pipeline, API, triage & fallback tests
    └── test_training_and_quiz.py    # Lessons, quiz feedback & scoring tests
```

---

## 4. Integration with Modules 1, 2 & 3

`ModuleIntegrationService` (`backend/integration_service.py`) operates with transparent data provenance:

1. **Direct Pipeline Mode (`DIRECT_PIPELINE` — Default):**
   - **Module 1 (`module1_aitm_poc`):** Reads `module1_aitm_poc/events/sample_events.json` (and `live_intercepted_event.json` if present), validates events against `integration/event_schema.json`, and redacts sensitive lab fields.
   - **Module 2 (`module2_detection`):** Executes `AiTMDetector.analyze_event_composite(...)` with `SessionTracker` and `TLSAnalyzer` without duplicating detection logic, plus evaluates `R = 30D + 20C + 25S + 15E + 10A`.
   - **Module 3 (`module3_hardening`):** Shares `data/aitm_sentinel.db`, runs `HardeningEngine.evaluate_detection(...)`, exposes `lab_scenarios.py` (`SCN-001`–`SCN-006`), `AuthDefenseKnowledgeBase`, `HardeningChecklist`, `revoke_session_db()`, `verify_session_access()`, and reuses `training_quiz.py`.
2. **Live Module 3 REST API Mode (`LIVE_MODULE3_API`):**
   - Set `AITM_API_BASE_URL=http://127.0.0.1:8000` when running `python module3_hardening/api.py` to proxy requests over HTTP to Module 3's FastAPI endpoints (`/api/v1/*`, `/api/defense/*`, `/api/pipeline/evaluate`).
3. **Synthetic Fallback Mode (`SYNTHETIC_FALLBACK`):**
   - Activated only when both the live Module 3 API and direct Python module imports are unavailable. All records carry `is_mock_data: true` and trigger a prominent warning banner in the UI.

---

## 5. Technologies Used

- **Backend:** Python 3.10+, FastAPI, Uvicorn, Pydantic, SQLite (`data/aitm_sentinel.db`)
- **Frontend:** Modular HTML5, CSS3 (Responsive Dark SOC Theme), Vanilla ES6 Modules, Custom Interactive SVG Charts
- **Testing:** `pytest`, `fastapi.testclient.TestClient`

---

## 6. Installation & Running Instructions

### Prerequisites
- Python 3.10+
- `fastapi`, `uvicorn`, `pytest`, `httpx` (required by `TestClient`)

```bash
pip install fastapi uvicorn pytest httpx
```

### Run Module 4 Standalone (Direct Pipeline Integration with Modules 1–3)
From the repository root (`E:\dashboard-training`):
```bash
python module4_soc_dashboard/run_dashboard.py
```
Open in browser:
- **Module 4 SOC Dashboard & Training UI:** `http://127.0.0.1:8004/`
- **Module 4 Swagger API Docs:** `http://127.0.0.1:8004/docs`

### Optional: Run Alongside Module 3 API & Module 1 Live Simulation
1. Terminal 1 — Module 3 API: `python module3_hardening/api.py` (port `8000`)
2. Terminal 2 — Module 4 Dashboard (pointing to Module 3 API):
   - PowerShell: `$env:AITM_API_BASE_URL="http://127.0.0.1:8000"; python module4_soc_dashboard/run_dashboard.py`
3. Optional Module 1 Live Proxy Demo:
   - `python module1_aitm_poc/mock_idp.py` (port `5001`)
   - `python module1_aitm_poc/lab_proxy.py` (port `5002`)

---

## 7. API Integration Reference (`/api/m4/*`)

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/m4/health` | `GET` | Health & integration mode check |
| `/api/m4/system/status` | `GET` | Per-module connectivity & data provenance |
| `/api/m4/dashboard/overview` | `GET` | KPI overview cards, threat analysis & chart series |
| `/api/m4/events` | `GET` | Filtered/searchable security events enriched with M2 risk scores |
| `/api/m4/pipeline/ingest-module1` | `POST` | Ingests Module 1 events through Module 2 & 3 |
| `/api/m4/pipeline/analyze` | `POST` | Evaluates a synthetic event via `M1 -> M2 -> M3` |
| `/api/m4/lab/scenarios` | `GET` | Lists Module 3 controlled lab scenarios |
| `/api/m4/lab/scenarios/{id}/run` | `POST` | Runs a Module 3 scenario (`SCN-001`–`SCN-006`) |
| `/api/m4/incidents` | `GET` | Lists & filters security incidents |
| `/api/m4/incidents/{id}` | `GET` | Detailed incident breakdown, formula & timeline |
| `/api/m4/incidents/{id}/status` | `PATCH` | Updates incident status (`Open`, `Investigating`, `Resolved`) |
| `/api/m4/sessions/{id}/revoke` | `POST` | Revokes synthetic session via Module 3 containment |
| `/api/m4/hardening/overview` | `GET` | Module 3 auth matrix, origin/token binding & checklist |
| `/api/m4/training/lessons` | `GET` | Retrieves all 9 awareness training lessons |
| `/api/m4/training/quiz` | `GET` | Retrieves 12 quiz questions (answers stripped) |
| `/api/m4/training/quiz/check` | `POST` | Immediate single-question check & explanation |
| `/api/m4/training/quiz/submit` | `POST` | Full quiz grading, score & percentage result |

---

## 8. Running Tests

Run Module 4's test suite:
```bash
python -m pytest module4_soc_dashboard/tests -v
```

Run the full repository test suite (Modules 1–4):
```bash
python -m pytest -v
```

---

## 9. Ethical & Safety Boundaries

- Operates exclusively on synthetic/anonymized lab telemetry (`*.invalid` domains, RFC 5737 test IPs `192.0.2.x` / `198.51.100.x`, synthetic users like `alice@lab.local`).
- Never collects real passwords, cookies, or live credentials; any `stolen_token` field from lab proxy logs is redacted before persistence or display.
