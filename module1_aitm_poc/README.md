# Module 1: AiTM Lab Simulation & Event Generator

## Purpose
Generate synthetic authentication security events for testing the AiTM detection engine in an authorized lab environment.

## Components
- `event_generator.py` — Generates sample authentication events.
- `events/sample_events.json` — Stores generated events.
- `tests/test_event_generator.py` — Tests the event generator.

## Event Fields

| Field | Meaning |
|---|---|
| `session_id` | Unique synthetic session identifier |
| `timestamp` | Time the event was generated |
| `auth_result` | Simulated authentication outcome |
| `redirect_count` | Number of redirects represented |
| `redirect_chain` | Illustrative sequence of lab hostnames |
| `tls_anomaly` | Simulated TLS anomaly indicator |
| `replay_indicator` | Simulated session-replay indicator |
| `source_ip` | Reserved example IP address |
| `device_id` | Synthetic device identifier |
| `scenario` | Normal or suspicious simulation |

## Run
From the repository root:

```powershell
python .\module1_aitm_poc\event_generator.py
python -m unittest discover -s .\module1_aitm_poc\tests -v
```

## Expected Output
Two synthetic events are saved to `events/sample_events.json`. Automated tests verify the event count, required fields, unique session IDs, and scenario labels.

## Safety
This module generates synthetic data only. It does not collect real credentials or session cookies, or interact with real identity providers.
