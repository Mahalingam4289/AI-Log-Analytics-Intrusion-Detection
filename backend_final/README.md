# Sentinel Backend — AI Security Log Analytics (Real-Time, All 8 Attacks)

FastAPI service that detects all 8 target attack types in real time:
DoS, Port Scanning, Brute Force (via trained ML models: Isolation Forest +
Random Forest), and IP Spoofing, Session Hijacking, DNS Spoofing, ARP
Spoofing, and Man-in-the-Middle (via 5 deterministic rule-based detectors).

Self-contained — includes every shared module the API needs.

## Setup

```bash
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Run

```bash
uvicorn backend.app.main:app --reload --port 8000
```

First run auto-generates synthetic data, trains the ML models, and seeds
the database (~1 minute). Subsequent restarts load existing models
immediately.

## Run with Docker

```bash
docker build -t sentinel-backend .
docker run -p 8000:8000 \
  -e SENTINEL_ADMIN_PASSWORD=changeme \
  -e SENTINEL_SECRET_KEY=your-random-secret \
  -v sentinel_models:/app/saved_models \
  -v sentinel_data:/app/data \
  -v sentinel_db:/app/database \
  sentinel-backend
```

## Login

Default demo credentials: **admin / admin123** — override via
`SENTINEL_ADMIN_USER` / `SENTINEL_ADMIN_PASSWORD`.

```bash
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```

## The 8 Attacks

| # | Attack | Method | Module |
|---|---|---|---|
| 1 | DoS/DDoS | ML | `models/anomaly_detector.py`, `models/attack_classifier.py` |
| 2 | Port Scanning | ML | same as above |
| 3 | Brute Force | ML | same as above |
| 4 | IP Spoofing | Rule (TTL deviation) | `rules/ip_spoofing.py` |
| 5 | Session Hijacking | Rule (IP change mid-session) | `rules/session_hijack.py` |
| 6 | DNS Spoofing | Rule (resolution outside known IPs) | `rules/dns_spoofing.py` |
| 7 | Network Sniffing | Rule (ARP spoofing — the real, detectable *precursor* to sniffing; sniffing itself is passive and leaves no log trace) | `rules/arp_spoofing.py` |
| 8 | Man-in-the-Middle | Compound rule (session hijack + ARP spoofing co-occurring) | `rules/mitm.py` |

Both detection paths (ML and rule-based) feed the **same** risk scoring,
correlation, alerting, and simulated response pipeline — severity and
alert behavior is consistent regardless of which path caught the attack.

## API reference

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/health` | no | Liveness check |
| POST | `/api/auth/login` | no | `{username, password}` -> JWT |
| GET | `/api/events` | yes | Filters: severity, log_source, user, start_date, end_date, search, limit |
| GET | `/api/events/export.csv` | yes | Same filters, CSV download |
| GET | `/api/alerts` | yes | Filters: severity, status, user, start_date, end_date, search, limit |
| GET | `/api/alerts/export.csv` | yes | Same filters, CSV download |
| PATCH | `/api/alerts/{id}` | yes | `{status?, analyst_notes?}` — investigation workflow |
| GET | `/api/incidents`, `/api/incidents/open` | yes | Persisted / currently-open incidents |
| GET | `/api/stats`, `/stats/severity-distribution`, `/stats/attack-distribution`, `/stats/timeline` | yes | Dashboard KPIs/charts |
| GET/PATCH | `/api/settings` | yes | Runtime-adjustable detection thresholds |
| GET/POST | `/api/stream/status`, `/stream/start`, `/stream/stop`, `/stream/speed` | yes | Control the live feed |
| GET | `/api/users/{entity}/summary`, `/events` | yes | Per-user/IP activity timeline |
| WS | `/ws/live?token=...` | yes | Pushes `{"type": "event"\|"alert"\|"incident_update"\|"stats", "data": {...}}` |

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `SENTINEL_REQUIRE_AUTH` | `true` | Set `false` to disable login for local dev |
| `SENTINEL_ADMIN_USER` / `SENTINEL_ADMIN_PASSWORD` | `admin` / `admin123` | Change before real deployment |
| `SENTINEL_SECRET_KEY` | dev default | JWT signing key — must change in production |
| `SENTINEL_LOG_SOURCE` | `simulated` | `simulated` (demo feed) or `udp` (real ingestion) |
| `SENTINEL_UDP_PORT` | `9999` | Port for the real UDP ingestion listener |
| `SENTINEL_USE_REDIS` | `false` | Enable Redis-backed correlation persistence |
| `SENTINEL_REDIS_URL` | `redis://localhost:6379/0` | Redis connection string |
| `SENTINEL_WEBHOOK_URL` | unset | Slack-compatible webhook, fires on CRITICAL alerts |
| `SENTINEL_NOTIFY_MIN_SEVERITY` | `CRITICAL` | Minimum severity that triggers a webhook |

## Real dataset (3 ML attacks)

`data/load_real_dataset.py` downloads NSL-KDD (real captured/simulated
network attack traffic) and maps it onto this project's log schema:

```bash
python data/load_real_dataset.py
python main.py    # retrains on the real data
```

The 5 rule-based attacks use `data/generate_extra_logs.py` — realistic
synthetic session/DNS/ARP/TTL logs, since no public dataset exists for
these attack types at the log level.

## Testing

```bash
pip install pytest httpx
pytest
```
43 tests (unit + live integration against the real running app).

## Known limitations

- UEBA baseline is built from a small population — expect some
  low-confidence MEDIUM alerts; tune via `PATCH /api/settings`.
- ARP spoofing detects sniffing's *precursor*, not sniffing itself —
  true passive sniffing leaves no log trace by nature.
- MITM is inferred from signal co-occurrence, never detected directly.
- Correlation state lives in one process's memory unless Redis is enabled.
- SQLite is fine for a demo; swap for Postgres in production.
- Single admin account, no role-based access control yet.

## Swapping in a real live log feed

`backend/app/live_source_udp.py` is a real (non-simulated) UDP listener.
Set `SENTINEL_LOG_SOURCE=udp` and point any JSON-over-UDP forwarder at
it — the same event dict shape as `live_source.py`'s simulator.
