# Endpoint Security Tool

A BurpSuite-alternative endpoint security testing tool built with **Electron** (UI), **FastAPI** (backend), **mitmproxy** (HTTP/S interception), and **Playwright** (crawling).

## Features

- **Embedded browser** with all traffic routed through an intercepting proxy
- **Real-time request/response logging** with filtering and search
- **Site map** auto-built from observed traffic + optional spider crawl
- **SQL injection scanner** — error-based, UNION, boolean-blind, time-blind
- **AQL injection scanner** — ArangoDB-specific payloads
- **Extensible injector framework** — add new DB types by subclassing `BaseInjector`
- **Request replay** — re-send any captured request
- **Session export** — dump all logs and scan results to JSON

## Prerequisites

- Python 3.11+
- Node.js 18+
- npm

## Setup

### Backend

```bash
cd backend
pip install -r requirements.txt
playwright install chromium
```

### Frontend

```bash
cd electron
npm install
```

## Running

The Electron app automatically starts the Python backend:

```bash
cd electron
npm start
```

Or run them separately:

```bash
# Terminal 1 — backend
cd backend
uvicorn main:app --host 127.0.0.1 --port 8000

# Terminal 2 — frontend
cd electron
npm start
```

## Architecture

```
Electron (BrowserView → mitmproxy → target)
    ↕ WebSocket / REST
FastAPI backend
    ├── mitmproxy (intercept + log)
    ├── Playwright (spider/crawler)
    └── Injectors (SQL, AQL, ...)
```

## Adding a New Injector

1. Create `backend/injectors/my_injector.py`
2. Subclass `BaseInjector` from `injectors.base`
3. Implement `generate_payloads()` and `analyze_response()`
4. Register it in `api/routes.py` → `INJECTORS` dict

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/logs` | List request logs (supports `method`, `host`, `status`, `search` filters) |
| GET | `/api/logs/{id}` | Get single log entry |
| DELETE | `/api/logs` | Clear all logs |
| POST | `/api/crawl?url=...` | Start spider crawl |
| GET | `/api/crawl/status` | Crawl progress |
| POST | `/api/crawl/stop` | Stop crawl |
| GET | `/api/crawl/results` | Crawl discovered URLs + forms |
| GET | `/api/injectors` | List available injector modules |
| POST | `/api/scan` | Launch injection scan (body: `ScanConfig` JSON) |
| GET | `/api/scan/results` | Fetch scan results |
| POST | `/api/replay/{id}` | Replay a captured request |
| POST | `/api/session/export` | Export full session to JSON |
| WS | `/ws` | Real-time log stream |
