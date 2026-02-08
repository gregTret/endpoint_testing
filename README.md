# Endpoint Security Tool

Custom BurpSuite alternative. Electron UI + FastAPI backend + mitmproxy interception.

## Features

- Embedded browser with HTTP/S traffic interception and logging
- Persistent site map with crawl/spider support
- Injection scanners: SQL, AQL (ArangoDB), MongoDB NoSQL, XSS
- Repeater for manual request editing and resending
- Workspace system — isolated sessions, credentials, scan history, site maps
- Encrypted credential storage per workspace
- Extensible injector framework (subclass `BaseInjector`)

## Setup

```bash
# Backend
cd backend
pip install -r requirements.txt
playwright install chromium

# Frontend
cd electron
npm install
```

## Run

```bash
cd electron
npm start
```

The Electron app launches the Python backend automatically.

## Architecture

```
Electron (BrowserView → mitmproxy → target)
    ↕ WebSocket / REST
FastAPI backend
    ├── mitmproxy (intercept + log)
    ├── Playwright (spider/crawler)
    ├── Injectors (SQL, AQL, MongoDB, XSS)
    └── SQLite (logs, scans, credentials, site map)
```

## Adding an Injector

1. Create `backend/injectors/my_injector.py`, subclass `BaseInjector`
2. Implement `generate_payloads()` and `analyze_response()`
3. Register in `api/routes.py` → `INJECTORS` dict
