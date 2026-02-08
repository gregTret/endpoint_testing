# Endpoint Security Tool

Custom BurpSuite alternative. Electron UI + FastAPI backend + mitmproxy interception.

> **This tool is intended for authorized security testing only.** You must have explicit written permission from the owner of any system you test. Unauthorized access to computer systems is illegal. Use at your own risk.

## Features

- Embedded browser with HTTP/S traffic interception and logging
- Persistent site map with crawl/spider support
- Injection scanners: SQL, AQL (ArangoDB), MongoDB NoSQL, XSS, JWT
- Repeater for manual request editing and resending
- Analytics dashboard with timing analysis, parameter profiling, and attack surface heatmap
- Workspace system — isolated sessions, credentials, scan history, site maps
- Encrypted credential storage per workspace
- Export to JSON, Postman Collection, and CSV
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
    ├── Injectors (SQL, AQL, MongoDB, XSS, JWT)
    └── SQLite (logs, scans, credentials, site map)
```

## Adding an Injector

1. Create `backend/injectors/my_injector.py`, subclass `BaseInjector`
2. Implement `generate_payloads()` and `analyze_response()`
3. Register in `api/routes.py` → `INJECTORS` dict

## Disclaimer

This tool is designed for **authorized penetration testing, security research, and educational purposes only**. You are solely responsible for ensuring you have proper authorization before testing any system. The authors take no responsibility for misuse, damage, or any legal consequences resulting from the use of this software.

By using this software you acknowledge that:
- You have obtained explicit permission from the system owner before conducting any tests

## License
MIT License