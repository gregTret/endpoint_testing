# Endpoint Security Tool

Custom BurpSuite alternative. Electron UI + FastAPI backend + mitmproxy interception.

> **This tool is intended for authorized security testing only.** You must have explicit written permission from the owner of any system you test. Unauthorized access to computer systems is illegal. Use at your own risk.

## Features

- Embedded browser with HTTP/S traffic interception and logging
- Persistent site map with crawl/spider support
- Injection scanners: SQL, AQL (ArangoDB), MongoDB NoSQL, XSS, JWT, SSTI, Command Injection, Path Traversal
- OOB (Out-of-Band) blind vulnerability detection via external callback server
- Intercept mode — pause, inspect, and modify requests/responses in transit
- Repeater for manual request editing and resending
- AI Analysis — uses Claude Code (local CLI) to analyze captured traffic and flag security risks
- Analytics dashboard with timing analysis, parameter profiling, and attack surface heatmap
- Configurable default request headers (User-Agent, etc.) per workspace
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

## AI Analysis (Claude Code Integration)

The AI tab uses [Claude Code](https://docs.anthropic.com/en/docs/claude-code) as a local subprocess to analyze captured traffic. No API key configuration needed — Claude Code handles its own authentication.

1. Capture traffic by browsing through the proxy
2. Open the AI tab, select a model (Opus / Sonnet / Haiku), optionally filter by host
3. Click **Analyze** — the tool collects deduplicated endpoints and confirmed scan vulnerabilities, then sends them to Claude for analysis
4. Results appear as risk-sorted findings with descriptions, evidence, and recommendations

**Requires:** Claude Code CLI installed and authenticated (`npm install -g @anthropic-ai/claude-code`)

## Architecture

```
Electron (BrowserView → mitmproxy → target)
    ↕ WebSocket / REST
FastAPI backend
    ├── mitmproxy (intercept + log)
    ├── Playwright (spider/crawler)
    ├── Injectors (SQL, AQL, MongoDB, XSS, JWT, SSTI, CMD, Traversal)
    ├── OOB Injector → external callback server
    ├── Claude Code subprocess (AI analysis)
    └── SQLite (logs, scans, credentials, site map)
```

## OOB Callback Server

Blind vulnerability detection (SSRF, XXE, command injection, SSTI, SQLi) uses an external callback server. Deploy the server from `oob_server/` to a publicly reachable host and configure the URL in Settings > OOB Callback Server.

See `.claude/notes/OOB_Server_notes/DEPLOYMENT.md` for deployment instructions.

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