# Endpoint Security Tool

Custom BurpSuite alternative. Electron UI + FastAPI backend + mitmproxy interception.

> **This tool is intended for authorized security testing only.** You must have explicit written permission from the owner of any system you test. Unauthorized access to computer systems is illegal. Use at your own risk.

## Features

- Embedded browser with HTTP/S traffic interception and logging
- Persistent site map with crawl/spider support
- Injection scanners: SQL, AQL (ArangoDB), MongoDB NoSQL, XSS, JWT, SSTI, Command Injection, Path Traversal, Python-specific (eval/exec, pickle, Jinja2 RCE, YAML deser)
- File upload attack testing — multipart and presigned-URL flows, 90+ presets (webshells, polyglots, SVG XSS, MIME abuse, path traversal filenames)
- OOB (Out-of-Band) blind vulnerability detection via external callback server
- Intercept mode — pause, inspect, and modify requests/responses in transit
- Repeater for manual request editing and resending
- AI Analysis — uses Claude Code (local CLI) to analyze captured traffic and flag security risks
- Analytics dashboard with timing analysis, parameter profiling, and attack surface heatmap
- Configurable default request headers (User-Agent, etc.) per workspace
- Per-workspace injector type enable/disable
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
    ├── Injectors (SQL, AQL, MongoDB, XSS, JWT, SSTI, CMD, Traversal, Python, Upload)
    ├── OOB Injector → external callback server
    ├── Claude Code subprocess (AI analysis)
    └── SQLite (logs, scans, credentials, site map)
```

## OOB Callback Server

Blind vulnerability detection (SSRF, XXE, command injection, SSTI, SQLi) uses an external callback server. Deploy the server from `oob_server/` to a publicly reachable host and configure the URL in Settings > OOB Callback Server.

See `.claude/notes/OOB_Server_notes/DEPLOYMENT.md` for deployment instructions.

The OOB server also provides IP analytics — view source IPs, country lookup, callback history, and IP exclusion filters via the dashboard.

## Standalone Tools

Scripts in `tools/` that run independently of the Electron app:

- **`deep_crawl.py`** — headless browser spider. Authenticates via OAuth/SSO, crawls pages, clicks interactive elements, intercepts network requests, parses OpenAPI specs. Outputs a full endpoint inventory.
- **`post_crawl_check.py`** — reads deep crawl output and runs injection tests against every discovered endpoint. Produces JSON findings + HTML report.
- **`upload_tester/`** — record a file upload via proxy, analyze the upload mechanism, then replay with all attack presets. `python main.py record` → `analyze` → `test`.

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