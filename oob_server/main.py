import json
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

from db import init_db, store_callback, get_callbacks, delete_callbacks


# --- In-memory pub/sub for live viewers ---

_subscribers: list[WebSocket] = []


async def _broadcast(data: dict):
    """Push a callback to all connected WebSocket viewers."""
    msg = json.dumps(data)
    dead = []
    for ws in _subscribers:
        try:
            await ws.send_text(msg)
        except Exception:
            dead.append(ws)
    for ws in dead:
        try:
            _subscribers.remove(ws)
        except ValueError:
            pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(title="OOB Callback Server", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- API routes (registered first so they take priority) ---


@app.get("/api/health")
async def health():
    return {"status": "ok"}


@app.get("/api/callbacks/{key}/{token}")
async def list_callbacks_for_token(key: str, token: str, since: float | None = None):
    results = await get_callbacks(key, token=token, since=since)
    return {"key": key, "token": token, "count": len(results), "callbacks": results}


@app.get("/api/callbacks/{key}")
async def list_callbacks(key: str, since: float | None = None):
    results = await get_callbacks(key, since=since)
    return {"key": key, "count": len(results), "callbacks": results}


@app.delete("/api/callbacks/{key}")
async def clear_callbacks(key: str):
    await delete_callbacks(key)
    return {"status": "cleared", "key": key}


# --- Live WebSocket + Dashboard ---


@app.websocket("/api/ws")
async def live_ws(ws: WebSocket):
    await ws.accept()
    _subscribers.append(ws)
    try:
        while True:
            await ws.receive_text()  # keep alive, ignore input
    except WebSocketDisconnect:
        pass
    finally:
        try:
            _subscribers.remove(ws)
        except ValueError:
            pass


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OOB Callbacks — Live</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#0d1117;color:#c9d1d9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:14px}
  .topbar{background:#161b22;border-bottom:1px solid #30363d;padding:12px 20px;display:flex;align-items:center;gap:16px;position:sticky;top:0;z-index:10}
  .topbar h1{font-size:16px;font-weight:600;color:#58a6ff}
  .dot{width:8px;height:8px;border-radius:50%;background:#3fb950;animation:pulse 2s infinite}
  .dot.dead{background:#f85149;animation:none}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
  .conn-status{font-size:11px;color:#8b949e}
  .filters{display:flex;gap:8px;margin-left:auto}
  .filters input{background:#0d1117;border:1px solid #30363d;color:#c9d1d9;padding:4px 8px;border-radius:4px;font-size:13px;width:120px}
  .filters input:focus{border-color:#58a6ff;outline:none}
  .btn-clear{background:#21262d;border:1px solid #30363d;color:#f85149;padding:4px 12px;border-radius:4px;cursor:pointer;font-size:12px}
  .btn-clear:hover{background:#3a1f1f;border-color:#f85149}
  .stats{padding:8px 20px;background:#161b22;border-bottom:1px solid #30363d;display:flex;gap:24px;font-size:13px;color:#8b949e}
  .stats .val{color:#c9d1d9;font-weight:600}
  #feed{padding:12px 20px;display:flex;flex-direction:column;gap:8px}
  .card{background:#161b22;border:1px solid #30363d;border-radius:8px;overflow:hidden;transition:border-color .2s}
  .card.fresh{border-color:#3fb950;animation:fadeBorder 3s forwards}
  @keyframes fadeBorder{to{border-color:#30363d}}
  .card:hover{border-color:#484f58}
  .card-head{padding:10px 14px;display:flex;align-items:center;gap:10px;cursor:pointer;user-select:none}
  .card-head:hover{background:#1c2129}
  .method{font-size:11px;font-weight:700;padding:2px 8px;border-radius:3px;text-transform:uppercase;flex-shrink:0}
  .method-GET{background:#1f3a2d;color:#3fb950}
  .method-POST{background:#2a1f3a;color:#bc8cff}
  .method-PUT{background:#3a2f1f;color:#d29922}
  .method-DELETE{background:#3a1f1f;color:#f85149}
  .method-PATCH{background:#1f2d3a;color:#58a6ff}
  .method-HEAD,.method-OPTIONS{background:#1f2a2a;color:#8b949e}
  .path{color:#58a6ff;font-family:monospace;font-size:13px;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .meta{display:flex;gap:12px;font-size:12px;color:#8b949e;flex-shrink:0}
  .tag{background:#0d1117;padding:2px 6px;border-radius:3px;font-family:monospace;font-size:11px}
  .tag-key{color:#d29922}
  .tag-token{color:#bc8cff}
  .ip{color:#8b949e;font-family:monospace}
  .ts{color:#484f58}
  .arrow{color:#484f58;transition:transform .2s;font-size:10px}
  .card.open .arrow{transform:rotate(90deg)}
  .card-body{display:none;border-top:1px solid #30363d;padding:14px}
  .card.open .card-body{display:block}
  .section{margin-bottom:12px}
  .section:last-child{margin-bottom:0}
  .section-title{font-size:11px;text-transform:uppercase;color:#8b949e;margin-bottom:6px;font-weight:600;letter-spacing:.5px}
  .kv-grid{display:grid;grid-template-columns:minmax(120px,auto) 1fr;gap:2px 12px;font-size:12px;font-family:monospace}
  .kv-grid .k{color:#8b949e;text-align:right;padding:2px 0;word-break:break-all}
  .kv-grid .v{color:#c9d1d9;padding:2px 0;word-break:break-all}
  .body-content{background:#0d1117;border:1px solid #30363d;border-radius:4px;padding:8px 10px;font-family:monospace;font-size:12px;white-space:pre-wrap;word-break:break-all;max-height:200px;overflow:auto;color:#c9d1d9}
  .empty{text-align:center;padding:60px 20px;color:#484f58;font-size:15px}
  .qp{color:#d29922}
</style>
</head>
<body>
<div class="topbar">
  <div class="dot" id="conn-dot"></div>
  <h1>OOB Callback Monitor</h1>
  <span class="conn-status" id="conn-status">connecting...</span>
  <div class="filters">
    <input type="text" id="filter-key" placeholder="Filter key...">
    <input type="text" id="filter-token" placeholder="Filter token...">
    <input type="text" id="filter-ip" placeholder="Filter IP...">
    <button class="btn-clear" id="btn-clear">Clear Feed</button>
  </div>
</div>
<div class="stats">
  <span>Total: <span class="val" id="stat-total">0</span></span>
  <span>Keys: <span class="val" id="stat-keys">0</span></span>
  <span>Tokens: <span class="val" id="stat-tokens">0</span></span>
  <span>IPs: <span class="val" id="stat-ips">0</span></span>
</div>
<div id="feed"><div class="empty">Waiting for callbacks...</div></div>

<script>
const feed = document.getElementById('feed');
const statTotal = document.getElementById('stat-total');
const statKeys = document.getElementById('stat-keys');
const statTokens = document.getElementById('stat-tokens');
const statIps = document.getElementById('stat-ips');
const filterKey = document.getElementById('filter-key');
const filterToken = document.getElementById('filter-token');
const filterIp = document.getElementById('filter-ip');
const connDot = document.getElementById('conn-dot');
const connStatus = document.getElementById('conn-status');

let entries = [];
const seenKeys = new Set();
const seenTokens = new Set();
const seenIps = new Set();

function fmtTime(ts) {
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString('en-GB', {hour:'2-digit',minute:'2-digit',second:'2-digit'})
    + '.' + String(d.getMilliseconds()).padStart(3,'0');
}

function esc(s) {
  const d = document.createElement('div');
  d.textContent = s || '';
  return d.innerHTML;
}

const SKIP_HEADERS = new Set(['cdn-loop','cf-ew-via','cf-ray','cf-visitor','cf-warp-tag-id','cf-worker','connection','upgrade-insecure-requests','sec-ch-ua','sec-ch-ua-mobile','sec-ch-ua-platform','sec-fetch-dest','sec-fetch-mode','sec-fetch-site','sec-fetch-user','sec-gpc','priority','accept-encoding','cache-control']);

function renderHeaders(hdrs) {
  if (!hdrs || typeof hdrs !== 'object') return '<span style="color:#484f58">none</span>';
  let html = '';
  for (const [k,v] of Object.entries(hdrs)) {
    if (SKIP_HEADERS.has(k.toLowerCase())) continue;
    html += '<div class="k">'+esc(k)+'</div><div class="v">'+esc(v)+'</div>';
  }
  return html || '<span style="color:#484f58">none (all filtered)</span>';
}

function renderQP(qp) {
  if (!qp || Object.keys(qp).length === 0) return '';
  let html = '';
  for (const [k,v] of Object.entries(qp)) {
    html += '<div class="k">'+esc(k)+'</div><div class="v qp">'+esc(v)+'</div>';
  }
  return html;
}

function matchesFilter(e) {
  const fk = filterKey.value.toLowerCase();
  const ft = filterToken.value.toLowerCase();
  const fi = filterIp.value.toLowerCase();
  if (fk && !e.key.toLowerCase().includes(fk)) return false;
  if (ft && !e.token.toLowerCase().includes(ft)) return false;
  if (fi && !e.source_ip.toLowerCase().includes(fi)) return false;
  return true;
}

function buildCard(entry, fresh) {
  const card = document.createElement('div');
  card.className = 'card' + (fresh ? ' fresh' : '');
  const qpStr = entry.query_params && Object.keys(entry.query_params).length
    ? '?' + Object.entries(entry.query_params).map(([k,v])=>k+'='+v).join('&') : '';
  card.innerHTML =
    '<div class="card-head">' +
      '<span class="arrow">&#9654;</span>' +
      '<span class="method method-'+esc(entry.method)+'">'+esc(entry.method)+'</span>' +
      '<span class="path">'+esc(entry.path + qpStr)+'</span>' +
      '<div class="meta">' +
        '<span class="tag tag-key">'+esc(entry.key)+'</span>' +
        '<span class="tag tag-token">'+esc(entry.token)+'</span>' +
        '<span class="ip">'+esc(entry.source_ip)+'</span>' +
        '<span class="ts">'+fmtTime(entry.timestamp)+'</span>' +
      '</div>' +
    '</div>' +
    '<div class="card-body">' +
      '<div class="section"><div class="section-title">Headers</div><div class="kv-grid">'+renderHeaders(entry.headers)+'</div></div>' +
      (entry.body ? '<div class="section"><div class="section-title">Body</div><div class="body-content">'+esc(entry.body)+'</div></div>' : '') +
      (renderQP(entry.query_params) ? '<div class="section"><div class="section-title">Query Params</div><div class="kv-grid">'+renderQP(entry.query_params)+'</div></div>' : '') +
      (entry.extra_path ? '<div class="section"><div class="section-title">Extra Path</div><div class="body-content">'+esc(entry.extra_path)+'</div></div>' : '') +
    '</div>';
  card.querySelector('.card-head').addEventListener('click', () => card.classList.toggle('open'));
  return card;
}

function addEntry(entry) {
  entries.push(entry);
  seenKeys.add(entry.key);
  seenTokens.add(entry.token);
  seenIps.add(entry.source_ip);
  statTotal.textContent = entries.length;
  statKeys.textContent = seenKeys.size;
  statTokens.textContent = seenTokens.size;
  statIps.textContent = seenIps.size;
  if (!matchesFilter(entry)) return;
  const empty = feed.querySelector('.empty');
  if (empty) empty.remove();
  feed.prepend(buildCard(entry, true));
}

function rerender() {
  feed.innerHTML = '';
  let shown = 0;
  for (let i = entries.length - 1; i >= 0; i--) {
    if (matchesFilter(entries[i])) { feed.appendChild(buildCard(entries[i], false)); shown++; }
  }
  if (!shown) feed.innerHTML = '<div class="empty">No matching callbacks</div>';
}

[filterKey, filterToken, filterIp].forEach(el => el.addEventListener('input', rerender));

document.getElementById('btn-clear').addEventListener('click', () => {
  entries = [];
  seenKeys.clear(); seenTokens.clear(); seenIps.clear();
  statTotal.textContent = '0'; statKeys.textContent = '0';
  statTokens.textContent = '0'; statIps.textContent = '0';
  feed.innerHTML = '<div class="empty">Waiting for callbacks...</div>';
});

// WebSocket connection with auto-reconnect
function connect() {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const ws = new WebSocket(proto + '//' + location.host + '/api/ws');
  ws.onopen = () => {
    connDot.classList.remove('dead');
    connStatus.textContent = 'connected';
  };
  ws.onmessage = (e) => {
    try { addEntry(JSON.parse(e.data)); } catch(_){}
  };
  ws.onclose = () => {
    connDot.classList.add('dead');
    connStatus.textContent = 'reconnecting...';
    setTimeout(connect, 3000);
  };
  ws.onerror = () => ws.close();
}
connect();
</script>
</body>
</html>"""


@app.get("/api/live", response_class=HTMLResponse)
async def live_dashboard():
    return DASHBOARD_HTML


# --- Catch-all routes ---


async def _handle_catch_all(request: Request, key: str, token: str, extra: str | None = None):
    body = (await request.body()).decode("utf-8", errors="replace")
    headers = dict(request.headers)
    query_params = dict(request.query_params)

    await store_callback(
        key=key,
        token=token,
        source_ip=request.client.host if request.client else "unknown",
        method=request.method,
        path=str(request.url.path),
        headers=headers,
        body=body,
        query_params=query_params,
        extra_path=extra,
    )

    # Push to all live viewers instantly
    await _broadcast({
        "id": 0,
        "key": key,
        "token": token,
        "timestamp": time.time(),
        "source_ip": request.client.host if request.client else "unknown",
        "method": request.method,
        "path": str(request.url.path),
        "headers": headers,
        "body": body,
        "query_params": query_params,
        "extra_path": extra,
    })

    return {"status": "logged", "key": key, "token": token}


@app.api_route("/{key}/{token}/{extra:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
async def catch_all_with_extra(request: Request, key: str, token: str, extra: str):
    return await _handle_catch_all(request, key, token, extra=extra)


@app.api_route("/{key}/{token}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
async def catch_all(request: Request, key: str, token: str):
    return await _handle_catch_all(request, key, token)
