import hashlib
import hmac
import json
import secrets
import time
from contextlib import asynccontextmanager
from http.cookies import SimpleCookie

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, HTTPException, Query, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware

from pathlib import Path

from db import init_db, store_callback, get_callbacks, get_all_callbacks, get_callback_count, delete_callbacks, verify_user, get_ip_summary, get_ip_detail, get_excluded_ips, add_excluded_ip, remove_excluded_ip

# --- Country lookup ---

_COUNTRIES: dict = {}

def _load_countries():
    global _COUNTRIES
    p = Path(__file__).parent / "countries.json"
    if p.exists():
        with open(p, encoding="utf-8") as f:
            _COUNTRIES = json.load(f)

_load_countries()


def _country_for_code(code: str | None) -> dict:
    if not code:
        return {"country_code": None, "country_name": None}
    code = code.upper().strip()
    name = _COUNTRIES.get(code)
    if name:
        return {"country_code": code, "country_name": name}
    return {"country_code": code, "country_name": code}


# --- Session auth ---

# Random signing key generated each server start.
# Sessions invalidate on restart — acceptable for a single-user tool.
_SESSION_SECRET = secrets.token_bytes(32)
_SESSION_MAX_AGE = 60 * 60 * 24 * 7  # 7 days


def _sign_session(username: str, expires: float) -> str:
    payload = f"{username}:{expires}"
    sig = hmac.new(_SESSION_SECRET, payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}:{sig}"


def _verify_session_cookie(cookie_val: str) -> str | None:
    """Return username if valid, None otherwise."""
    parts = cookie_val.split(":")
    if len(parts) != 3:
        return None
    username, expires_str, sig = parts
    try:
        expires = float(expires_str)
    except ValueError:
        return None
    if time.time() > expires:
        return None
    expected = hmac.new(_SESSION_SECRET, f"{username}:{expires_str}".encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    return username


def _get_session_user(request: Request) -> str | None:
    cookie_val = request.cookies.get("session")
    if not cookie_val:
        return None
    return _verify_session_cookie(cookie_val)


def _require_session(request: Request) -> str:
    user = _get_session_user(request)
    if user is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


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


# --- Login ---


LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Login</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@radix-ui/colors@3.0.0/gray-dark.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@radix-ui/colors@3.0.0/red-dark.css">
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--gray-1);color:var(--gray-9);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh}
  body::after{content:'';position:fixed;inset:0;background:radial-gradient(ellipse at 50% 40%,rgba(255,255,255,.02),transparent 70%);pointer-events:none}
  form{width:280px;position:relative;z-index:1}
  input{display:block;width:100%;background:transparent;border:none;border-bottom:1px solid var(--gray-4);color:var(--gray-12);padding:12px 0 8px;font-size:15px;outline:none;transition:border-color .2s;-webkit-text-fill-color:var(--gray-12)}
  input:-webkit-autofill,input:-webkit-autofill:hover,input:-webkit-autofill:focus{-webkit-box-shadow:0 0 0 1000px var(--gray-1) inset;-webkit-text-fill-color:var(--gray-12);transition:background-color 5000s ease-in-out 0s}
  input:focus{border-color:var(--gray-7)}
  input::placeholder{color:var(--gray-6);-webkit-text-fill-color:var(--gray-6)}
  input+input{margin-top:24px}
  button{display:block;width:100%;background:transparent;border:1px solid var(--gray-4);color:var(--gray-9);padding:10px;margin-top:32px;font-size:13px;letter-spacing:.5px;cursor:pointer;transition:all .15s}
  button:hover{border-color:var(--gray-6);color:var(--gray-11)}
  .err{color:var(--red-9);font-size:12px;text-align:center;margin-bottom:16px;opacity:0;transition:opacity .2s}
  .err.on{opacity:1}
</style>
</head>
<body class="dark">
<form id="f">
  <div class="err" id="err">invalid credentials</div>
  <input type="text" name="username" placeholder="username" autocomplete="username" autofocus required>
  <input type="password" name="password" placeholder="password" autocomplete="current-password" required>
  <button type="submit">enter</button>
</form>
<script>
document.getElementById('f').addEventListener('submit', async (e) => {
  e.preventDefault();
  const err = document.getElementById('err');
  err.classList.remove('on');
  const fd = new FormData(e.target);
  try {
    const r = await fetch('/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body: new URLSearchParams({username: fd.get('username'), password: fd.get('password')}),
    });
    if (r.ok) { window.location.href = '/api/live'; }
    else { err.classList.add('on'); }
  } catch(_) { err.classList.add('on'); }
});
</script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if _get_session_user(request):
        return RedirectResponse("/api/live", status_code=302)
    return LOGIN_HTML


@app.post("/login")
async def login_submit(request: Request):
    from urllib.parse import parse_qs
    body = (await request.body()).decode()
    parsed = parse_qs(body)
    username = parsed.get("username", [""])[0]
    password = parsed.get("password", [""])[0]
    if not username or not password or not await verify_user(username, password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    expires = time.time() + _SESSION_MAX_AGE
    cookie_val = _sign_session(username, expires)
    response = Response('{"ok": true}', media_type="application/json")
    response.set_cookie(
        "session", cookie_val,
        max_age=_SESSION_MAX_AGE,
        httponly=False,
        samesite="lax",
        secure=False,  # set True if always behind HTTPS
    )
    return response


@app.get("/logout")
async def logout():
    response = RedirectResponse("/login", status_code=302)
    response.delete_cookie("session")
    return response


# --- API routes (registered first so they take priority) ---


@app.get("/api/health")
async def health(request: Request):
    await _broadcast({
        "id": 0,
        "key": "api",
        "token": "health",
        "timestamp": time.time(),
        "source_ip": request.client.host if request.client else "unknown",
        "method": "GET",
        "path": "/api/health",
        "headers": dict(request.headers),
        "body": "",
        "query_params": dict(request.query_params),
        "extra_path": None,
    })
    return {"status": "ok"}


@app.get("/api/callbacks")
async def list_all_callbacks(
    request: Request,
    limit: int = Query(500, ge=1, le=50000),
    offset: int = Query(0, ge=0),
    exclude: bool = Query(True),
):
    _require_session(request)
    exc_ips = None
    if exclude:
        exc_list = await get_excluded_ips()
        exc_ips = [e["ip"] for e in exc_list] if exc_list else None
    results = await get_all_callbacks(limit=limit, offset=offset, exclude_ips=exc_ips)
    total = await get_callback_count(exclude_ips=exc_ips)
    return {"count": len(results), "total": total, "callbacks": results}


@app.get("/api/callbacks/{key}/{token}")
async def list_callbacks_for_token(key: str, token: str, since: float | None = None):
    results = await get_callbacks(key, token=token, since=since)
    return {"key": key, "token": token, "count": len(results), "callbacks": results}


@app.get("/api/callbacks/{key}")
async def list_callbacks(key: str, since: float | None = None):
    results = await get_callbacks(key, since=since)
    return {"key": key, "count": len(results), "callbacks": results}


@app.delete("/api/callbacks/{key}")
async def clear_callbacks(request: Request, key: str):
    _require_session(request)
    await delete_callbacks(key)
    return {"status": "cleared", "key": key}


# --- IP Analytics API ---


@app.get("/api/ips")
async def list_ips(request: Request):
    _require_session(request)
    results = await get_ip_summary()
    for r in results:
        r.update(_country_for_code(r.pop("country_code", None)))
    return {"count": len(results), "ips": results}


@app.get("/api/ips/{ip}")
async def get_ip_info(
    request: Request,
    ip: str,
    limit: int = Query(500, ge=1, le=50000),
    offset: int = Query(0, ge=0),
):
    _require_session(request)
    result = await get_ip_detail(ip, limit=limit, offset=offset)
    return result


# --- IP Exclusion API ---


@app.get("/api/excluded-ips")
async def list_excluded_ips(request: Request):
    _require_session(request)
    ips = await get_excluded_ips()
    return {"count": len(ips), "ips": ips}


@app.post("/api/excluded-ips")
async def create_excluded_ip(request: Request):
    _require_session(request)
    body = await request.json()
    ip = body.get("ip", "").strip()
    if not ip:
        raise HTTPException(status_code=400, detail="ip is required")
    reason = body.get("reason", "")
    added = await add_excluded_ip(ip, reason)
    return {"status": "added" if added else "already_excluded", "ip": ip}


@app.delete("/api/excluded-ips/{ip}")
async def delete_excluded_ip(request: Request, ip: str):
    _require_session(request)
    removed = await remove_excluded_ip(ip)
    if not removed:
        raise HTTPException(status_code=404, detail="IP not in exclusion list")
    return {"status": "removed", "ip": ip}


# --- Live WebSocket + Dashboard ---


@app.websocket("/api/ws")
async def live_ws(ws: WebSocket, token: str = Query("")):
    # Accept first — closing before accept hangs some proxies (Cloudflare)
    await ws.accept()

    # Try cookie auth first
    cookie_header = ws.headers.get("cookie", "")
    session_val = None
    for part in cookie_header.split(";"):
        part = part.strip()
        if part.startswith("session="):
            session_val = part[len("session="):]
            break
    authed = session_val and _verify_session_cookie(session_val)

    # Fallback: token query param (session cookie value passed explicitly)
    if not authed and token:
        authed = _verify_session_cookie(token)

    if not authed:
        await ws.close(code=4001, reason="Unauthorized")
        return
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
<title>OOB Callbacks</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@radix-ui/colors@3.0.0/gray-dark.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@radix-ui/colors@3.0.0/blue-dark.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@radix-ui/colors@3.0.0/violet-dark.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@radix-ui/colors@3.0.0/amber-dark.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@radix-ui/colors@3.0.0/red-dark.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@radix-ui/colors@3.0.0/green-dark.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@radix-ui/colors@3.0.0/indigo-dark.css">
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--gray-1);color:var(--gray-11);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;font-size:13px}

  /* topbar */
  .bar{position:sticky;top:0;z-index:10;background:var(--gray-1);border-bottom:1px solid var(--gray-3);padding:10px 20px;display:flex;align-items:center;gap:12px}
  .dot{width:7px;height:7px;border-radius:50%;background:var(--green-9);flex-shrink:0}
  .dot.off{background:var(--red-9)}
  @keyframes blink{50%{opacity:.3}}
  .dot:not(.off){animation:blink 2.5s ease-in-out infinite}
  .title{font-size:13px;font-weight:600;color:var(--gray-12);letter-spacing:-.2px}
  .conn{font-size:11px;color:var(--gray-8)}
  .spacer{flex:1}
  .bar input{background:var(--gray-2);border:1px solid var(--gray-4);color:var(--gray-12);padding:5px 10px;border-radius:4px;font-size:12px;width:100px;outline:none;transition:border-color .15s;-webkit-text-fill-color:var(--gray-12)}
  .bar input:-webkit-autofill,.bar input:-webkit-autofill:hover,.bar input:-webkit-autofill:focus{-webkit-box-shadow:0 0 0 1000px var(--gray-2) inset;-webkit-text-fill-color:var(--gray-12);transition:background-color 5000s ease-in-out 0s}
  .bar input:focus{border-color:var(--gray-7)}
  .bar input::placeholder{color:var(--gray-7);-webkit-text-fill-color:var(--gray-7)}
  .bar button,.bar a{background:none;border:1px solid var(--gray-4);color:var(--gray-9);padding:5px 12px;border-radius:4px;font-size:11px;cursor:pointer;text-decoration:none;white-space:nowrap;transition:all .15s}
  .bar button:hover,.bar a:hover{border-color:var(--gray-6);color:var(--gray-11)}
  .bar .del{color:var(--red-9)}
  .bar .del:hover{border-color:var(--red-7);color:var(--red-11)}

  /* stats row */
  .stats{display:flex;gap:1px;background:var(--gray-3);border-bottom:1px solid var(--gray-3)}
  .stat{flex:1;background:var(--gray-1);padding:10px 16px}
  .stat-label{font-size:10px;text-transform:uppercase;letter-spacing:.6px;color:var(--gray-8);margin-bottom:2px}
  .stat-val{font-size:18px;font-weight:600;color:var(--gray-12);font-variant-numeric:tabular-nums}

  /* feed */
  #feed{padding:8px 0}
  .empty{text-align:center;padding:48px 20px;color:var(--gray-7)}

  /* row */
  .row{border-bottom:1px solid var(--gray-3);transition:background .1s}
  .row:hover{background:var(--gray-2)}
  .row-head{display:flex;align-items:center;gap:8px;padding:8px 20px;cursor:pointer;user-select:none}
  .arrow{color:var(--gray-7);font-size:9px;transition:transform .15s;width:12px;text-align:center;flex-shrink:0}
  .row.open .arrow{transform:rotate(90deg)}
  .method{font-size:10px;font-weight:700;text-transform:uppercase;width:52px;text-align:center;padding:2px 0;border-radius:3px;flex-shrink:0}
  .m-GET{background:var(--green-3);color:var(--green-11)}.m-POST{background:var(--violet-3);color:var(--violet-11)}
  .m-PUT{background:var(--amber-3);color:var(--amber-11)}.m-DELETE{background:var(--red-3);color:var(--red-11)}
  .m-PATCH{background:var(--blue-3);color:var(--blue-11)}.m-HEAD,.m-OPTIONS{background:var(--gray-3);color:var(--gray-9)}
  .path{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;color:var(--indigo-11);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .tag{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11px;background:var(--gray-3);padding:1px 6px;border-radius:3px}
  .tag-k{color:var(--amber-11)}.tag-t{color:var(--violet-11)}
  .ip{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11px;color:var(--gray-8);text-decoration:none}
  a.ip:hover{color:var(--gray-11);text-decoration:underline}
  .stat-link{cursor:pointer}
  .stat-link:hover{background:var(--gray-2)}
  .ts{font-size:11px;color:var(--gray-7);white-space:nowrap}
  .meta{display:flex;align-items:center;gap:8px;flex-shrink:0}

  /* detail */
  .detail{display:none;border-top:1px solid var(--gray-3);padding:12px 20px 12px 40px}
  .row.open .detail{display:grid;grid-template-columns:1fr 1fr;gap:16px}
  .sec-title{font-size:10px;text-transform:uppercase;letter-spacing:.5px;color:var(--gray-8);margin-bottom:6px;font-weight:600}
  .kv{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11px;line-height:1.6}
  .kv .k{color:var(--gray-8)}.kv .v{color:var(--gray-11);word-break:break-all}
  .kv .qv{color:var(--amber-11)}
  .pre{background:var(--gray-2);border:1px solid var(--gray-3);border-radius:4px;padding:8px 10px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11px;white-space:pre-wrap;word-break:break-all;max-height:180px;overflow:auto;color:var(--gray-11)}

  /* load more */
  .load-row{text-align:center;padding:12px}
  .load-row button{background:none;border:1px solid var(--gray-4);color:var(--gray-9);padding:6px 20px;border-radius:4px;font-size:12px;cursor:pointer;transition:all .15s}
  .load-row button:hover{border-color:var(--gray-6);color:var(--gray-11)}

  /* exclusion controls */
  .exc-toggle{display:flex;align-items:center;gap:5px;font-size:11px;color:var(--gray-9);cursor:pointer;user-select:none;white-space:nowrap}
  .exc-toggle input{accent-color:var(--red-9);cursor:pointer}
  .exc-btn{background:none;border:1px solid var(--gray-4);color:var(--gray-9);padding:4px 10px;border-radius:4px;font-size:11px;cursor:pointer;transition:all .15s;white-space:nowrap;position:relative}
  .exc-btn:hover{border-color:var(--gray-6);color:var(--gray-11)}
  .exc-badge{background:var(--red-9);color:#fff;font-size:9px;font-weight:700;padding:1px 5px;border-radius:8px;margin-left:4px;min-width:16px;text-align:center;display:inline-block}
  .exc-x{background:none;border:none;color:var(--gray-6);font-size:13px;cursor:pointer;padding:0 2px;margin-left:2px;line-height:1;transition:color .15s;font-weight:700}
  .exc-x:hover{color:var(--red-9)}

  /* exclusion panel */
  .exc-panel{display:none;position:absolute;top:100%;right:0;margin-top:6px;background:var(--gray-2);border:1px solid var(--gray-4);border-radius:6px;width:340px;max-height:400px;overflow:auto;z-index:20;box-shadow:0 4px 16px rgba(0,0,0,.3)}
  .exc-panel.open{display:block}
  .exc-panel-head{padding:10px 12px;border-bottom:1px solid var(--gray-3);display:flex;align-items:center;gap:8px}
  .exc-panel-head input{flex:1;background:var(--gray-1);border:1px solid var(--gray-4);color:var(--gray-12);padding:5px 8px;border-radius:4px;font-size:12px;outline:none}
  .exc-panel-head input::placeholder{color:var(--gray-7)}
  .exc-panel-head button{background:var(--red-3);border:1px solid var(--red-6);color:var(--red-11);padding:5px 10px;border-radius:4px;font-size:11px;cursor:pointer;white-space:nowrap}
  .exc-panel-head button:hover{background:var(--red-4)}
  .exc-list{padding:4px 0}
  .exc-item{display:flex;align-items:center;gap:8px;padding:6px 12px;font-size:12px;border-bottom:1px solid var(--gray-3)}
  .exc-item:last-child{border-bottom:none}
  .exc-item .ip{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--gray-12);flex:1}
  .exc-item .reason{font-size:11px;color:var(--gray-7);max-width:100px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .exc-item .rm{background:none;border:none;color:var(--gray-6);cursor:pointer;font-size:11px;padding:2px 6px;border-radius:3px;transition:all .15s}
  .exc-item .rm:hover{background:var(--red-3);color:var(--red-11)}
  .exc-empty{padding:16px 12px;text-align:center;color:var(--gray-7);font-size:12px}

  /* toast */
  .toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:var(--gray-2);border:1px solid var(--gray-4);color:var(--gray-11);padding:8px 16px;border-radius:6px;font-size:12px;z-index:100;opacity:0;transition:opacity .2s;pointer-events:none}
  .toast.show{opacity:1}
</style>
</head>
<body class="dark">
<div class="bar">
  <div class="dot" id="conn-dot"></div>
  <span class="title">OOB Callbacks</span>
  <span class="conn" id="conn-status">connecting</span>
  <span class="spacer"></span>
  <input type="text" id="filter-key" placeholder="key">
  <input type="text" id="filter-token" placeholder="token">
  <input type="text" id="filter-ip" placeholder="ip">
  <label class="exc-toggle"><input type="checkbox" id="exc-toggle" checked> Hide excluded</label>
  <span style="position:relative">
    <button class="exc-btn" id="exc-manage-btn">Exclusions <span class="exc-badge" id="exc-count">0</span></button>
    <div class="exc-panel" id="exc-panel">
      <div class="exc-panel-head">
        <input type="text" id="exc-add-input" placeholder="Add IP to exclude...">
        <button id="exc-add-btn">Exclude</button>
      </div>
      <div class="exc-list" id="exc-list"></div>
    </div>
  </span>
  <button class="del" id="btn-clear">clear</button>
  <a href="/logout">logout</a>
</div>
<div class="toast" id="toast"></div>
<div class="stats">
  <div class="stat"><div class="stat-label">Loaded</div><div class="stat-val" id="stat-total">0</div></div>
  <div class="stat"><div class="stat-label">In DB</div><div class="stat-val" id="stat-db-total">--</div></div>
  <div class="stat"><div class="stat-label">Keys</div><div class="stat-val" id="stat-keys">0</div></div>
  <div class="stat"><div class="stat-label">Tokens</div><div class="stat-val" id="stat-tokens">0</div></div>
  <div class="stat stat-link" onclick="window.location.href='/api/ip-analytics'" title="View IP analytics"><div class="stat-label">IPs</div><div class="stat-val" id="stat-ips">0</div></div>
</div>
<div id="feed"><div class="empty">loading...</div></div>

<script>
const $=id=>document.getElementById(id);
const feed=$('feed'),statTotal=$('stat-total'),statKeys=$('stat-keys'),statTokens=$('stat-tokens'),statIps=$('stat-ips'),statDbTotal=$('stat-db-total');
const filterKey=$('filter-key'),filterToken=$('filter-token'),filterIp=$('filter-ip'),connDot=$('conn-dot'),connStatus=$('conn-status');
let entries=[];const seenKeys=new Set,seenTokens=new Set,seenIps=new Set;const PAGE=500;let loadedAll=false,dbTotal=0;
const excludedIps=new Set;let hideExcluded=true;

function fmtTime(ts){const d=new Date(ts*1000);return d.toLocaleTimeString('en-GB',{hour:'2-digit',minute:'2-digit',second:'2-digit'})+'.'+String(d.getMilliseconds()).padStart(3,'0')}
function fmtDate(ts){const d=new Date(ts*1000);return d.toLocaleDateString('en-GB',{day:'2-digit',month:'short'})}
function esc(s){const d=document.createElement('div');d.textContent=s||'';return d.innerHTML}

const SKIP=new Set(['cdn-loop','cf-ew-via','cf-ray','cf-visitor','cf-warp-tag-id','cf-worker','connection','upgrade-insecure-requests','sec-ch-ua','sec-ch-ua-mobile','sec-ch-ua-platform','sec-fetch-dest','sec-fetch-mode','sec-fetch-site','sec-fetch-user','sec-gpc','priority','accept-encoding','cache-control']);

function buildRow(e,fresh){
  const row=document.createElement('div');
  row.className='row';
  if(fresh)row.style.borderLeftColor='#22c55e';
  const qp=e.query_params&&Object.keys(e.query_params).length?'?'+Object.entries(e.query_params).map(([k,v])=>k+'='+v).join('&'):'';

  let hdrs='';
  if(e.headers&&typeof e.headers==='object'){for(const[k,v]of Object.entries(e.headers)){if(SKIP.has(k.toLowerCase()))continue;hdrs+='<span class="k">'+esc(k)+': </span><span class="v">'+esc(v)+'</span><br>';}}
  if(!hdrs)hdrs='<span class="k">none</span>';

  let qpHtml='';
  if(e.query_params&&Object.keys(e.query_params).length){for(const[k,v]of Object.entries(e.query_params)){qpHtml+='<span class="k">'+esc(k)+': </span><span class="qv">'+esc(v)+'</span><br>';}}

  row.innerHTML=
    '<div class="row-head">'+
      '<span class="arrow">&#9654;</span>'+
      '<span class="method m-'+esc(e.method)+'">'+esc(e.method)+'</span>'+
      '<span class="path">'+esc(e.path+qp)+'</span>'+
      '<div class="meta">'+
        '<span class="tag tag-k">'+esc(e.key)+'</span>'+
        '<span class="tag tag-t">'+esc(e.token)+'</span>'+
        '<a href="/api/ip-detail/'+encodeURIComponent(e.source_ip)+'" class="ip" onclick="event.stopPropagation()" title="View IP details">'+esc(e.source_ip)+'</a>'+
        '<button class="exc-x" data-ip="'+esc(e.source_ip)+'" onclick="event.stopPropagation();excludeIp(this.dataset.ip)" title="Exclude this IP">&times;</button>'+
        '<span class="ts">'+fmtDate(e.timestamp)+' '+fmtTime(e.timestamp)+'</span>'+
      '</div>'+
    '</div>'+
    '<div class="detail">'+
      '<div><div class="sec-title">Headers</div><div class="kv">'+hdrs+'</div></div>'+
      '<div>'+
        (e.body?'<div class="sec-title">Body</div><div class="pre">'+esc(e.body)+'</div>':'')+
        (qpHtml?'<div class="sec-title" style="'+(e.body?'margin-top:10px':'')+'">Query Params</div><div class="kv">'+qpHtml+'</div>':'')+
        (e.extra_path?'<div class="sec-title" style="margin-top:10px">Extra Path</div><div class="pre">'+esc(e.extra_path)+'</div>':'')+
      '</div>'+
    '</div>';
  row.querySelector('.row-head').addEventListener('click',()=>row.classList.toggle('open'));
  return row;
}

function matchesFilter(e){
  if(hideExcluded&&excludedIps.has(e.source_ip))return false;
  const fk=filterKey.value.toLowerCase(),ft=filterToken.value.toLowerCase(),fi=filterIp.value.toLowerCase();
  if(fk&&!e.key.toLowerCase().includes(fk))return false;
  if(ft&&!e.token.toLowerCase().includes(ft))return false;
  if(fi&&!e.source_ip.toLowerCase().includes(fi))return false;
  return true;
}
let _trueIpCount=0;
function updateStats(){
  statTotal.textContent=entries.length.toLocaleString();
  statKeys.textContent=seenKeys.size.toLocaleString();
  statTokens.textContent=seenTokens.size.toLocaleString();
  statIps.textContent=Math.max(_trueIpCount,seenIps.size).toLocaleString();
  statDbTotal.textContent=dbTotal.toLocaleString();
}
function track(e){seenKeys.add(e.key);seenTokens.add(e.token);if(!seenIps.has(e.source_ip)){seenIps.add(e.source_ip);_trueIpCount=Math.max(_trueIpCount,seenIps.size)}}
function addEntry(e){
  if(hideExcluded&&excludedIps.has(e.source_ip))return;
  entries.push(e);track(e);dbTotal++;updateStats();
  if(!matchesFilter(e))return;
  const em=feed.querySelector('.empty');if(em)em.remove();
  feed.prepend(buildRow(e,true));
}
function rerender(){
  feed.innerHTML='';let n=0;
  for(let i=entries.length-1;i>=0;i--){if(matchesFilter(entries[i])){feed.appendChild(buildRow(entries[i],false));n++}}
  if(!loadedAll){const d=document.createElement('div');d.className='load-row';d.innerHTML='<button>load more</button>';d.querySelector('button').addEventListener('click',loadMore);feed.appendChild(d)}
  if(!n&&loadedAll)feed.innerHTML='<div class="empty">no callbacks</div>';
}
[filterKey,filterToken,filterIp].forEach(el=>el.addEventListener('input',rerender));
$('btn-clear').addEventListener('click',()=>{entries=[];seenKeys.clear();seenTokens.clear();seenIps.clear();updateStats();feed.innerHTML='<div class="empty">waiting for callbacks...</div>'});

function cbUrl(){return '/api/callbacks?limit='+PAGE+'&offset=0&exclude='+hideExcluded}

async function loadHistory(){
  try{
    const [r,ipR,excR]=await Promise.all([
      fetch(cbUrl(),{credentials:'same-origin'}),
      fetch('/api/ips',{credentials:'same-origin'}),
      fetch('/api/excluded-ips',{credentials:'same-origin'})
    ]);
    if(r.status===401){window.location.href='/login';return}
    if(excR.ok){const excData=await excR.json();excludedIps.clear();for(const e of (excData.ips||[]))excludedIps.add(e.ip);renderExcPanel();updateExcCount()}
    if(!r.ok)return;const data=await r.json();
    dbTotal=data.total||data.count||0;
    const items=data.callbacks.reverse();
    for(const e of items){entries.push(e);track(e)}
    if(data.count<PAGE)loadedAll=true;
    if(ipR.ok){const ipData=await ipR.json();_trueIpCount=ipData.count||0}
    updateStats();rerender();
  }catch(e){console.error(e)}
}
async function loadMore(){
  try{
    const r=await fetch('/api/callbacks?limit='+PAGE+'&offset='+entries.length+'&exclude='+hideExcluded,{credentials:'same-origin'});
    if(!r.ok)return;const data=await r.json();
    dbTotal=data.total||dbTotal;
    const items=data.callbacks.reverse();
    for(const e of items){entries.push(e);track(e)}
    if(data.count<PAGE)loadedAll=true;
    updateStats();rerender();
  }catch(e){console.error(e)}
}

// --- Exclusion logic ---
function showToast(msg){const t=$('toast');t.textContent=msg;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2000)}
function updateExcCount(){$('exc-count').textContent=excludedIps.size;$('exc-count').style.display=excludedIps.size?'':'none'}

async function excludeIp(ip){
  try{
    const r=await fetch('/api/excluded-ips',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip})});
    if(!r.ok)return;
    excludedIps.add(ip);updateExcCount();renderExcPanel();showToast('Excluded '+ip);
    if(hideExcluded){entries=[];seenKeys.clear();seenTokens.clear();seenIps.clear();loadedAll=false;loadHistory()}
    else rerender();
  }catch(e){console.error(e)}
}

async function unexcludeIp(ip){
  try{
    const r=await fetch('/api/excluded-ips/'+encodeURIComponent(ip),{method:'DELETE',credentials:'same-origin'});
    if(!r.ok)return;
    excludedIps.delete(ip);updateExcCount();renderExcPanel();showToast('Removed exclusion for '+ip);
    if(hideExcluded){entries=[];seenKeys.clear();seenTokens.clear();seenIps.clear();loadedAll=false;loadHistory()}
    else rerender();
  }catch(e){console.error(e)}
}

function renderExcPanel(){
  const list=$('exc-list');
  if(!excludedIps.size){list.innerHTML='<div class="exc-empty">No excluded IPs</div>';return}
  list.innerHTML='';
  for(const ip of excludedIps){
    const item=document.createElement('div');item.className='exc-item';
    item.innerHTML='<span class="ip">'+esc(ip)+'</span><button class="rm" data-ip="'+esc(ip)+'">remove</button>';
    item.querySelector('.rm').addEventListener('click',function(){unexcludeIp(this.dataset.ip)});
    list.appendChild(item);
  }
}

// Toggle
$('exc-toggle').addEventListener('change',function(){
  hideExcluded=this.checked;
  entries=[];seenKeys.clear();seenTokens.clear();seenIps.clear();loadedAll=false;
  loadHistory();
});

// Manage panel toggle
$('exc-manage-btn').addEventListener('click',function(e){
  e.stopPropagation();$('exc-panel').classList.toggle('open');
});
document.addEventListener('click',function(e){if(!$('exc-panel').contains(e.target)&&e.target!==$('exc-manage-btn'))$('exc-panel').classList.remove('open')});

// Manual add
$('exc-add-btn').addEventListener('click',function(){
  const inp=$('exc-add-input');const ip=inp.value.trim();
  if(!ip)return;inp.value='';excludeIp(ip);
});
$('exc-add-input').addEventListener('keydown',function(e){if(e.key==='Enter'){e.preventDefault();$('exc-add-btn').click()}});

function getCookie(n){const m=document.cookie.match('(^|;)\\s*'+n+'=([^;]*)');return m?m[2]:''}
let _pingInterval=null;
function connect(){
  const tok=encodeURIComponent(getCookie('session'));
  const ws=new WebSocket((location.protocol==='https:'?'wss:':'ws:')+'//'+location.host+'/api/ws?token='+tok);
  ws.onopen=()=>{
    connDot.classList.remove('off');connStatus.textContent='live';
    clearInterval(_pingInterval);
    _pingInterval=setInterval(()=>{try{ws.send('ping')}catch(_){}},30000);
  };
  ws.onmessage=e=>{try{addEntry(JSON.parse(e.data))}catch(_){}};
  ws.onclose=()=>{clearInterval(_pingInterval);connDot.classList.add('off');connStatus.textContent='reconnecting';setTimeout(connect,3000)};
  ws.onerror=()=>ws.close();
}
loadHistory().then(()=>connect());
</script>
</body>
</html>"""


@app.get("/api/live", response_class=HTMLResponse)
async def live_dashboard(request: Request):
    if not _get_session_user(request):
        return RedirectResponse("/login", status_code=302)
    return DASHBOARD_HTML


# --- IP Analytics Pages ---


IP_LIST_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IP Analytics</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@radix-ui/colors@3.0.0/gray-dark.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@radix-ui/colors@3.0.0/blue-dark.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@radix-ui/colors@3.0.0/violet-dark.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@radix-ui/colors@3.0.0/amber-dark.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@radix-ui/colors@3.0.0/red-dark.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@radix-ui/colors@3.0.0/green-dark.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@radix-ui/colors@3.0.0/indigo-dark.css">
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--gray-1);color:var(--gray-11);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;font-size:13px}
  .bar{position:sticky;top:0;z-index:10;background:var(--gray-1);border-bottom:1px solid var(--gray-3);padding:10px 20px;display:flex;align-items:center;gap:12px}
  .bar a{background:none;border:1px solid var(--gray-4);color:var(--gray-9);padding:5px 12px;border-radius:4px;font-size:11px;cursor:pointer;text-decoration:none;white-space:nowrap;transition:all .15s}
  .bar a:hover{border-color:var(--gray-6);color:var(--gray-11)}
  .title{font-size:13px;font-weight:600;color:var(--gray-12);letter-spacing:-.2px}
  .spacer{flex:1}
  .bar input{background:var(--gray-2);border:1px solid var(--gray-4);color:var(--gray-12);padding:5px 10px;border-radius:4px;font-size:12px;width:160px;outline:none;transition:border-color .15s}
  .bar input:focus{border-color:var(--gray-7)}
  .bar input::placeholder{color:var(--gray-7)}
  .stats{display:flex;gap:1px;background:var(--gray-3);border-bottom:1px solid var(--gray-3)}
  .stat{flex:1;background:var(--gray-1);padding:10px 16px}
  .stat-label{font-size:10px;text-transform:uppercase;letter-spacing:.6px;color:var(--gray-8);margin-bottom:2px}
  .stat-val{font-size:18px;font-weight:600;color:var(--gray-12);font-variant-numeric:tabular-nums}
  .stat-val.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:14px}
  table{width:100%;border-collapse:collapse}
  thead{position:sticky;top:45px;z-index:5}
  th{background:var(--gray-2);padding:8px 16px;text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:.5px;color:var(--gray-8);font-weight:600;cursor:pointer;user-select:none;border-bottom:1px solid var(--gray-3);white-space:nowrap}
  th:hover{color:var(--gray-11)}
  th .arrow{font-size:9px;margin-left:4px;opacity:0}
  th.active .arrow{opacity:1}
  td{padding:8px 16px;border-bottom:1px solid var(--gray-3)}
  tr:hover td{background:var(--gray-2)}
  tr{cursor:pointer;transition:background .1s}
  .ip-cell{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;color:var(--indigo-11)}
  .country-cell{font-size:12px;color:var(--gray-11);white-space:nowrap}
  .num{font-variant-numeric:tabular-nums;text-align:right;color:var(--gray-12);font-weight:500}
  .methods{display:flex;gap:4px;flex-wrap:wrap}
  .mbadge{font-size:9px;font-weight:700;text-transform:uppercase;padding:1px 5px;border-radius:3px}
  .mb-GET{background:var(--green-3);color:var(--green-11)}.mb-POST{background:var(--violet-3);color:var(--violet-11)}
  .mb-PUT{background:var(--amber-3);color:var(--amber-11)}.mb-DELETE{background:var(--red-3);color:var(--red-11)}
  .mb-PATCH{background:var(--blue-3);color:var(--blue-11)}.mb-HEAD,.mb-OPTIONS{background:var(--gray-3);color:var(--gray-9)}
  .ts{font-size:11px;color:var(--gray-8);white-space:nowrap}
  .empty{text-align:center;padding:48px 20px;color:var(--gray-7)}
  .pager{display:flex;align-items:center;justify-content:center;gap:6px;padding:12px 20px;border-top:1px solid var(--gray-3);background:var(--gray-1)}
  .pager button{background:var(--gray-2);border:1px solid var(--gray-4);color:var(--gray-9);padding:4px 10px;border-radius:4px;font-size:11px;cursor:pointer;transition:all .15s}
  .pager button:hover:not(:disabled){border-color:var(--gray-6);color:var(--gray-11)}
  .pager button:disabled{opacity:.35;cursor:default}
  .pager button.active{background:var(--gray-4);color:var(--gray-12);border-color:var(--gray-6);font-weight:600}
  .pager .info{font-size:11px;color:var(--gray-8);margin:0 8px}
  .pager select{background:var(--gray-2);border:1px solid var(--gray-4);color:var(--gray-11);padding:4px 6px;border-radius:4px;font-size:11px;cursor:pointer}
</style>
</head>
<body class="dark">
<div class="bar">
  <a href="/api/live">&larr; Dashboard</a>
  <span class="title">IP Analytics</span>
  <span class="spacer"></span>
  <input type="text" id="search" placeholder="search IPs...">
  <a href="/logout">logout</a>
</div>
<div class="stats">
  <div class="stat"><div class="stat-label">Unique IPs</div><div class="stat-val" id="stat-total">--</div></div>
  <div class="stat"><div class="stat-label">Total Callbacks</div><div class="stat-val" id="stat-callbacks">--</div></div>
  <div class="stat"><div class="stat-label">Most Active</div><div class="stat-val mono" id="stat-top">--</div></div>
</div>
<div id="table-wrap">
  <table>
    <thead><tr>
      <th data-sort="source_ip">IP Address <span class="arrow">&#9650;</span></th>
      <th data-sort="country_name">Country <span class="arrow">&#9650;</span></th>
      <th data-sort="callback_count" class="active">Callbacks <span class="arrow">&#9660;</span></th>
      <th data-sort="distinct_keys">Keys <span class="arrow">&#9650;</span></th>
      <th data-sort="distinct_tokens">Tokens <span class="arrow">&#9650;</span></th>
      <th>Methods</th>
      <th data-sort="first_seen">First Seen <span class="arrow">&#9650;</span></th>
      <th data-sort="last_seen">Last Seen <span class="arrow">&#9650;</span></th>
    </tr></thead>
    <tbody id="tbody"></tbody>
  </table>
</div>
<div id="pager" class="pager" style="display:none"></div>
<div id="empty-msg" class="empty" style="display:none">no IP data</div>

<script>
let ipData=[],sortCol='callback_count',sortDir=-1,page=0,perPage=50;
const tbody=document.getElementById('tbody'),searchEl=document.getElementById('search'),pagerEl=document.getElementById('pager');

function fmtTs(ts){
  if(!ts)return '--';
  const d=new Date(ts*1000);
  return d.toLocaleDateString('en-GB',{day:'2-digit',month:'short',year:'numeric'})+' '+d.toLocaleTimeString('en-GB',{hour:'2-digit',minute:'2-digit',second:'2-digit'});
}
function esc(s){const d=document.createElement('div');d.textContent=s||'';return d.innerHTML}

function render(){
  const q=searchEl.value.toLowerCase();
  let filtered=ipData;
  if(q)filtered=ipData.filter(r=>r.source_ip.toLowerCase().includes(q)||(r.country_name||'').toLowerCase().includes(q));
  filtered.sort((a,b)=>{
    let av=a[sortCol],bv=b[sortCol];
    if(typeof av==='string')return sortDir*(av||'').localeCompare(bv||'');
    return sortDir*((av||0)-(bv||0));
  });
  const total=filtered.length;
  const pages=Math.ceil(total/perPage)||1;
  if(page>=pages)page=pages-1;
  if(page<0)page=0;
  const start=page*perPage;
  const slice=filtered.slice(start,start+perPage);

  tbody.innerHTML='';
  if(!total){document.getElementById('empty-msg').style.display='';pagerEl.style.display='none';return}
  document.getElementById('empty-msg').style.display='none';
  for(const r of slice){
    const tr=document.createElement('tr');
    tr.onclick=()=>window.location.href='/api/ip-detail/'+encodeURIComponent(r.source_ip);
    const methods=r.methods.map(m=>'<span class="mbadge mb-'+esc(m)+'">'+esc(m)+'</span>').join('');
    const cc=r.country_name?esc(r.country_name):'<span style="color:var(--gray-7)">--</span>';
    tr.innerHTML=
      '<td class="ip-cell">'+esc(r.source_ip)+'</td>'+
      '<td class="country-cell">'+cc+'</td>'+
      '<td class="num">'+r.callback_count.toLocaleString()+'</td>'+
      '<td class="num">'+r.distinct_keys.toLocaleString()+'</td>'+
      '<td class="num">'+r.distinct_tokens.toLocaleString()+'</td>'+
      '<td><div class="methods">'+methods+'</div></td>'+
      '<td class="ts">'+fmtTs(r.first_seen)+'</td>'+
      '<td class="ts">'+fmtTs(r.last_seen)+'</td>';
    tbody.appendChild(tr);
  }
  renderPager(total,pages);
}

function renderPager(total,pages){
  if(pages<=1&&perPage>=total){pagerEl.style.display='none';return}
  pagerEl.style.display='flex';
  let h='<button '+(page<=0?'disabled':'')+' onclick="page=0;render()">&#171;</button>';
  h+='<button '+(page<=0?'disabled':'')+' onclick="page--;render()">&#8249;</button>';
  const wing=2;
  let lo=Math.max(0,page-wing),hi=Math.min(pages-1,page+wing);
  if(lo>0)h+='<button onclick="page=0;render()"'+(page===0?' class="active"':'')+'>1</button>';
  if(lo>1)h+='<span class="info">...</span>';
  for(let i=lo;i<=hi;i++){
    if(i===0&&lo>0)continue;
    h+='<button onclick="page='+i+';render()"'+(i===page?' class="active"':'')+'>'+( i+1)+'</button>';
  }
  if(hi<pages-2)h+='<span class="info">...</span>';
  if(hi<pages-1)h+='<button onclick="page='+(pages-1)+';render()"'+(page===pages-1?' class="active"':'')+'>'+pages+'</button>';
  h+='<button '+(page>=pages-1?'disabled':'')+' onclick="page++;render()">&#8250;</button>';
  h+='<button '+(page>=pages-1?'disabled':'')+' onclick="page='+(pages-1)+';render()">&#187;</button>';
  h+='<span class="info">'+(page*perPage+1)+'&ndash;'+Math.min((page+1)*perPage,total)+' of '+total+'</span>';
  h+='<select onchange="perPage=+this.value;page=0;render()">';
  for(const n of [25,50,100,250]){h+='<option value="'+n+'"'+(perPage===n?' selected':'')+'>'+n+'/page</option>'}
  h+='</select>';
  pagerEl.innerHTML=h;
}

document.querySelectorAll('th[data-sort]').forEach(th=>{
  th.addEventListener('click',()=>{
    const col=th.dataset.sort;
    if(sortCol===col)sortDir*=-1;else{sortCol=col;sortDir=-1}
    document.querySelectorAll('th[data-sort]').forEach(t=>{t.classList.remove('active');t.querySelector('.arrow').innerHTML='&#9650;'});
    th.classList.add('active');th.querySelector('.arrow').innerHTML=sortDir>0?'&#9650;':'&#9660;';
    page=0;render();
  });
});
searchEl.addEventListener('input',()=>{page=0;render()});

async function load(){
  try{
    const r=await fetch('/api/ips',{credentials:'same-origin'});
    if(r.status===401){window.location.href='/login';return}
    if(!r.ok)return;
    const data=await r.json();
    ipData=data.ips||[];
    document.getElementById('stat-total').textContent=ipData.length.toLocaleString();
    let total=0;
    for(const ip of ipData)total+=ip.callback_count;
    document.getElementById('stat-callbacks').textContent=total.toLocaleString();
    document.getElementById('stat-top').textContent=ipData.length?ipData[0].source_ip:'--';
    render();
  }catch(e){console.error(e)}
}
load();
</script>
</body>
</html>"""


IP_DETAIL_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IP Detail</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@radix-ui/colors@3.0.0/gray-dark.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@radix-ui/colors@3.0.0/blue-dark.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@radix-ui/colors@3.0.0/violet-dark.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@radix-ui/colors@3.0.0/amber-dark.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@radix-ui/colors@3.0.0/red-dark.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@radix-ui/colors@3.0.0/green-dark.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@radix-ui/colors@3.0.0/indigo-dark.css">
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--gray-1);color:var(--gray-11);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;font-size:13px}
  .bar{position:sticky;top:0;z-index:10;background:var(--gray-1);border-bottom:1px solid var(--gray-3);padding:10px 20px;display:flex;align-items:center;gap:8px}
  .bar a{background:none;border:1px solid var(--gray-4);color:var(--gray-9);padding:5px 12px;border-radius:4px;font-size:11px;cursor:pointer;text-decoration:none;white-space:nowrap;transition:all .15s}
  .bar a:hover{border-color:var(--gray-6);color:var(--gray-11)}
  .sep{color:var(--gray-6);font-size:11px}
  .title{font-size:13px;font-weight:600;color:var(--gray-12);letter-spacing:-.2px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
  .spacer{flex:1}
  .stats{display:flex;gap:1px;background:var(--gray-3);border-bottom:1px solid var(--gray-3)}
  .stat{flex:1;background:var(--gray-1);padding:10px 16px}
  .stat-label{font-size:10px;text-transform:uppercase;letter-spacing:.6px;color:var(--gray-8);margin-bottom:2px}
  .stat-val{font-size:18px;font-weight:600;color:var(--gray-12);font-variant-numeric:tabular-nums}

  .grid{display:grid;grid-template-columns:1fr 1fr;gap:1px;background:var(--gray-3);border-bottom:1px solid var(--gray-3)}
  .card{background:var(--gray-1);padding:16px 20px}
  .card.wide{grid-column:1/-1}
  .card-title{font-size:10px;text-transform:uppercase;letter-spacing:.6px;color:var(--gray-8);margin-bottom:10px;font-weight:600}
  canvas{width:100%;display:block;cursor:crosshair}

  .breakdown-item{display:flex;align-items:center;gap:8px;padding:4px 0}
  .breakdown-bar{height:6px;border-radius:3px;min-width:2px}
  .breakdown-label{font-size:12px;color:var(--gray-11);min-width:60px}
  .breakdown-count{font-size:11px;color:var(--gray-8);font-variant-numeric:tabular-nums;margin-left:auto}
  .mbadge{font-size:9px;font-weight:700;text-transform:uppercase;padding:1px 5px;border-radius:3px;min-width:52px;text-align:center;display:inline-block}
  .mb-GET{background:var(--green-3);color:var(--green-11)}.mb-POST{background:var(--violet-3);color:var(--violet-11)}
  .mb-PUT{background:var(--amber-3);color:var(--amber-11)}.mb-DELETE{background:var(--red-3);color:var(--red-11)}
  .mb-PATCH{background:var(--blue-3);color:var(--blue-11)}.mb-HEAD,.mb-OPTIONS{background:var(--gray-3);color:var(--gray-9)}

  .key-item{display:flex;align-items:center;gap:8px;padding:3px 0}
  .key-name{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;color:var(--amber-11)}
  .key-count{font-size:11px;color:var(--gray-8);margin-left:auto;font-variant-numeric:tabular-nums}

  .ua-item{padding:6px 0;border-bottom:1px solid var(--gray-3)}
  .ua-item:last-child{border-bottom:none}
  .ua-str{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11px;color:var(--gray-11);word-break:break-all}
  .ua-count{font-size:10px;color:var(--gray-8);margin-top:2px}

  .section-title{font-size:10px;text-transform:uppercase;letter-spacing:.6px;color:var(--gray-8);font-weight:600;padding:12px 20px 6px;background:var(--gray-1);border-bottom:1px solid var(--gray-3)}

  #feed{padding:0}
  .row{border-bottom:1px solid var(--gray-3);transition:background .1s}
  .row:hover{background:var(--gray-2)}
  .row-head{display:flex;align-items:center;gap:8px;padding:8px 20px;cursor:pointer;user-select:none}
  .arrow{color:var(--gray-7);font-size:9px;transition:transform .15s;width:12px;text-align:center;flex-shrink:0}
  .row.open .arrow{transform:rotate(90deg)}
  .method{font-size:10px;font-weight:700;text-transform:uppercase;width:52px;text-align:center;padding:2px 0;border-radius:3px;flex-shrink:0}
  .m-GET{background:var(--green-3);color:var(--green-11)}.m-POST{background:var(--violet-3);color:var(--violet-11)}
  .m-PUT{background:var(--amber-3);color:var(--amber-11)}.m-DELETE{background:var(--red-3);color:var(--red-11)}
  .m-PATCH{background:var(--blue-3);color:var(--blue-11)}.m-HEAD,.m-OPTIONS{background:var(--gray-3);color:var(--gray-9)}
  .path{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;color:var(--indigo-11);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .tag{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11px;background:var(--gray-3);padding:1px 6px;border-radius:3px}
  .tag-k{color:var(--amber-11)}.tag-t{color:var(--violet-11)}
  .ts{font-size:11px;color:var(--gray-7);white-space:nowrap}
  .meta{display:flex;align-items:center;gap:8px;flex-shrink:0}
  .detail{display:none;border-top:1px solid var(--gray-3);padding:12px 20px 12px 40px}
  .row.open .detail{display:grid;grid-template-columns:1fr 1fr;gap:16px}
  .sec-title{font-size:10px;text-transform:uppercase;letter-spacing:.5px;color:var(--gray-8);margin-bottom:6px;font-weight:600}
  .kv{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11px;line-height:1.6}
  .kv .k{color:var(--gray-8)}.kv .v{color:var(--gray-11);word-break:break-all}
  .kv .qv{color:var(--amber-11)}
  .pre{background:var(--gray-2);border:1px solid var(--gray-3);border-radius:4px;padding:8px 10px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11px;white-space:pre-wrap;word-break:break-all;max-height:180px;overflow:auto;color:var(--gray-11)}
  .load-row{text-align:center;padding:12px}
  .load-row button{background:none;border:1px solid var(--gray-4);color:var(--gray-9);padding:6px 20px;border-radius:4px;font-size:12px;cursor:pointer;transition:all .15s}
  .load-row button:hover{border-color:var(--gray-6);color:var(--gray-11)}
  .empty{text-align:center;padding:48px 20px;color:var(--gray-7)}
</style>
</head>
<body class="dark">
<div class="bar">
  <a href="/api/live">&larr; Dashboard</a>
  <span class="sep">/</span>
  <a href="/api/ip-analytics">IP Analytics</a>
  <span class="sep">/</span>
  <span class="title" id="ip-title">--</span>
  <span class="spacer"></span>
  <a href="/logout">logout</a>
</div>
<div class="stats">
  <div class="stat"><div class="stat-label">Total Callbacks</div><div class="stat-val" id="s-total">--</div></div>
  <div class="stat"><div class="stat-label">First Seen</div><div class="stat-val" id="s-first" style="font-size:14px">--</div></div>
  <div class="stat"><div class="stat-label">Last Seen</div><div class="stat-val" id="s-last" style="font-size:14px">--</div></div>
  <div class="stat"><div class="stat-label">Unique Keys</div><div class="stat-val" id="s-keys">--</div></div>
  <div class="stat"><div class="stat-label">Unique Paths</div><div class="stat-val" id="s-paths">--</div></div>
</div>
<div class="grid">
  <div class="card wide" style="position:relative"><div class="card-title">Activity Over Time</div><canvas id="chart" height="170"></canvas><div id="chart-tip" style="display:none;position:absolute;pointer-events:none;background:var(--gray-1);border:1px solid var(--gray-4);border-radius:6px;padding:6px 10px;font-size:11px;color:var(--gray-11);box-shadow:0 2px 8px rgba(0,0,0,.12);z-index:20;white-space:nowrap"></div></div>
  <div class="card"><div class="card-title">Methods Used</div><div id="method-bd"></div></div>
  <div class="card"><div class="card-title">Keys Targeted</div><div id="key-bd"></div></div>
  <div class="card wide"><div class="card-title">User Agents</div><div id="ua-bd"></div></div>
</div>
<div class="section-title" id="cb-title">Callbacks</div>
<div id="feed"><div class="empty">loading...</div></div>

<script>
const PAGE=500;
let callbacks=[],loadedAll=false,totalCb=0;

function fmtTime(ts){const d=new Date(ts*1000);return d.toLocaleTimeString('en-GB',{hour:'2-digit',minute:'2-digit',second:'2-digit'})+'.'+String(d.getMilliseconds()).padStart(3,'0')}
function fmtDate(ts){const d=new Date(ts*1000);return d.toLocaleDateString('en-GB',{day:'2-digit',month:'short'})}
function fmtFull(ts){if(!ts)return'--';const d=new Date(ts*1000);return d.toLocaleDateString('en-GB',{day:'2-digit',month:'short',year:'numeric'})+' '+d.toLocaleTimeString('en-GB',{hour:'2-digit',minute:'2-digit'})}
function esc(s){const d=document.createElement('div');d.textContent=s||'';return d.innerHTML}
const SKIP=new Set(['cdn-loop','cf-ew-via','cf-ray','cf-visitor','cf-warp-tag-id','cf-worker','connection','upgrade-insecure-requests','sec-ch-ua','sec-ch-ua-mobile','sec-ch-ua-platform','sec-fetch-dest','sec-fetch-mode','sec-fetch-site','sec-fetch-user','sec-gpc','priority','accept-encoding','cache-control']);

function buildRow(e){
  const row=document.createElement('div');row.className='row';
  const qp=e.query_params&&Object.keys(e.query_params).length?'?'+Object.entries(e.query_params).map(([k,v])=>k+'='+v).join('&'):'';
  let hdrs='';
  if(e.headers&&typeof e.headers==='object'){for(const[k,v]of Object.entries(e.headers)){if(SKIP.has(k.toLowerCase()))continue;hdrs+='<span class="k">'+esc(k)+': </span><span class="v">'+esc(v)+'</span><br>';}}
  if(!hdrs)hdrs='<span class="k">none</span>';
  let qpHtml='';
  if(e.query_params&&Object.keys(e.query_params).length){for(const[k,v]of Object.entries(e.query_params)){qpHtml+='<span class="k">'+esc(k)+': </span><span class="qv">'+esc(v)+'</span><br>';}}
  row.innerHTML=
    '<div class="row-head">'+
      '<span class="arrow">&#9654;</span>'+
      '<span class="method m-'+esc(e.method)+'">'+esc(e.method)+'</span>'+
      '<span class="path">'+esc(e.path+qp)+'</span>'+
      '<div class="meta">'+
        '<span class="tag tag-k">'+esc(e.key)+'</span>'+
        '<span class="tag tag-t">'+esc(e.token)+'</span>'+
        '<span class="ts">'+fmtDate(e.timestamp)+' '+fmtTime(e.timestamp)+'</span>'+
      '</div>'+
    '</div>'+
    '<div class="detail">'+
      '<div><div class="sec-title">Headers</div><div class="kv">'+hdrs+'</div></div>'+
      '<div>'+
        (e.body?'<div class="sec-title">Body</div><div class="pre">'+esc(e.body)+'</div>':'')+
        (qpHtml?'<div class="sec-title" style="'+(e.body?'margin-top:10px':'')+'">Query Params</div><div class="kv">'+qpHtml+'</div>':'')+
        (e.extra_path?'<div class="sec-title" style="margin-top:10px">Extra Path</div><div class="pre">'+esc(e.extra_path)+'</div>':'')+
      '</div>'+
    '</div>';
  row.querySelector('.row-head').addEventListener('click',()=>row.classList.toggle('open'));
  return row;
}

function renderFeed(){
  const feed=document.getElementById('feed');
  feed.innerHTML='';
  for(const e of callbacks)feed.appendChild(buildRow(e));
  if(!loadedAll){const d=document.createElement('div');d.className='load-row';d.innerHTML='<button>load more</button>';d.querySelector('button').addEventListener('click',loadMore);feed.appendChild(d)}
  if(!callbacks.length&&loadedAll)feed.innerHTML='<div class="empty">no callbacks from this IP</div>';
  document.getElementById('cb-title').textContent='Callbacks ('+callbacks.length+(loadedAll?'':' of '+totalCb)+')';
}

let _chartBuckets=[];
function drawChart(histogram){
  const canvas=document.getElementById('chart'),ctx=canvas.getContext('2d');
  const tip=document.getElementById('chart-tip');
  const dpr=window.devicePixelRatio||1;
  const rect=canvas.getBoundingClientRect();
  canvas.width=rect.width*dpr;canvas.height=rect.height*dpr;
  ctx.scale(dpr,dpr);
  const W=rect.width,H=rect.height;
  const cs=getComputedStyle(document.body);
  const labelColor=cs.getPropertyValue('--gray-7').trim()||'#666';
  const barColor=cs.getPropertyValue('--indigo-9').trim()||'#6366f1';
  const fillColor=(cs.getPropertyValue('--indigo-4').trim()||'#c7d2fe')+'80';
  const gridColor=cs.getPropertyValue('--gray-3').trim()||'#e5e5e5';

  if(!histogram.length){ctx.fillStyle=labelColor;ctx.font='12px system-ui';ctx.textAlign='center';ctx.fillText('no activity data',W/2,H/2);_chartBuckets=[];return}

  // determine bucket size based on time span
  const tMin=histogram[0].timestamp,tMax=histogram[histogram.length-1].timestamp;
  const spanH=(tMax-tMin)/3600;
  let bucketSec=3600; // 1h default (from DB)
  if(spanH>24*60) bucketSec=3600*24*7; // >60d -> weekly
  else if(spanH>24*14) bucketSec=3600*24; // >14d -> daily
  else if(spanH>48) bucketSec=3600*4; // >2d -> 4h

  // re-bucket if needed and fill gaps
  const srcMap={};
  for(const h of histogram) srcMap[h.timestamp]=(srcMap[h.timestamp]||0)+h.count;
  const bStart=Math.floor(tMin/bucketSec)*bucketSec;
  const bEnd=Math.floor(tMax/bucketSec)*bucketSec;
  const buckets=[];
  for(let t=bStart;t<=bEnd;t+=bucketSec){
    let count=0;
    // sum all source hours that fall into this bucket
    for(let s=t;s<t+bucketSec;s+=3600){
      if(srcMap[s]) count+=srcMap[s];
    }
    buckets.push({timestamp:t,count});
  }
  if(!buckets.length){buckets.push(histogram[0])}
  _chartBuckets=buckets;

  // layout
  const ML=44,MR=12,MT=12,MB=28; // margins
  const plotW=W-ML-MR,plotH=H-MT-MB;
  const maxC=Math.max(...buckets.map(b=>b.count),1);

  // nice Y ticks
  const rawStep=maxC/4;
  const mag=Math.pow(10,Math.floor(Math.log10(rawStep||1)));
  const niceStep=Math.ceil(rawStep/mag)*mag||1;
  const yMax=Math.ceil(maxC/niceStep)*niceStep;

  // draw grid + Y labels
  ctx.textBaseline='middle';ctx.textAlign='right';ctx.font='10px system-ui';
  for(let v=0;v<=yMax;v+=niceStep){
    const y=MT+plotH-(v/yMax)*plotH;
    ctx.strokeStyle=gridColor;ctx.lineWidth=0.5;
    ctx.beginPath();ctx.moveTo(ML,y);ctx.lineTo(ML+plotW,y);ctx.stroke();
    ctx.fillStyle=labelColor;
    ctx.fillText(v>=1000?(v/1000).toFixed(v%1000?1:0)+'k':String(v),ML-6,y);
  }

  // area fill + line
  const n=buckets.length;
  const xStep=n>1?plotW/(n-1):plotW;
  const pts=buckets.map((b,i)=>{
    const x=ML+(n>1?i*xStep:plotW/2);
    const y=MT+plotH-(b.count/yMax)*plotH;
    return{x,y};
  });

  // filled area
  ctx.beginPath();
  ctx.moveTo(pts[0].x,MT+plotH);
  for(const p of pts) ctx.lineTo(p.x,p.y);
  ctx.lineTo(pts[pts.length-1].x,MT+plotH);
  ctx.closePath();
  ctx.fillStyle=fillColor;ctx.fill();

  // line
  ctx.beginPath();
  ctx.moveTo(pts[0].x,pts[0].y);
  for(let i=1;i<pts.length;i++) ctx.lineTo(pts[i].x,pts[i].y);
  ctx.strokeStyle=barColor;ctx.lineWidth=1.5;ctx.stroke();

  // dots
  for(const p of pts){
    if(n>80) break; // skip dots if too many points
    ctx.beginPath();ctx.arc(p.x,p.y,2,0,Math.PI*2);ctx.fillStyle=barColor;ctx.fill();
  }

  // X labels
  ctx.fillStyle=labelColor;ctx.font='10px system-ui';ctx.textAlign='center';ctx.textBaseline='top';
  const labelCount=Math.min(n,Math.floor(plotW/90));
  const labelStep=Math.max(1,Math.floor(n/(labelCount||1)));
  for(let i=0;i<n;i+=labelStep){
    const b=buckets[i];
    const x=ML+(n>1?i*xStep:plotW/2);
    const d=new Date(b.timestamp*1000);
    let label;
    if(bucketSec>=86400) label=d.toLocaleDateString('en-GB',{day:'2-digit',month:'short'});
    else label=d.toLocaleDateString('en-GB',{day:'2-digit',month:'short'})+' '+d.toLocaleTimeString('en-GB',{hour:'2-digit',minute:'2-digit'});
    ctx.fillText(label,x,H-MB+6);
  }

  // hover
  canvas.onmousemove=function(e){
    const cr=canvas.getBoundingClientRect();
    const mx=e.clientX-cr.left,my=e.clientY-cr.top;
    if(mx<ML||mx>ML+plotW||my<MT||my>MT+plotH){tip.style.display='none';return}
    let closest=0,closestDist=Infinity;
    for(let i=0;i<pts.length;i++){
      const d=Math.abs(pts[i].x-mx);
      if(d<closestDist){closestDist=d;closest=i}
    }
    const b=buckets[closest];
    const bd=new Date(b.timestamp*1000);
    let tLabel=bd.toLocaleDateString('en-GB',{day:'2-digit',month:'short',year:'numeric'})+' '+bd.toLocaleTimeString('en-GB',{hour:'2-digit',minute:'2-digit'});
    tip.innerHTML='<div style="font-weight:600;color:var(--gray-12)">'+b.count+' callback'+(b.count!==1?'s':'')+'</div><div style="color:var(--gray-8);font-size:10px;margin-top:2px">'+tLabel+'</div>';
    let tx=e.clientX-cr.left+12,ty=e.clientY-cr.top-40;
    if(tx+140>W)tx=e.clientX-cr.left-150;
    if(ty<0)ty=e.clientY-cr.top+16;
    tip.style.display='';tip.style.left=tx+'px';tip.style.top=ty+'px';
  };
  canvas.onmouseleave=function(){tip.style.display='none'};
}

function renderMethodBreakdown(cbs){
  const counts={};
  for(const c of cbs)counts[c.method]=(counts[c.method]||0)+1;
  const sorted=Object.entries(counts).sort((a,b)=>b[1]-a[1]);
  const max=sorted.length?sorted[0][1]:1;
  const el=document.getElementById('method-bd');
  el.innerHTML='';
  for(const[method,count]of sorted){
    const pct=Math.round((count/max)*100);
    el.innerHTML+=
      '<div class="breakdown-item">'+
        '<span class="mbadge mb-'+esc(method)+'">'+esc(method)+'</span>'+
        '<div style="flex:1;background:var(--gray-3);border-radius:3px;height:6px">'+
          '<div class="breakdown-bar" style="width:'+pct+'%;background:var(--indigo-9)"></div>'+
        '</div>'+
        '<span class="breakdown-count">'+count.toLocaleString()+'</span>'+
      '</div>';
  }
  if(!sorted.length)el.innerHTML='<span style="color:var(--gray-7)">none</span>';
}

function renderKeyBreakdown(cbs){
  const counts={};
  for(const c of cbs)counts[c.key]=(counts[c.key]||0)+1;
  const sorted=Object.entries(counts).sort((a,b)=>b[1]-a[1]);
  const el=document.getElementById('key-bd');
  el.innerHTML='';
  for(const[key,count]of sorted.slice(0,20)){
    el.innerHTML+='<div class="key-item"><span class="key-name">'+esc(key)+'</span><span class="key-count">'+count.toLocaleString()+'</span></div>';
  }
  if(sorted.length>20)el.innerHTML+='<div class="key-item" style="color:var(--gray-7)">+'+(sorted.length-20)+' more</div>';
  if(!sorted.length)el.innerHTML='<span style="color:var(--gray-7)">none</span>';
}

function renderUABreakdown(cbs){
  const counts={};
  for(const c of cbs){
    const ua=(c.headers&&(c.headers['user-agent']||c.headers['User-Agent']))||'(none)';
    counts[ua]=(counts[ua]||0)+1;
  }
  const sorted=Object.entries(counts).sort((a,b)=>b[1]-a[1]);
  const el=document.getElementById('ua-bd');
  el.innerHTML='';
  for(const[ua,count]of sorted.slice(0,10)){
    el.innerHTML+='<div class="ua-item"><div class="ua-str">'+esc(ua)+'</div><div class="ua-count">'+count.toLocaleString()+' request'+(count!==1?'s':'')+'</div></div>';
  }
  if(sorted.length>10)el.innerHTML+='<div class="ua-item" style="color:var(--gray-7)">+'+(sorted.length-10)+' more unique user agents</div>';
  if(!sorted.length)el.innerHTML='<span style="color:var(--gray-7)">none</span>';
}

const ipAddr=decodeURIComponent(window.location.pathname.replace('/api/ip-detail/',''));
document.getElementById('ip-title').textContent=ipAddr;
document.title='IP: '+ipAddr;

async function load(){
  try{
    const r=await fetch('/api/ips/'+encodeURIComponent(ipAddr),{credentials:'same-origin'});
    if(r.status===401){window.location.href='/login';return}
    if(!r.ok){document.getElementById('feed').innerHTML='<div class="empty">IP not found</div>';return}
    const data=await r.json();
    totalCb=data.total_callbacks||0;
    document.getElementById('s-total').textContent=totalCb.toLocaleString();
    document.getElementById('s-first').textContent=fmtFull(data.first_seen);
    document.getElementById('s-last').textContent=fmtFull(data.last_seen);
    document.getElementById('s-keys').textContent=(data.distinct_keys||0).toLocaleString();
    document.getElementById('s-paths').textContent=(data.distinct_paths||0).toLocaleString();
    callbacks=data.callbacks||[];
    if(data.returned<PAGE)loadedAll=true;
    window._hist=data.histogram||[];
    drawChart(window._hist);
    renderMethodBreakdown(callbacks);
    renderKeyBreakdown(callbacks);
    renderUABreakdown(callbacks);
    renderFeed();
  }catch(e){console.error(e)}
}

async function loadMore(){
  try{
    const r=await fetch('/api/ips/'+encodeURIComponent(ipAddr)+'?limit='+PAGE+'&offset='+callbacks.length,{credentials:'same-origin'});
    if(!r.ok)return;
    const data=await r.json();
    const newCbs=data.callbacks||[];
    callbacks=callbacks.concat(newCbs);
    if(newCbs.length<PAGE)loadedAll=true;
    renderMethodBreakdown(callbacks);
    renderKeyBreakdown(callbacks);
    renderUABreakdown(callbacks);
    renderFeed();
  }catch(e){console.error(e)}
}

load();
window.addEventListener('resize',()=>{const data=window._hist;if(data)drawChart(data)});
</script>
</body>
</html>"""


@app.get("/api/ip-analytics", response_class=HTMLResponse)
async def ip_list_page(request: Request):
    if not _get_session_user(request):
        return RedirectResponse("/login", status_code=302)
    return IP_LIST_HTML


@app.get("/api/ip-detail/{ip}", response_class=HTMLResponse)
async def ip_detail_page(request: Request, ip: str):
    if not _get_session_user(request):
        return RedirectResponse("/login", status_code=302)
    return IP_DETAIL_HTML


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
