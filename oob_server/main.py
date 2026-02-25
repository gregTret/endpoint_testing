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

from db import init_db, store_callback, get_callbacks, get_all_callbacks, get_callback_count, delete_callbacks, verify_user

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
):
    _require_session(request)
    results = await get_all_callbacks(limit=limit, offset=offset)
    total = await get_callback_count()
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
  .ip{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11px;color:var(--gray-8)}
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
  <button class="del" id="btn-clear">clear</button>
  <a href="/logout">logout</a>
</div>
<div class="stats">
  <div class="stat"><div class="stat-label">Loaded</div><div class="stat-val" id="stat-total">0</div></div>
  <div class="stat"><div class="stat-label">In DB</div><div class="stat-val" id="stat-db-total">--</div></div>
  <div class="stat"><div class="stat-label">Keys</div><div class="stat-val" id="stat-keys">0</div></div>
  <div class="stat"><div class="stat-label">Tokens</div><div class="stat-val" id="stat-tokens">0</div></div>
  <div class="stat"><div class="stat-label">IPs</div><div class="stat-val" id="stat-ips">0</div></div>
</div>
<div id="feed"><div class="empty">loading...</div></div>

<script>
const $=id=>document.getElementById(id);
const feed=$('feed'),statTotal=$('stat-total'),statKeys=$('stat-keys'),statTokens=$('stat-tokens'),statIps=$('stat-ips'),statDbTotal=$('stat-db-total');
const filterKey=$('filter-key'),filterToken=$('filter-token'),filterIp=$('filter-ip'),connDot=$('conn-dot'),connStatus=$('conn-status');
let entries=[];const seenKeys=new Set,seenTokens=new Set,seenIps=new Set;const PAGE=500;let loadedAll=false,dbTotal=0;

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
        '<span class="ip">'+esc(e.source_ip)+'</span>'+
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
  const fk=filterKey.value.toLowerCase(),ft=filterToken.value.toLowerCase(),fi=filterIp.value.toLowerCase();
  if(fk&&!e.key.toLowerCase().includes(fk))return false;
  if(ft&&!e.token.toLowerCase().includes(ft))return false;
  if(fi&&!e.source_ip.toLowerCase().includes(fi))return false;
  return true;
}
function updateStats(){
  statTotal.textContent=entries.length.toLocaleString();
  statKeys.textContent=seenKeys.size.toLocaleString();
  statTokens.textContent=seenTokens.size.toLocaleString();
  statIps.textContent=seenIps.size.toLocaleString();
  statDbTotal.textContent=dbTotal.toLocaleString();
}
function track(e){seenKeys.add(e.key);seenTokens.add(e.token);seenIps.add(e.source_ip)}
function addEntry(e){
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

async function loadHistory(){
  try{
    const r=await fetch('/api/callbacks?limit='+PAGE+'&offset=0',{credentials:'same-origin'});
    if(r.status===401){window.location.href='/login';return}
    if(!r.ok)return;const data=await r.json();
    dbTotal=data.total||data.count||0;
    const items=data.callbacks.reverse();
    for(const e of items){entries.push(e);track(e)}
    if(data.count<PAGE)loadedAll=true;
    updateStats();rerender();
  }catch(e){console.error(e)}
}
async function loadMore(){
  try{
    const r=await fetch('/api/callbacks?limit='+PAGE+'&offset='+entries.length,{credentials:'same-origin'});
    if(!r.ok)return;const data=await r.json();
    dbTotal=data.total||dbTotal;
    const items=data.callbacks.reverse();
    for(const e of items){entries.push(e);track(e)}
    if(data.count<PAGE)loadedAll=true;
    updateStats();rerender();
  }catch(e){console.error(e)}
}
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
