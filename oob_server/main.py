from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from db import init_db, store_callback, get_callbacks, delete_callbacks


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
    return {"status": "logged", "key": key, "token": token}


@app.api_route("/{key}/{token}/{extra:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
async def catch_all_with_extra(request: Request, key: str, token: str, extra: str):
    return await _handle_catch_all(request, key, token, extra=extra)


@app.api_route("/{key}/{token}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
async def catch_all(request: Request, key: str, token: str):
    return await _handle_catch_all(request, key, token)
