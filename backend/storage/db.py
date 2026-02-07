import json
import logging
from typing import Optional

import aiosqlite

from config import DB_PATH

log = logging.getLogger(__name__)


async def init_db():
    """Create tables if they don't exist."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS request_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                method TEXT NOT NULL,
                url TEXT NOT NULL,
                host TEXT DEFAULT '',
                path TEXT DEFAULT '',
                request_headers TEXT DEFAULT '{}',
                request_body TEXT DEFAULT '',
                status_code INTEGER DEFAULT 0,
                response_headers TEXT DEFAULT '{}',
                response_body TEXT DEFAULT '',
                content_type TEXT DEFAULT '',
                duration_ms REAL DEFAULT 0,
                session_id TEXT DEFAULT 'default'
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                target_url TEXT NOT NULL,
                injector_type TEXT NOT NULL,
                payload TEXT DEFAULT '',
                injection_point TEXT DEFAULT '',
                original_param TEXT DEFAULT '',
                response_code INTEGER DEFAULT 0,
                response_body TEXT DEFAULT '',
                response_time_ms REAL DEFAULT 0,
                is_vulnerable INTEGER DEFAULT 0,
                confidence TEXT DEFAULT 'low',
                details TEXT DEFAULT '',
                session_id TEXT DEFAULT 'default'
            )
        """)
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_logs_session ON request_logs(session_id)"
        )
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_logs_host ON request_logs(host)"
        )
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_scans_session ON scan_results(session_id)"
        )
        await db.commit()


async def save_request_log(entry: dict) -> int:
    """Persist a request/response log entry. Returns the new row ID."""
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("""
            INSERT INTO request_logs
            (timestamp, method, url, host, path, request_headers, request_body,
             status_code, response_headers, response_body, content_type, duration_ms, session_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            entry.get("timestamp", ""),
            entry.get("method", ""),
            entry.get("url", ""),
            entry.get("host", ""),
            entry.get("path", ""),
            json.dumps(entry.get("request_headers", {})),
            entry.get("request_body", ""),
            entry.get("status_code", 0),
            json.dumps(entry.get("response_headers", {})),
            entry.get("response_body", ""),
            entry.get("content_type", ""),
            entry.get("duration_ms", 0),
            entry.get("session_id", "default"),
        ))
        await db.commit()
        return cursor.lastrowid


async def get_request_logs(
    session_id: str = "default",
    limit: int = 500,
    method_filter: str = None,
    host_filter: str = None,
    status_filter: int = None,
    search: str = None,
) -> list[dict]:
    """Fetch request logs with optional filters."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        query = "SELECT * FROM request_logs WHERE session_id = ?"
        params: list = [session_id]

        if method_filter:
            query += " AND method = ?"
            params.append(method_filter)
        if host_filter:
            query += " AND host LIKE ?"
            params.append(f"%{host_filter}%")
        if status_filter:
            query += " AND status_code = ?"
            params.append(status_filter)
        if search:
            query += " AND (url LIKE ? OR request_body LIKE ? OR response_body LIKE ?)"
            params.extend([f"%{search}%"] * 3)

        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        cursor = await db.execute(query, params)
        rows = await cursor.fetchall()
        results = []
        for row in rows:
            d = dict(row)
            d["request_headers"] = _safe_json(d.get("request_headers", "{}"))
            d["response_headers"] = _safe_json(d.get("response_headers", "{}"))
            results.append(d)
        return results


async def get_request_log_by_id(log_id: int) -> Optional[dict]:
    """Fetch a single log entry by ID."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM request_logs WHERE id = ?", (log_id,)
        )
        row = await cursor.fetchone()
        if row:
            d = dict(row)
            d["request_headers"] = _safe_json(d.get("request_headers", "{}"))
            d["response_headers"] = _safe_json(d.get("response_headers", "{}"))
            return d
        return None


async def clear_request_logs(session_id: str = "default"):
    """Delete all logs for a session."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "DELETE FROM request_logs WHERE session_id = ?", (session_id,)
        )
        await db.commit()


async def save_scan_result(result: dict) -> int:
    """Persist an injection scan result."""
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("""
            INSERT INTO scan_results
            (timestamp, target_url, injector_type, payload, injection_point,
             original_param, response_code, response_body, response_time_ms,
             is_vulnerable, confidence, details, session_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            result.get("timestamp", ""),
            result.get("target_url", ""),
            result.get("injector_type", ""),
            result.get("payload", ""),
            result.get("injection_point", ""),
            result.get("original_param", ""),
            result.get("response_code", 0),
            result.get("response_body", ""),
            result.get("response_time_ms", 0),
            1 if result.get("is_vulnerable") else 0,
            result.get("confidence", "low"),
            result.get("details", ""),
            result.get("session_id", "default"),
        ))
        await db.commit()
        return cursor.lastrowid


async def get_scan_results(
    session_id: str = "default", limit: int = 200
) -> list[dict]:
    """Fetch injection scan results."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM scan_results WHERE session_id = ? ORDER BY id DESC LIMIT ?",
            (session_id, limit),
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]


async def export_session(session_id: str = "default") -> dict:
    """Export all data for a session."""
    logs = await get_request_logs(session_id, limit=10000)
    scans = await get_scan_results(session_id, limit=10000)
    return {"session_id": session_id, "request_logs": logs, "scan_results": scans}


# ── Helpers ────────────────────────────────────────────────────────


def _safe_json(raw: str) -> dict:
    """Parse JSON string, returning empty dict on failure."""
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return {}
