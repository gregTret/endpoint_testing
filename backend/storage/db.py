import json
import logging
from typing import Optional

import aiosqlite

from config import DB_PATH

log = logging.getLogger(__name__)


async def init_db():
    """Create tables if they don't exist."""
    async with aiosqlite.connect(DB_PATH) as db:
        # ── Workspaces ──
        await db.execute("""
            CREATE TABLE IF NOT EXISTS workspaces (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_opened_at TEXT NOT NULL
            )
        """)

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
        await db.execute("""
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                site TEXT NOT NULL,
                username TEXT DEFAULT '',
                password TEXT DEFAULT '',
                token TEXT DEFAULT '',
                auth_type TEXT DEFAULT 'basic',
                notes TEXT DEFAULT '',
                workspace_id TEXT DEFAULT 'default',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
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
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_creds_site ON credentials(site)"
        )

        # Migration: add workspace_id to credentials if missing (must run before index)
        try:
            await db.execute("SELECT workspace_id FROM credentials LIMIT 1")
        except Exception:
            await db.execute("ALTER TABLE credentials ADD COLUMN workspace_id TEXT DEFAULT 'default'")
            log.info("migrated credentials table: added workspace_id column")

        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_creds_workspace ON credentials(workspace_id)"
        )

        # Migration: add request_headers / request_body to scan_results if missing
        try:
            await db.execute("SELECT request_headers FROM scan_results LIMIT 1")
        except Exception:
            await db.execute("ALTER TABLE scan_results ADD COLUMN request_headers TEXT DEFAULT ''")
            await db.execute("ALTER TABLE scan_results ADD COLUMN request_body TEXT DEFAULT ''")
            log.info("migrated scan_results table: added request_headers, request_body")

        # Migration: add workspace_id to scan_results if missing
        try:
            await db.execute("SELECT workspace_id FROM scan_results LIMIT 1")
        except Exception:
            await db.execute("ALTER TABLE scan_results ADD COLUMN workspace_id TEXT DEFAULT 'default'")
            log.info("migrated scan_results table: added workspace_id")

        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_scans_workspace ON scan_results(workspace_id)"
        )

        # ── Site Map URLs (persistent per workspace) ──
        await db.execute("""
            CREATE TABLE IF NOT EXISTS sitemap_urls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                workspace_id TEXT DEFAULT 'default',
                added_at TEXT NOT NULL,
                UNIQUE(url, workspace_id)
            )
        """)
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_sitemap_workspace ON sitemap_urls(workspace_id)"
        )

        await db.commit()


# ── Workspace CRUD ────────────────────────────────────────────────


async def create_workspace(workspace_id: str, name: str) -> dict:
    """Create a new workspace."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO workspaces (id, name, created_at, last_opened_at) VALUES (?, ?, ?, ?)",
            (workspace_id, name, now, now),
        )
        await db.commit()
    return {"id": workspace_id, "name": name, "created_at": now, "last_opened_at": now}


async def list_workspaces() -> list[dict]:
    """Return all workspaces, most recently opened first."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM workspaces ORDER BY last_opened_at DESC")
        return [dict(row) for row in await cursor.fetchall()]


async def update_workspace_opened(workspace_id: str) -> None:
    """Touch the last_opened_at timestamp."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE workspaces SET last_opened_at = ? WHERE id = ?", (now, workspace_id)
        )
        await db.commit()


async def rename_workspace(workspace_id: str, name: str) -> None:
    """Rename a workspace."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("UPDATE workspaces SET name = ? WHERE id = ?", (name, workspace_id))
        await db.commit()


async def delete_workspace(workspace_id: str) -> None:
    """Delete a workspace and CASCADE all its data."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM request_logs WHERE session_id = ?", (workspace_id,))
        await db.execute("DELETE FROM scan_results WHERE workspace_id = ?", (workspace_id,))
        await db.execute("DELETE FROM credentials WHERE workspace_id = ?", (workspace_id,))
        await db.execute("DELETE FROM sitemap_urls WHERE workspace_id = ?", (workspace_id,))
        await db.execute("DELETE FROM workspaces WHERE id = ?", (workspace_id,))
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
             is_vulnerable, confidence, details, session_id,
             request_headers, request_body, workspace_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            result.get("request_headers", ""),
            result.get("request_body", ""),
            result.get("workspace_id", "default"),
        ))
        await db.commit()
        return cursor.lastrowid


async def get_scan_results(
    session_id: str = "default", limit: int = 200
) -> list[dict]:
    """Fetch injection scan results by scan session_id (for live polling)."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM scan_results WHERE session_id = ? ORDER BY id DESC LIMIT ?",
            (session_id, limit),
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]


async def get_scan_results_by_workspace(
    workspace_id: str = "default", limit: int = 500
) -> list[dict]:
    """Fetch all injection scan results for a workspace (history)."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM scan_results WHERE workspace_id = ? ORDER BY id DESC LIMIT ?",
            (workspace_id, limit),
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]


async def delete_scan_history_by_workspace(workspace_id: str = "default"):
    """Delete all scan results for a workspace."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "DELETE FROM scan_results WHERE workspace_id = ?", (workspace_id,)
        )
        await db.commit()


async def export_session(session_id: str = "default") -> dict:
    """Export all data for a session."""
    logs = await get_request_logs(session_id, limit=10000)
    scans = await get_scan_results(session_id, limit=10000)
    return {"session_id": session_id, "request_logs": logs, "scan_results": scans}


# ── Credentials (encrypted at rest) ───────────────────────────────

from storage.crypto import encrypt, decrypt

# Fields that get encrypted before storage
_SENSITIVE_FIELDS = ("password", "token")


async def save_credential(cred: dict, workspace_id: str = "default") -> int:
    """Save a credential entry. Sensitive fields are encrypted."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("""
            INSERT INTO credentials (site, username, password, token, auth_type, notes, workspace_id, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            cred.get("site", ""),
            cred.get("username", ""),
            encrypt(cred.get("password", "")),
            encrypt(cred.get("token", "")),
            cred.get("auth_type", "basic"),
            cred.get("notes", ""),
            workspace_id,
            now, now,
        ))
        await db.commit()
        return cursor.lastrowid


async def get_credentials(workspace_id: str = "default", site_filter: str = None) -> list[dict]:
    """Fetch credentials for a workspace, decrypting sensitive fields."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        if site_filter:
            cursor = await db.execute(
                "SELECT * FROM credentials WHERE workspace_id = ? AND site LIKE ? ORDER BY updated_at DESC",
                (workspace_id, f"%{site_filter}%"),
            )
        else:
            cursor = await db.execute(
                "SELECT * FROM credentials WHERE workspace_id = ? ORDER BY updated_at DESC",
                (workspace_id,),
            )
        rows = [dict(row) for row in await cursor.fetchall()]
        for row in rows:
            row["password"] = decrypt(row.get("password", ""))
            row["token"] = decrypt(row.get("token", ""))
        return rows


async def update_credential(cred_id: int, cred: dict) -> bool:
    """Update an existing credential. Sensitive fields are re-encrypted."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            UPDATE credentials SET site=?, username=?, password=?, token=?, auth_type=?, notes=?, updated_at=?
            WHERE id=?
        """, (
            cred.get("site", ""),
            cred.get("username", ""),
            encrypt(cred.get("password", "")),
            encrypt(cred.get("token", "")),
            cred.get("auth_type", "basic"),
            cred.get("notes", ""),
            now, cred_id,
        ))
        await db.commit()
        return True


async def delete_credential(cred_id: int) -> bool:
    """Delete a credential by ID."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM credentials WHERE id=?", (cred_id,))
        await db.commit()
        return True


# ── Site Map ──────────────────────────────────────────────────────


async def save_sitemap_url(url: str, workspace_id: str = "default"):
    """Persist a URL to the site map (idempotent)."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT OR IGNORE INTO sitemap_urls (url, workspace_id, added_at) VALUES (?, ?, ?)",
            (url, workspace_id, now),
        )
        await db.commit()


async def save_sitemap_urls_bulk(urls: list[str], workspace_id: str = "default"):
    """Persist many URLs at once (idempotent)."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executemany(
            "INSERT OR IGNORE INTO sitemap_urls (url, workspace_id, added_at) VALUES (?, ?, ?)",
            [(u, workspace_id, now) for u in urls],
        )
        await db.commit()


async def get_sitemap_urls(workspace_id: str = "default") -> list[str]:
    """Return all saved site map URLs for a workspace."""
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            "SELECT url FROM sitemap_urls WHERE workspace_id = ? ORDER BY id",
            (workspace_id,),
        )
        rows = await cursor.fetchall()
        return [row[0] for row in rows]


async def delete_sitemap_url(url: str, workspace_id: str = "default"):
    """Remove a single URL from the site map."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "DELETE FROM sitemap_urls WHERE url = ? AND workspace_id = ?",
            (url, workspace_id),
        )
        await db.commit()


async def delete_sitemap_urls_by_prefix(prefix: str, workspace_id: str = "default"):
    """Remove all URLs matching a prefix (used for removing a host or subtree)."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "DELETE FROM sitemap_urls WHERE workspace_id = ? AND url LIKE ?",
            (workspace_id, prefix + "%"),
        )
        await db.commit()


# ── Helpers ────────────────────────────────────────────────────────


def _safe_json(raw: str) -> dict:
    """Parse JSON string, returning empty dict on failure."""
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return {}
