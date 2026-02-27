import aiosqlite
import hashlib
import json
import os
import time
from pathlib import Path

DB_PATH = Path(__file__).parent / "oob.db"


async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS callbacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT NOT NULL,
                token TEXT NOT NULL,
                timestamp REAL NOT NULL,
                source_ip TEXT,
                method TEXT,
                path TEXT,
                headers TEXT,
                body TEXT,
                query_params TEXT,
                extra_path TEXT
            )
        """)
        await db.execute("CREATE INDEX IF NOT EXISTS idx_key ON callbacks (key)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_key_token ON callbacks (key, token)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_source_ip ON callbacks (source_ip)")
        await db.execute("""
            CREATE TABLE IF NOT EXISTS excluded_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL UNIQUE,
                reason TEXT DEFAULT '',
                created_at REAL NOT NULL
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at REAL NOT NULL
            )
        """)
        await db.commit()


def _hash_password(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, iterations=600_000
    ).hex()


async def create_user(username: str, password: str):
    salt = os.urandom(32)
    pw_hash = _hash_password(password, salt)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO users (username, password_hash, salt, created_at) VALUES (?, ?, ?, ?)",
            (username, pw_hash, salt.hex(), time.time()),
        )
        await db.commit()
    print(f"[+] User '{username}' created successfully")
    # Verify it round-trips
    ok = await verify_user(username, password)
    print(f"[+] Verification: {'PASS' if ok else 'FAIL'}")


async def verify_user(username: str, password: str) -> bool:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT password_hash, salt FROM users WHERE username = ?", (username,)
        ) as cursor:
            row = await cursor.fetchone()
            if row is None:
                return False
            salt = bytes.fromhex(row["salt"])
            return _hash_password(password, salt) == row["password_hash"]


async def store_callback(
    key: str,
    token: str,
    source_ip: str,
    method: str,
    path: str,
    headers: dict,
    body: str,
    query_params: dict,
    extra_path: str | None = None,
):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            INSERT INTO callbacks (key, token, timestamp, source_ip, method, path, headers, body, query_params, extra_path)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                key,
                token,
                time.time(),
                source_ip,
                method,
                path,
                json.dumps(headers),
                body,
                json.dumps(query_params),
                extra_path,
            ),
        )
        await db.commit()


async def get_callbacks(key: str, token: str | None = None, since: float | None = None):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        query = "SELECT * FROM callbacks WHERE key = ?"
        params: list = [key]

        if token is not None:
            query += " AND token = ?"
            params.append(token)

        if since is not None:
            query += " AND timestamp > ?"
            params.append(since)

        query += " ORDER BY timestamp ASC"

        async with db.execute(query, params) as cursor:
            rows = await cursor.fetchall()
            return [
                {
                    "id": row["id"],
                    "key": row["key"],
                    "token": row["token"],
                    "timestamp": row["timestamp"],
                    "source_ip": row["source_ip"],
                    "method": row["method"],
                    "path": row["path"],
                    "headers": json.loads(row["headers"]),
                    "body": row["body"],
                    "query_params": json.loads(row["query_params"]),
                    "extra_path": row["extra_path"],
                }
                for row in rows
            ]


async def get_all_callbacks(limit: int = 500, offset: int = 0, exclude_ips: list[str] | None = None):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        params: list = []
        where = ""
        if exclude_ips:
            placeholders = ",".join("?" for _ in exclude_ips)
            where = f" WHERE source_ip NOT IN ({placeholders})"
            params.extend(exclude_ips)
        query = f"SELECT * FROM callbacks{where} ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        async with db.execute(query, params) as cursor:
            rows = await cursor.fetchall()
            return [
                {
                    "id": row["id"],
                    "key": row["key"],
                    "token": row["token"],
                    "timestamp": row["timestamp"],
                    "source_ip": row["source_ip"],
                    "method": row["method"],
                    "path": row["path"],
                    "headers": json.loads(row["headers"]),
                    "body": row["body"],
                    "query_params": json.loads(row["query_params"]),
                    "extra_path": row["extra_path"],
                }
                for row in rows
            ]


async def get_callback_count(exclude_ips: list[str] | None = None) -> int:
    async with aiosqlite.connect(DB_PATH) as db:
        params: list = []
        where = ""
        if exclude_ips:
            placeholders = ",".join("?" for _ in exclude_ips)
            where = f" WHERE source_ip NOT IN ({placeholders})"
            params.extend(exclude_ips)
        async with db.execute(f"SELECT COUNT(*) FROM callbacks{where}", params) as cursor:
            row = await cursor.fetchone()
            return row[0] if row else 0


async def get_excluded_ips() -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM excluded_ips ORDER BY created_at DESC") as cursor:
            rows = await cursor.fetchall()
            return [
                {
                    "id": row["id"],
                    "ip": row["ip"],
                    "reason": row["reason"],
                    "created_at": row["created_at"],
                }
                for row in rows
            ]


async def add_excluded_ip(ip: str, reason: str = "") -> bool:
    async with aiosqlite.connect(DB_PATH) as db:
        try:
            await db.execute(
                "INSERT OR IGNORE INTO excluded_ips (ip, reason, created_at) VALUES (?, ?, ?)",
                (ip, reason, time.time()),
            )
            await db.commit()
            return db.total_changes > 0
        except Exception:
            return False


async def remove_excluded_ip(ip: str) -> bool:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM excluded_ips WHERE ip = ?", (ip,))
        await db.commit()
        return db.total_changes > 0


async def delete_callbacks(key: str):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM callbacks WHERE key = ?", (key,))
        await db.commit()


async def get_ip_summary() -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        query = """
            SELECT
                s.source_ip,
                s.callback_count,
                s.first_seen,
                s.last_seen,
                s.distinct_methods,
                s.distinct_keys,
                s.distinct_tokens,
                s.methods,
                latest.headers as latest_headers
            FROM (
                SELECT
                    source_ip,
                    COUNT(*) as callback_count,
                    MIN(timestamp) as first_seen,
                    MAX(timestamp) as last_seen,
                    COUNT(DISTINCT method) as distinct_methods,
                    COUNT(DISTINCT key) as distinct_keys,
                    COUNT(DISTINCT token) as distinct_tokens,
                    GROUP_CONCAT(DISTINCT method) as methods
                FROM callbacks
                WHERE source_ip IS NOT NULL
                GROUP BY source_ip
            ) s
            LEFT JOIN callbacks latest ON latest.source_ip = s.source_ip
                AND latest.timestamp = s.last_seen
            ORDER BY s.callback_count DESC
        """
        async with db.execute(query) as cursor:
            rows = await cursor.fetchall()
            seen = set()
            results = []
            for row in rows:
                ip = row["source_ip"]
                if ip in seen:
                    continue
                seen.add(ip)
                country_code = None
                if row["latest_headers"]:
                    try:
                        hdrs = json.loads(row["latest_headers"])
                        country_code = hdrs.get("cf-ipcountry") or hdrs.get("CF-IPCountry")
                    except (json.JSONDecodeError, AttributeError):
                        pass
                results.append({
                    "source_ip": ip,
                    "callback_count": row["callback_count"],
                    "first_seen": row["first_seen"],
                    "last_seen": row["last_seen"],
                    "distinct_methods": row["distinct_methods"],
                    "distinct_keys": row["distinct_keys"],
                    "distinct_tokens": row["distinct_tokens"],
                    "methods": row["methods"].split(",") if row["methods"] else [],
                    "country_code": country_code,
                })
            return results


async def get_ip_detail(ip: str, limit: int = 500, offset: int = 0) -> dict:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        summary_query = """
            SELECT
                COUNT(*) as total_callbacks,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen,
                COUNT(DISTINCT method) as distinct_methods,
                COUNT(DISTINCT key) as distinct_keys,
                COUNT(DISTINCT token) as distinct_tokens,
                COUNT(DISTINCT path) as distinct_paths,
                GROUP_CONCAT(DISTINCT method) as methods,
                GROUP_CONCAT(DISTINCT key) as keys
            FROM callbacks
            WHERE source_ip = ?
        """
        async with db.execute(summary_query, (ip,)) as cursor:
            sr = await cursor.fetchone()

        callbacks_query = """
            SELECT * FROM callbacks
            WHERE source_ip = ?
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
        """
        async with db.execute(callbacks_query, (ip, limit, offset)) as cursor:
            rows = await cursor.fetchall()
            callbacks = [
                {
                    "id": row["id"],
                    "key": row["key"],
                    "token": row["token"],
                    "timestamp": row["timestamp"],
                    "source_ip": row["source_ip"],
                    "method": row["method"],
                    "path": row["path"],
                    "headers": json.loads(row["headers"]),
                    "body": row["body"],
                    "query_params": json.loads(row["query_params"]),
                    "extra_path": row["extra_path"],
                }
                for row in rows
            ]

        histogram_query = """
            SELECT
                CAST((timestamp / 3600) AS INTEGER) * 3600 as hour_bucket,
                COUNT(*) as count
            FROM callbacks
            WHERE source_ip = ?
            GROUP BY hour_bucket
            ORDER BY hour_bucket ASC
        """
        async with db.execute(histogram_query, (ip,)) as cursor:
            histogram = [
                {"timestamp": row["hour_bucket"], "count": row["count"]}
                for row in await cursor.fetchall()
            ]

        return {
            "source_ip": ip,
            "total_callbacks": sr["total_callbacks"],
            "first_seen": sr["first_seen"],
            "last_seen": sr["last_seen"],
            "distinct_methods": sr["distinct_methods"],
            "distinct_keys": sr["distinct_keys"],
            "distinct_tokens": sr["distinct_tokens"],
            "distinct_paths": sr["distinct_paths"],
            "methods": sr["methods"].split(",") if sr["methods"] else [],
            "keys": sr["keys"].split(",") if sr["keys"] else [],
            "histogram": histogram,
            "callbacks": callbacks,
            "returned": len(callbacks),
        }
