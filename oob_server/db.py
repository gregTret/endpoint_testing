import aiosqlite
import json
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
        await db.commit()


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


async def delete_callbacks(key: str):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM callbacks WHERE key = ?", (key,))
        await db.commit()
