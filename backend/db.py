"""SQLite storage for WebScope HTTP history."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "data"
DB_PATH = DATA_DIR / "webscope.sqlite3"


def connect() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    return connection


def init_db() -> None:
    with connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS http_flows (
                id TEXT PRIMARY KEY,
                captured_at TEXT NOT NULL,
                method TEXT NOT NULL,
                scheme TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER,
                path TEXT NOT NULL,
                url TEXT NOT NULL,
                http_version TEXT,
                client_ip TEXT,
                request_headers TEXT NOT NULL DEFAULT '[]',
                request_body TEXT NOT NULL DEFAULT '',
                response_status INTEGER,
                response_reason TEXT,
                response_headers TEXT NOT NULL DEFAULT '[]',
                response_body TEXT NOT NULL DEFAULT '',
                elapsed_ms REAL,
                content_type TEXT,
                error TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_flows_captured_at ON http_flows(captured_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_flows_host ON http_flows(host)")


def list_flows(limit: int = 500, search: str = "", method: str = "", status: str = "") -> list[dict[str, Any]]:
    clauses: list[str] = []
    values: list[Any] = []
    if search.strip():
        needle = f"%{search.strip()}%"
        clauses.append("(host LIKE ? OR path LIKE ? OR method LIKE ? OR url LIKE ?)")
        values.extend([needle, needle, needle, needle])
    if method and method.upper() != "ALL":
        clauses.append("method = ?")
        values.append(method.upper())
    if status:
        if status == "2xx": clauses.append("response_status >= 200 AND response_status < 300")
        elif status == "3xx": clauses.append("response_status >= 300 AND response_status < 400")
        elif status == "4xx": clauses.append("response_status >= 400 AND response_status < 500")
        elif status == "5xx": clauses.append("response_status >= 500 AND response_status < 600")
        elif status == "pending": clauses.append("response_status IS NULL AND error IS NULL")
        elif status == "error": clauses.append("error IS NOT NULL")
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    values.append(max(1, min(limit, 2000)))
    with connect() as conn:
        rows = conn.execute(
            "SELECT id, captured_at, method, scheme, host, port, path, url, response_status, elapsed_ms, content_type, error "
            f"FROM http_flows{where} ORDER BY captured_at DESC LIMIT ?", values
        ).fetchall()
    return [dict(row) for row in rows]


def get_flow(flow_id: str) -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM http_flows WHERE id = ?", (flow_id,)).fetchone()
    if not row:
        return None
    result = dict(row)
    for key in ("request_headers", "response_headers"):
        try: result[key] = json.loads(result[key] or "[]")
        except json.JSONDecodeError: result[key] = []
    return result


def stats() -> dict[str, int]:
    with connect() as conn:
        total = conn.execute("SELECT COUNT(*) FROM http_flows").fetchone()[0]
        hosts = conn.execute("SELECT COUNT(DISTINCT host) FROM http_flows").fetchone()[0]
        findings = conn.execute("SELECT COUNT(*) FROM http_flows WHERE response_status >= 400 OR error IS NOT NULL").fetchone()[0]
    return {"requests": int(total), "hosts": int(hosts), "issues": int(findings)}


def clear_flows() -> int:
    with connect() as conn:
        count = conn.execute("SELECT COUNT(*) FROM http_flows").fetchone()[0]
        conn.execute("DELETE FROM http_flows")
    return int(count)
