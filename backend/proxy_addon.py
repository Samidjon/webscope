"""mitmproxy addon that stores a privacy-sanitized HTTP history in SQLite.

Run from the project root with:
    mitmdump --listen-host 127.0.0.1 --listen-port 8080 -s backend/proxy_addon.py
"""
from __future__ import annotations

import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

# Ensure `backend` can be imported when mitmdump launches this addon.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.db import DATA_DIR, connect, init_db  # noqa: E402
from backend.sanitize import sanitize_body, sanitize_headers, sanitize_url  # noqa: E402


def _headers(message) -> list[list[str]]:
    try:
        return sanitize_headers([(str(k), str(v)) for k, v in message.headers.items(multi=True)])
    except TypeError:
        return sanitize_headers([(str(k), str(v)) for k, v in message.headers.items()])


def _body(message) -> str:
    try:
        body = message.get_text(strict=False) or ""
    except Exception:
        raw = getattr(message, "raw_content", None) or b""
        return f"[Body omitted: unable to decode {len(raw)} bytes]" if raw else ""
    content_type = message.headers.get("content-type", "") if message else ""
    return sanitize_body(body, content_type)


class WebScopeCapture:
    def load(self, loader):
        init_db()

    def running(self):
        # Mark this exact proxy process as online; the API checks this marker.
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        status_path = DATA_DIR / "proxy_status.json"
        temporary_path = DATA_DIR / "proxy_status.tmp"
        temporary_path.write_text(json.dumps({"pid": os.getpid(), "host": "127.0.0.1", "port": 8080}), encoding="utf-8")
        temporary_path.replace(status_path)

    def done(self):
        status_path = DATA_DIR / "proxy_status.json"
        try:
            status = json.loads(status_path.read_text(encoding="utf-8"))
            if int(status.get("pid", -1)) == os.getpid():
                status_path.unlink(missing_ok=True)
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            pass

    def request(self, flow):
        request = flow.request
        flow_id = str(uuid.uuid4())
        flow.metadata["webscope_id"] = flow_id
        host = str(request.host or "")
        url = sanitize_url(str(request.pretty_url))
        safe_parts = urlsplit(url)
        safe_path = safe_parts.path + ("?" + safe_parts.query if safe_parts.query else "")
        content_type = request.headers.get("content-type", "")
        try:
            with connect() as conn:
                conn.execute("""
                    INSERT INTO http_flows (
                        id, captured_at, method, scheme, host, port, path, url,
                        http_version, client_ip, request_headers, request_body,
                        content_type
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    flow_id,
                    datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                    str(request.method), str(request.scheme), host, int(request.port),
                    safe_path, url, str(request.http_version),
                    str(flow.client_conn.peername[0]) if flow.client_conn.peername else None,
                    json.dumps(_headers(request), ensure_ascii=False), _body(request),
                    str(content_type),
                ))
        except Exception as exc:
            # A local history-write failure should never break the proxied request.
            print(f"[WebScope] Could not store request: {exc}", file=sys.stderr)

    def response(self, flow):
        flow_id = flow.metadata.get("webscope_id")
        if not flow_id or not flow.response:
            return
        response = flow.response
        content_type = response.headers.get("content-type", "")
        elapsed_ms = None
        try:
            start = flow.request.timestamp_start
            end = response.timestamp_end
            if start is not None and end is not None:
                elapsed_ms = max(0.0, (end - start) * 1000)
        except Exception:
            pass
        try:
            with connect() as conn:
                conn.execute("""
                    UPDATE http_flows SET response_status = ?, response_reason = ?,
                        response_headers = ?, response_body = ?, elapsed_ms = ?,
                        content_type = ? WHERE id = ?
                """, (
                    int(response.status_code), str(response.reason or ""),
                    json.dumps(_headers(response), ensure_ascii=False), _body(response),
                    elapsed_ms, str(content_type), flow_id,
                ))
        except Exception as exc:
            print(f"[WebScope] Could not store response: {exc}", file=sys.stderr)

    def error(self, flow):
        flow_id = flow.metadata.get("webscope_id")
        if not flow_id or not flow.error:
            return
        try:
            with connect() as conn:
                conn.execute("UPDATE http_flows SET error = ? WHERE id = ?", (str(flow.error.msg)[:1000], flow_id))
        except Exception as exc:
            print(f"[WebScope] Could not store flow error: {exc}", file=sys.stderr)


addons = [WebScopeCapture()]
