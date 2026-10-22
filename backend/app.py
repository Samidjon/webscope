"""WebScope local API. Bind only to loopback for a single-user workbench."""
from __future__ import annotations

import json
import os
import re
import time
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from backend.db import DATA_DIR, clear_flows, connect, get_flow, init_db, list_flows, stats
from backend.sanitize import sanitize_body, sanitize_headers, sanitize_url
from backend.security_tools import add_scope_host, analyze_history, get_scope, host_in_scope, normalize_host, remove_scope_host

_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_\x60|~0-9A-Za-z-]+$")
_FORBIDDEN_FORWARD_HEADERS = {
    "host", "content-length", "transfer-encoding", "connection", "proxy-connection",
    "keep-alive", "te", "trailer", "upgrade", "proxy-authorization",
}
_ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="WebScope API", version="0.2.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


class ScopeHostPayload(BaseModel):
    host: str = Field(min_length=1, max_length=253)


class RepeaterPayload(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    method: str = Field(default="GET", min_length=1, max_length=12)
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = Field(default="", max_length=65536)


@app.get("/api/health")
def health():
    proxy_online = False
    status_path = DATA_DIR / "proxy_status.json"
    try:
        status = json.loads(status_path.read_text(encoding="utf-8"))
        pid = int(status.get("pid", -1))
        if pid > 0:
            os.kill(pid, 0)
            proxy_online = status.get("host") == "127.0.0.1" and status.get("port") == 8080
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        proxy_online = False
    return {"api": "online", "proxy": "online" if proxy_online else "offline", "host": "127.0.0.1"}


@app.get("/api/stats")
def get_stats():
    return stats()


@app.get("/api/flows")
def flows(
    limit: int = Query(default=500, ge=1, le=2000),
    search: str = Query(default="", max_length=300),
    method: str = Query(default="ALL", max_length=20),
    status: str = Query(default="", max_length=20),
):
    return list_flows(limit=limit, search=search, method=method, status=status)


@app.get("/api/flows/{flow_id}")
def flow_detail(flow_id: str):
    result = get_flow(flow_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Request was not found")
    return result


@app.delete("/api/flows")
def delete_flows():
    return {"deleted": clear_flows()}


@app.get("/api/targets")
def targets():
    """Build a passive site map from paths already present in local history."""
    with connect() as conn:
        rows = conn.execute(
            "SELECT host, scheme, path, captured_at, response_status FROM http_flows "
            "WHERE host <> '' ORDER BY captured_at DESC LIMIT 5000"
        ).fetchall()
    allowed = set(get_scope())
    items: dict[str, dict] = {}
    for row in rows:
        host = str(row["host"])
        item = items.setdefault(host, {
            "host": host, "schemes": set(), "requests": 0, "paths": [],
            "last_seen": row["captured_at"], "in_scope": host.lower().rstrip(".") in allowed,
        })
        item["requests"] += 1
        if row["scheme"]:
            item["schemes"].add(str(row["scheme"]))
        path = str(row["path"] or "/")
        if path not in item["paths"] and len(item["paths"]) < 40:
            item["paths"].append(path)
        if row["captured_at"] > item["last_seen"]:
            item["last_seen"] = row["captured_at"]
    return [
        {**item, "schemes": sorted(item["schemes"]), "paths": item["paths"][:40]}
        for item in sorted(items.values(), key=lambda value: value["host"].lower())
    ]


@app.get("/api/scope")
def read_scope():
    return {"hosts": get_scope(), "policy": "Exact hostname match; redirects are not followed by Repeater."}


@app.post("/api/scope")
def write_scope(payload: ScopeHostPayload):
    try:
        hosts = add_scope_host(payload.host)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"hosts": hosts}


@app.delete("/api/scope/{host}")
def delete_scope_host(host: str):
    try:
        hosts = remove_scope_host(host)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"hosts": hosts}


@app.get("/api/scanner/findings")
def scanner_findings():
    """Passive-only analysis of captured responses; this endpoint sends no traffic."""
    with connect() as conn:
        rows = conn.execute(
            "SELECT id, scheme, host, path, content_type, response_status, response_headers "
            "FROM http_flows WHERE response_status IS NOT NULL "
            "ORDER BY captured_at DESC LIMIT 1500"
        ).fetchall()
    documents = [dict(row) for row in rows]
    findings = analyze_history(documents)
    return {
        "scanned_responses": len(documents),
        "hosts": len({str(row.get("host") or "") for row in documents}),
        "findings": findings,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


@app.post("/api/repeater/send")
async def repeater_send(payload: RepeaterPayload):
    """Send one manually composed request, only to an exact allowlisted host."""
    method = payload.method.upper().strip()
    if method not in _ALLOWED_METHODS:
        raise HTTPException(status_code=422, detail="Method is not allowed in Repeater.")
    try:
        parsed = urlsplit(payload.url.strip())
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Use an absolute http:// or https:// URL.")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("Credentials in the URL are not allowed; use explicit headers instead.")
        port = parsed.port
        target_host = normalize_host(parsed.hostname)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if port is not None and not (1 <= port <= 65535):
        raise HTTPException(status_code=422, detail="Invalid target port.")
    if not host_in_scope(target_host):
        raise HTTPException(
            status_code=403,
            detail="Target host is out of scope. Add this exact hostname to Scope & Settings before sending.",
        )

    headers: dict[str, str] = {}
    for name, value in payload.headers.items():
        key = str(name).strip()
        val = str(value)
        if not _HEADER_NAME.fullmatch(key):
            raise HTTPException(status_code=422, detail="Invalid HTTP header name: " + key[:80])
        if key.lower() in _FORBIDDEN_FORWARD_HEADERS:
            continue
        if "\r" in val or "\n" in val:
            raise HTTPException(status_code=422, detail="Header values cannot contain line breaks.")
        headers[key] = val[:8192]

    started = time.perf_counter()
    try:
        timeout = httpx.Timeout(15.0, connect=7.0)
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, trust_env=False) as client:
            response = await client.request(
                method,
                payload.url.strip(),
                headers=headers,
                content=payload.body.encode("utf-8") if payload.body else None,
            )
    except httpx.TimeoutException as exc:
        raise HTTPException(status_code=504, detail="The target did not respond before the 15-second timeout.") from exc
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail="Request failed: " + type(exc).__name__) from exc

    elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
    response_headers = sanitize_headers(list(response.headers.multi_items()))
    content_type = response.headers.get("content-type", "")
    try:
        response_text = response.text
    except Exception:
        response_text = ""
    response_body = sanitize_body(response_text, content_type)
    return {
        "status": response.status_code,
        "reason": response.reason_phrase,
        "url": sanitize_url(str(response.url)),
        "elapsed_ms": elapsed_ms,
        "headers": response_headers,
        "body": response_body,
        "redirect_not_followed": 300 <= response.status_code < 400 and bool(response.headers.get("location")),
        "note": "Response is not saved to history automatically. Redirects are not followed.",
    }
