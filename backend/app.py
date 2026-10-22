"""WebScope local API."""
from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from backend.db import DATA_DIR, clear_flows, get_flow, init_db, list_flows, stats


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="WebScope API", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
    allow_credentials=False,
    allow_methods=["GET", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health():
    proxy_online = False
    status_path = DATA_DIR / "proxy_status.json"
    try:
        status = json.loads(status_path.read_text(encoding="utf-8"))
        pid = int(status.get("pid", -1))
        # os.kill(pid, 0) checks process existence without terminating it.
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
