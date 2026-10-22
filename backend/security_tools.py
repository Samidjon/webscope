"""Local target scope and passive analysis helpers for WebScope."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from pathlib import Path
from typing import Any, Iterable

from backend.db import DATA_DIR

SCOPE_PATH = DATA_DIR / "scope.json"
_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def normalize_host(value: str) -> str:
    """Validate and normalize one exact DNS hostname or IPv4 address."""
    host = (value or "").strip().lower().rstrip(".")
    if not host or len(host) > 253 or any(ch in host for ch in "/\\?#@*"):
        raise ValueError("Enter a hostname or IPv4 address only, without a scheme, path, port, or wildcard.")
    try:
        return str(ipaddress.IPv4Address(host))
    except ipaddress.AddressValueError:
        pass
    if ":" in host:
        raise ValueError("IPv6 scope entries are not supported yet.")
    labels = host.split(".")
    if not all(_HOST_LABEL.fullmatch(label) for label in labels):
        raise ValueError("Enter a valid hostname, such as localhost or app.example.com.")
    return host


def get_scope() -> list[str]:
    try:
        document = json.loads(SCOPE_PATH.read_text(encoding="utf-8"))
        hosts = document.get("hosts", [])
    except (OSError, ValueError, TypeError):
        return []
    normalized: set[str] = set()
    for host in hosts if isinstance(hosts, list) else []:
        try:
            normalized.add(normalize_host(str(host)))
        except ValueError:
            continue
    return sorted(normalized)


def _write_scope(hosts: Iterable[str]) -> list[str]:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    values = sorted(set(hosts))
    temp = SCOPE_PATH.with_suffix(".tmp")
    temp.write_text(json.dumps({"hosts": values}, indent=2), encoding="utf-8")
    temp.replace(SCOPE_PATH)
    return values


def add_scope_host(value: str) -> list[str]:
    host = normalize_host(value)
    return _write_scope([*get_scope(), host])


def remove_scope_host(value: str) -> list[str]:
    host = normalize_host(value)
    return _write_scope(item for item in get_scope() if item != host)


def host_in_scope(value: str) -> bool:
    try:
        return normalize_host(value) in get_scope()
    except ValueError:
        return False


def _parse_headers(value: str | list[list[str]] | list[tuple[str, str]]) -> list[tuple[str, str]]:
    try:
        raw = json.loads(value) if isinstance(value, str) else value
    except (ValueError, TypeError):
        return []
    if not isinstance(raw, list):
        return []
    result: list[tuple[str, str]] = []
    for pair in raw:
        if isinstance(pair, (list, tuple)) and len(pair) >= 2:
            result.append((str(pair[0]), str(pair[1])))
    return result


def analyze_history(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Create deduplicated passive findings from already captured responses only."""
    findings: dict[tuple[str, str, str], dict[str, Any]] = {}

    def add(rule: str, title: str, severity: str, category: str, host: str, path: str,
            evidence: str, recommendation: str, flow_id: str) -> None:
        key = (rule, host.lower(), path)
        if key in findings:
            return
        digest = hashlib.sha1("|".join(key).encode("utf-8", "replace")).hexdigest()[:16]
        findings[key] = {
            "id": digest,
            "rule": rule,
            "title": title,
            "severity": severity,
            "category": category,
            "host": host,
            "path": path,
            "evidence": evidence,
            "recommendation": recommendation,
            "flow_id": flow_id,
        }

    for row in rows:
        status = row.get("response_status")
        if status is None:
            continue
        host = str(row.get("host") or "(unknown host)")
        path = str(row.get("path") or "/")
        flow_id = str(row.get("id") or "")
        scheme = str(row.get("scheme") or "").lower()
        content_type = str(row.get("content_type") or "").lower()
        pairs = _parse_headers(row.get("response_headers", "[]"))
        headers: dict[str, str] = {}
        cookies: list[str] = []
        for name, value in pairs:
            lowered = name.lower()
            if lowered == "set-cookie":
                cookies.append(value)
            else:
                headers[lowered] = value
        is_html = "text/html" in content_type
        csp = headers.get("content-security-policy", "")

        if scheme == "https" and "strict-transport-security" not in headers:
            add("missing-hsts", "HSTS header is missing", "medium", "Transport security", host, path,
                "HTTPS response did not include Strict-Transport-Security.",
                "Configure Strict-Transport-Security after confirming every subdomain can safely use HTTPS.", flow_id)
        if is_html and "content-security-policy" not in headers:
            add("missing-csp", "Content Security Policy is missing", "low", "Browser protection", host, path,
                "HTML response did not include Content-Security-Policy.",
                "Define a Content Security Policy appropriate to the application; start in report-only mode if needed.", flow_id)
        if is_html and "x-content-type-options" not in headers:
            add("missing-nosniff", "X-Content-Type-Options is missing", "low", "Browser protection", host, path,
                "HTML response did not include X-Content-Type-Options.",
                "Set X-Content-Type-Options: nosniff and serve accurate Content-Type values.", flow_id)
        if is_html and "x-frame-options" not in headers and "frame-ancestors" not in csp.lower():
            add("missing-framing-policy", "No clickjacking protection was observed", "low", "Browser protection", host, path,
                "Neither X-Frame-Options nor CSP frame-ancestors was present on this HTML response.",
                "Set an appropriate X-Frame-Options policy or Content-Security-Policy frame-ancestors directive.", flow_id)
        if is_html and "referrer-policy" not in headers:
            add("missing-referrer-policy", "Referrer-Policy is missing", "info", "Privacy", host, path,
                "No Referrer-Policy response header was captured.",
                "Choose a Referrer-Policy such as strict-origin-when-cross-origin that matches the application's needs.", flow_id)
        if headers.get("access-control-allow-origin", "").strip() == "*" and headers.get("access-control-allow-credentials", "").strip().lower() == "true":
            add("cors-wildcard-credentials", "Potentially inconsistent CORS configuration", "medium", "CORS",
                host, path, "Access-Control-Allow-Origin is '*' while Access-Control-Allow-Credentials is 'true'.",
                "Review CORS policy and allow only the specific origins required. Browsers reject this combination for credentialed reads, but it can indicate a misconfiguration.", flow_id)
        if "server" in headers:
            add("server-banner", "Server banner is exposed", "info", "Information disclosure", host, path,
                "Server: " + headers["server"][:180],
                "Remove unnecessary version details from server response headers where practical.", flow_id)
        if "x-powered-by" in headers:
            add("powered-by-banner", "Technology banner is exposed", "info", "Information disclosure", host, path,
                "X-Powered-By: " + headers["x-powered-by"][:180],
                "Remove unnecessary technology-identifying response headers where practical.", flow_id)

        for cookie in cookies:
            parts = [part.strip() for part in cookie.split(";")]
            first = parts[0] if parts else "Set-Cookie"
            cookie_name = first.split("=", 1)[0][:80] or "cookie"
            attributes = {part.split("=", 1)[0].strip().lower() for part in parts[1:] if part}
            if scheme == "https" and "secure" not in attributes:
                add("cookie-no-secure", "Cookie lacks the Secure attribute", "medium", "Cookie security", host, path,
                    "A Set-Cookie header for " + cookie_name + " did not include Secure.",
                    "Add Secure to cookies that must only be sent over HTTPS.", flow_id)
            if "httponly" not in attributes:
                add("cookie-no-httponly", "Cookie lacks the HttpOnly attribute", "low", "Cookie security", host, path,
                    "A Set-Cookie header for " + cookie_name + " did not include HttpOnly.",
                    "Add HttpOnly to session and authentication cookies that do not need JavaScript access.", flow_id)
            if "samesite" not in attributes:
                add("cookie-no-samesite", "Cookie lacks the SameSite attribute", "low", "Cookie security", host, path,
                    "A Set-Cookie header for " + cookie_name + " did not include SameSite.",
                    "Set an appropriate SameSite value (Lax or Strict where possible; None requires Secure).", flow_id)

    priority = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(findings.values(), key=lambda item: (priority.get(item["severity"], 5), item["host"], item["path"], item["title"]))[:500]
