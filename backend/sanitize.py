"""Privacy-conscious sanitizers for captured HTTP data."""
from __future__ import annotations

import json
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from typing import Any, Iterable

SENSITIVE_PARTS = (
    "password", "passwd", "secret", "token", "authorization", "api_key",
    "apikey", "access_key", "refresh", "session", "credential", "private_key",
)
SENSITIVE_HEADERS = {
    "authorization", "proxy-authorization", "cookie",
    "x-api-key", "x-auth-token", "x-access-token",
}
MAX_BODY_CHARS = 64_000


def _is_sensitive(key: str) -> bool:
    lowered = key.lower().replace("-", "_")
    return any(part in lowered for part in SENSITIVE_PARTS)


def _sanitize_set_cookie(value: str) -> str:
    """Keep cookie flags useful for passive checks but never keep the cookie value."""
    parts = [part.strip() for part in value.split(";")]
    if not parts:
        return "[REDACTED]"
    first = parts[0]
    name = first.split("=", 1)[0].strip() if "=" in first else "cookie"
    safe_first = (name[:100] or "cookie") + "=[REDACTED]"
    safe_attributes = []
    for part in parts[1:]:
        attr_name = part.split("=", 1)[0].strip().lower()
        if attr_name in {"path", "domain", "expires", "max-age", "samesite", "priority"} or attr_name in {"secure", "httponly", "partitioned"}:
            safe_attributes.append(part[:250])
    return "; ".join([safe_first, *safe_attributes])


def sanitize_headers(headers: Iterable[tuple[str, str]]) -> list[list[str]]:
    """Mask secrets while retaining non-secret Set-Cookie security attributes."""
    output: list[list[str]] = []
    for name, value in headers:
        lowered = name.lower()
        if lowered == "set-cookie":
            value = _sanitize_set_cookie(str(value))
        elif lowered in SENSITIVE_HEADERS or _is_sensitive(name):
            value = "[REDACTED]"
        output.append([str(name), str(value)])
    return output


def sanitize_url(url: str) -> str:
    """Mask likely secret values in URL query parameters."""
    try:
        parts = urlsplit(url)
        safe_query = []
        for key, value in parse_qsl(parts.query, keep_blank_values=True):
            safe_query.append((key, "[REDACTED]" if _is_sensitive(key) else value))
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(safe_query), parts.fragment))
    except Exception:
        return url


def _redact_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: ("[REDACTED]" if _is_sensitive(str(key)) else _redact_json(item))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_json(item) for item in value]
    return value


def sanitize_body(body: str | None, content_type: str | None = None) -> str:
    """Redact common JSON/form secrets and cap stored body size."""
    if not body:
        return ""
    content_type = (content_type or "").lower()
    text = body
    try:
        if "json" in content_type or text.lstrip().startswith(("{", "[")):
            parsed = json.loads(text)
            text = json.dumps(_redact_json(parsed), ensure_ascii=False, indent=2)
        elif "application/x-www-form-urlencoded" in content_type:
            pairs = parse_qsl(text, keep_blank_values=True)
            text = urlencode([(key, "[REDACTED]" if _is_sensitive(key) else value) for key, value in pairs])
        elif not any(marker in content_type for marker in ("text/", "xml", "javascript", "graphql", "x-www-form-urlencoded")):
            return f"[Body omitted: non-text content, {len(body)} characters]"
    except (json.JSONDecodeError, UnicodeError, TypeError):
        pass
    pattern = re.compile(r'(?i)(["\']?(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|refresh[_-]?token)["\']?\s*[:=]\s*)(["\']?)([^\s,"\']+&}]+)')
    text = pattern.sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", text)
    if len(text) > MAX_BODY_CHARS:
        text = text[:MAX_BODY_CHARS] + "\n… [truncated by WebScope]"
    return text
