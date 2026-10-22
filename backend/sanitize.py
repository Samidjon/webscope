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
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "x-auth-token", "x-access-token",
}
MAX_BODY_CHARS = 64_000


def _is_sensitive(key: str) -> bool:
    lowered = key.lower().replace("-", "_")
    return any(part in lowered for part in SENSITIVE_PARTS)


def sanitize_headers(headers: Iterable[tuple[str, str]]) -> list[list[str]]:
    """Return headers as ordered pairs, masking common credential headers."""
    output: list[list[str]] = []
    for name, value in headers:
        if name.lower() in SENSITIVE_HEADERS or _is_sensitive(name):
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
        # Don't discard malformed JSON: still redact obvious inline key/value patterns below.
        pass
    # Fallback for simple key=value or JSON-like snippets where parsing failed.
    pattern = re.compile(r'(?i)(["\']?(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|refresh[_-]?token)["\']?\s*[:=]\s*)(["\']?)([^\s,"\'&}]+)')
    text = pattern.sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", text)
    if len(text) > MAX_BODY_CHARS:
        text = text[:MAX_BODY_CHARS] + "\n… [truncated by WebScope]"
    return text
