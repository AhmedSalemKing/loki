"""
LOKI Secret Patterns — regex signatures for common leaked credentials.
Used by `loki secrets scan` against localStorage/sessionStorage/cookies.
"""
from __future__ import annotations
import re

SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS Secret Access Key", re.compile(r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]")),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Google OAuth Token", re.compile(r"ya29\.[0-9A-Za-z\-_]+")),
    ("Stripe Live Secret Key", re.compile(r"sk_live_[0-9a-zA-Z]{24,}")),
    ("Stripe Live Publishable Key", re.compile(r"pk_live_[0-9a-zA-Z]{24,}")),
    ("Stripe Restricted Key", re.compile(r"rk_live_[0-9a-zA-Z]{24,}")),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
    ("GitHub Token", re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}")),
    ("Firebase URL/Key hint", re.compile(r"[a-z0-9-]+\.firebaseio\.com")),
    ("Generic JWT", re.compile(r"eyJ[0-9A-Za-z_\-]+\.eyJ[0-9A-Za-z_\-]+\.[0-9A-Za-z_\-]+")),
    ("Private Key Block", re.compile(r"-----BEGIN (RSA|EC|OPENSSH|PGP)? ?PRIVATE KEY-----")),
    ("Generic API Key (key=value)", re.compile(r"(?i)(api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"][0-9a-zA-Z\-_]{16,}['\"]")),
    ("Generic Secret (key=value)", re.compile(r"(?i)(secret|client[_-]?secret)['\"]?\s*[:=]\s*['\"][0-9a-zA-Z\-_]{12,}['\"]")),
    ("Generic Token (key=value)", re.compile(r"(?i)(access[_-]?token|auth[_-]?token)['\"]?\s*[:=]\s*['\"][0-9a-zA-Z\-_.]{16,}['\"]")),
    ("Basic Auth in URL", re.compile(r"https?://[^\s:'\"@/]+:[^\s:'\"@/]+@")),
]


def scan_text(source: str, key: str, value: str) -> list[dict]:
    hits = []
    haystack = f"{key}={value}"
    for name, pattern in SECRET_PATTERNS:
        m = pattern.search(haystack)
        if m:
            hits.append({"source": source, "key": key, "pattern": name, "match": m.group(0)})
    return hits


def mask(value: str) -> str:
    if len(value) <= 10:
        return "*" * len(value)
    return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"