"""
LOKI Session Store — persistent browser session between CLI commands.
One browser, one session, all commands share the same auth context.
"""
from __future__ import annotations
import json
import os
import tempfile
from pathlib import Path
from typing import Optional
import asyncio
from urllib.parse import urlparse

def _session_file(slot: str = "default") -> Path:
    return Path(tempfile.gettempdir()) / f"loki_active_session_{slot}.json"

SESSION_FILE = _session_file("default")


def save_session(host: str, cookies: list, local_storage: dict,
                  session_storage: dict, auth_headers: dict, url: str = "",
                  slot: str = "default") -> None:
    data = {
        "host": host,
        "slot": slot,
        "resolved_host": urlparse(url).netloc or host,
        "url": url,
        "cookies": cookies,
        "local_storage": local_storage,
        "session_storage": session_storage,
        "auth_headers": auth_headers,
    }
    _session_file(slot).write_text(json.dumps(data, indent=2))


def load_session(slot: str = "default") -> Optional[dict]:
    sf = _session_file(slot)
    if not sf.exists():
        return None
    try:
        return json.loads(sf.read_text())
    except Exception:
        return None


def clear_session(slot: str = "default") -> None:
    sf = _session_file(slot)
    if sf.exists():
        sf.unlink()


def session_exists(slot: str = "default") -> bool:
    return _session_file(slot).exists()


def get_session_host(slot: str = "default") -> Optional[str]:
    s = load_session(slot)
    return s.get("host") if s else None

def get_auth_header_for_host(session: dict, host: str) -> dict:
    """
    Return the {header_name: value} captured for this host during the
    crawl (e.g. {"authorization": "Bearer ..."}), or {} if none was seen.
    Used to auto-attach the right auth header when a request targets a
    different host than the one the session was captured under (common
    for SPA frontend + separate API backend setups).
    """
    auth_headers = session.get("auth_headers") or {}
    return dict(auth_headers.get(host, {}))


def resolve_host_for_path(session: dict, path: str, host_override: str | None = None) -> tuple[str, str]:
    """
    Figure out which host a relative path actually belongs to, for
    multi-host apps (SPA frontend + separate API backend on a different
    domain — common on Vercel/Render/Railway deployments).

    Returns (host, mode) where mode is one of:
      "explicit" — caller passed --host, used as-is
      "url"      — path was already a full URL, host extracted from it
      "auto"     — matched exactly one host from previously discovered
                   endpoints recorded for this path during crawl
      "default"  — no match found (or ambiguous across multiple hosts),
                   fell back to the session's own resolved host
    Callers should print a note when mode == "auto" so the user knows
    LOKI silently redirected the request to a different host than the
    session's own — never guess silently without saying so.
    """
    if host_override:
        return host_override, "explicit"
    if path.startswith("http://") or path.startswith("https://"):
        return urlparse(path).netloc, "url"

    default_host = session.get("resolved_host") or session.get("host", "")
    clean_path = path.split("?")[0]
    endpoints = session.get("endpoints") or []
    matches = {e.get("host") for e in endpoints if e.get("path") == clean_path and e.get("host")}
    matches.discard(None)
    matches.discard("")

    if len(matches) == 1:
        return matches.pop(), "auto"
    return default_host, "default"
