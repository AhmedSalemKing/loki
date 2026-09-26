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
