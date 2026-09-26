"""
Project state vault — tracks active project / session context.
Stored in ~/.loki/state.json (0600).
"""
from __future__ import annotations
import json
import os
import stat
from pathlib import Path
from typing import Optional

_STATE = Path.home() / ".loki" / "state.json"


def _load() -> dict:
    if _STATE.exists():
        try:
            return json.loads(_STATE.read_text())
        except Exception:
            pass
    return {}


def _save(data: dict) -> None:
    _STATE.parent.mkdir(parents=True, exist_ok=True)
    _STATE.write_text(json.dumps(data, indent=2))
    os.chmod(_STATE, stat.S_IRUSR | stat.S_IWUSR)


def get_active_project() -> Optional[str]:
    return _load().get("project")


def set_active_project(name: str) -> None:
    d = _load()
    d["project"] = name
    _save(d)


def get_active_host(project: str) -> Optional[str]:
    return _load().get(f"{project}:host")


def set_active_host(project: str, host: str) -> None:
    d = _load()
    d[f"{project}:host"] = host
    _save(d)
