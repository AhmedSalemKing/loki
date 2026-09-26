"""
Persistent Chrome daemon — launched as an INDEPENDENT OS process (not a
Playwright-managed subprocess), so it survives after the CLI command exits.
"""
from __future__ import annotations
import json
import os
import shutil
import signal
import socket
import subprocess
import time
from pathlib import Path

import httpx

LOG_FILE = Path("/tmp/loki_chrome.log")


def _profile_dir(slot: str = "default") -> Path:
    return Path(f"/tmp/loki_chrome_profile_{slot}")


def _state_file(slot: str = "default") -> Path:
    return Path(f"/tmp/loki_browser_daemon_{slot}.json")


# Backward-compat aliases (default slot)
PROFILE_DIR = _profile_dir("default")
STATE_FILE = _state_file("default")

_CHROME_CANDIDATES = [
    "google-chrome", "google-chrome-stable",
    "chromium", "chromium-browser", "chromium.exe",
]

_LOCK_FILES = ["SingletonLock", "SingletonCookie", "SingletonSocket"]

_supports_geteuid = hasattr(os, "geteuid")


def _find_chrome() -> str:
    for name in _CHROME_CANDIDATES:
        path = shutil.which(name)
        if path:
            return path
    raise RuntimeError(
        "No Chrome/Chromium binary found on PATH.\n"
        "Install: sudo apt install chromium"
    )


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def is_alive(port: int) -> bool:
    try:
        r = httpx.get(f"http://127.0.0.1:{port}/json/version", timeout=1.5)
        return r.status_code == 200
    except Exception:
        return False


def get_daemon_info(slot: str = "default") -> dict | None:
    sf = _state_file(slot)
    if not sf.exists():
        return None
    try:
        return json.loads(sf.read_text())
    except Exception:
        return None


def _clear_stale_locks(slot: str = "default") -> None:
    """Remove leftover Chrome singleton locks from a crashed/killed instance."""
    for name in _LOCK_FILES:
        f = _profile_dir(slot) / name
        try:
            if f.exists() or f.is_symlink():
                f.unlink()
        except Exception:
            pass


def launch(headless: bool = False, host_hint: str = "", slot: str = "default") -> tuple[int, int]:
    """
    Launch a detached Chrome with remote debugging.
    Returns (pid, port). Raises RuntimeError with the ACTUAL Chrome
    stderr/stdout tail if it fails to come up, instead of a blind timeout.
    """
    existing = get_daemon_info(slot)
    if existing and is_alive(existing["port"]):
        return existing["pid"], existing["port"]

    chrome = _find_chrome()
    port = _free_port()
    profile_dir = _profile_dir(slot)
    profile_dir.mkdir(exist_ok=True)
    _clear_stale_locks(slot)

    is_root = os.geteuid() == 0 if _supports_geteuid else False

    args = [
        chrome,
        f"--remote-debugging-port={port}",
        f"--remote-debugging-address=127.0.0.1",
        f"--user-data-dir={profile_dir}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-blink-features=AutomationControlled",
        "--disable-infobars",
        "--disable-dev-shm-usage",
        "--start-maximized",
    ]
    if is_root:
        args.append("--no-sandbox")
    if headless:
        args.append("--headless=new")

    log_fh = open(LOG_FILE, "w")
    proc = subprocess.Popen(
        args,
        stdout=log_fh,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        start_new_session=True,  # detach — keeps running after CLI exits
    )

    # Wait for CDP endpoint to come up (max ~15s), but bail out immediately
    # if the process itself has already died.
    started = False
    for _ in range(75):
        if proc.poll() is not None:
            break  # process exited early — stop waiting, go report the error
        if is_alive(port):
            started = True
            break
        time.sleep(0.2)

    if not started:
        try:
            proc.kill()
        except Exception:
            pass
        log_fh.close()
        tail = ""
        try:
            tail = LOG_FILE.read_text()[-2000:]
        except Exception:
            pass
        raise RuntimeError(
            "Chrome failed to start remote debugging.\n"
            f"Binary: {chrome}\n"
            f"Running as root: {is_root}\n"
            f"---- Chrome output (last 2000 chars) ----\n{tail}\n"
            "------------------------------------------\n"
            "Common fixes:\n"
            "  1) Missing deps: sudo apt install -y libnss3 libgbm1 libasound2\n"
            "  2) Stale profile: rm -rf /tmp/loki_chrome_profile\n"
            "  3) Try running the binary directly to see the real error:\n"
            f"     {chrome} --headless=new --remote-debugging-port=9333 --no-sandbox --user-data-dir=/tmp/test_profile"
        )

    _state_file(slot).write_text(json.dumps({"pid": proc.pid, "port": port, "host": host_hint, "slot": slot}))
    return proc.pid, port


def stop(slot: str = "default") -> bool:
    info = get_daemon_info(slot)
    if not info:
        return False
    try:
        os.kill(info["pid"], signal.SIGTERM)
    except ProcessLookupError:
        pass
    _state_file(slot).unlink(missing_ok=True)
    _clear_stale_locks(slot)
    return True