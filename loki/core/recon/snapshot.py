"""
LOKI Recon Snapshot — save a point-in-time picture of a target's known
endpoints and JS bundle hashes, and diff two snapshots later to catch
newly deployed routes, removed routes, or changed JS bundles.
"""
from __future__ import annotations
import hashlib
import json
import time
from pathlib import Path

SNAPSHOTS_DIR = Path.home() / ".loki" / "snapshots"


def _host_dir(host: str) -> Path:
    d = SNAPSHOTS_DIR / host.replace(":", "_")
    d.mkdir(parents=True, exist_ok=True)
    return d


async def take_snapshot(page, host: str, endpoints: list[dict], js_urls: list[str], label: str | None = None) -> Path:
    """Fetch each JS bundle, hash its content, and save a snapshot file."""
    js_hashes: dict[str, str] = {}
    for url in js_urls:
        try:
            text = await page.evaluate(
                """async (url) => {
                    try {
                        const r = await fetch(url, { credentials: 'include' });
                        return r.ok ? await r.text() : '';
                    } catch(e) { return ''; }
                }""",
                url,
            )
        except Exception:
            text = ""
        js_hashes[url] = hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest() if text else ""

    snapshot = {
        "host": host,
        "taken_at": time.time(),
        "label": label,
        "paths": sorted({e.get("path", "") for e in endpoints if e.get("path")}),
        "js_hashes": js_hashes,
    }

    fname = f"{int(snapshot['taken_at'])}_{label or 'snap'}.json"
    fpath = _host_dir(host) / fname
    fpath.write_text(json.dumps(snapshot, indent=2))
    return fpath


def list_snapshots(host: str) -> list[Path]:
    d = _host_dir(host)
    return sorted(d.glob("*.json"), key=lambda p: p.stat().st_mtime)


def diff_snapshots(old_path: Path, new_path: Path) -> dict:
    old = json.loads(old_path.read_text())
    new = json.loads(new_path.read_text())

    old_paths = set(old.get("paths", []))
    new_paths = set(new.get("paths", []))

    added_paths = sorted(new_paths - old_paths)
    removed_paths = sorted(old_paths - new_paths)

    old_js = old.get("js_hashes", {})
    new_js = new.get("js_hashes", {})
    changed_js = sorted(
        url for url in new_js
        if url in old_js and old_js[url] and new_js[url] and old_js[url] != new_js[url]
    )
    new_js_files = sorted(set(new_js) - set(old_js))

    return {
        "old_label": old.get("label"), "new_label": new.get("label"),
        "added_paths": added_paths, "removed_paths": removed_paths,
        "changed_js": changed_js, "new_js_files": new_js_files,
    }
