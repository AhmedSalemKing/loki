"""
LOKI JS Scanner — fetch already-loaded .js bundles and regex them for
API path string literals, then diff against endpoints actually called
during the crawl to surface "hidden" endpoints.
"""
from __future__ import annotations
import re
from urllib.parse import urlparse

from playwright.async_api import Page

_PATH_PATTERN = re.compile(r"""["'`](/(?:api|graphql|v[0-9]+|internal|admin)[a-zA-Z0-9_\-/{}\.]*)["'`]""")
_SKIP_SUFFIXES = (".js", ".css", ".png", ".jpg", ".svg", ".woff", ".woff2", ".map")


def _extract_paths(js_text: str) -> set[str]:
    found = set()
    for m in _PATH_PATTERN.finditer(js_text):
        path = m.group(1)
        if path.endswith(_SKIP_SUFFIXES):
            continue
        if len(path) < 4 or len(path) > 200:
            continue
        found.add(path)
    return found


async def scan_js_bundles(page: Page, js_urls: list[str], timeout_ms: int = 8000) -> dict[str, set[str]]:
    results: dict[str, set[str]] = {}
    for url in js_urls:
        try:
            text = await page.evaluate(
                """async (url) => {
                    try {
                        const r = await fetch(url, { credentials: 'include' });
                        if (!r.ok) return '';
                        return await r.text();
                    } catch(e) { return ''; }
                }""",
                url,
            )
        except Exception:
            text = ""
        results[url] = _extract_paths(text) if text else set()
    return results


def diff_hidden_endpoints(js_paths_by_file: dict[str, set[str]], called_endpoints: list[dict]) -> list[dict]:
    called_paths = {e.get("path", "") for e in called_endpoints}
    hidden: list[dict] = []
    seen: set[str] = set()
    for js_url, paths in js_paths_by_file.items():
        for path in paths:
            if path in called_paths or path in seen:
                continue
            seen.add(path)
            hidden.append({"path": path, "found_in": js_url})
    hidden.sort(key=lambda h: h["path"])
    return hidden