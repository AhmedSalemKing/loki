"""
Auto-crawler — BFS through same-origin links using the already-authenticated
browser session. No manual clicking required. Skips destructive actions
(logout, delete, remove) and off-site links.
"""
from __future__ import annotations
import asyncio
import time
from urllib.parse import urlparse, urljoin

from playwright.async_api import Page, BrowserContext

_SKIP_PATTERNS = [
    "logout", "signout", "sign-out", "log-out",
    "delete", "remove", "cancel-order", "unsubscribe",
    "javascript:", "mailto:", "tel:", "#",
]

_SKIP_EXTENSIONS = (
    ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".svg", ".css", ".js",
    ".woff", ".woff2", ".ico", ".zip", ".mp4", ".webp",
)


def _should_skip(url: str, base_host: str) -> bool:
    low = url.lower()
    if any(p in low for p in _SKIP_PATTERNS):
        return True
    if low.endswith(_SKIP_EXTENSIONS):
        return True
    parsed = urlparse(url)
    if parsed.netloc and parsed.netloc != base_host:
        return True  # off-site
    return False


async def _extract_links(page: Page, base_url: str) -> list[str]:
    try:
        hrefs = await page.evaluate(
            """() => Array.from(document.querySelectorAll('a[href]'))
                       .map(a => a.getAttribute('href'))
                       .filter(Boolean)"""
        )
    except Exception:
        return []
    absolute = []
    for h in hrefs:
        try:
            absolute.append(urljoin(base_url, h))
        except Exception:
            continue
    return absolute


async def auto_crawl(
    context: BrowserContext,
    page: Page,
    base_url: str,
    max_pages: int = 25,
    max_seconds: int = 45,
    on_progress=None,
) -> list[str]:
    """
    BFS-crawl same-origin links starting from the current page.
    Returns the list of URLs actually visited.
    The caller should already have request/response listeners attached
    to `context` to capture API calls made during navigation.
    """
    base_host = urlparse(base_url).netloc
    visited: set[str] = set()
    queue: list[str] = [page.url]
    start = time.time()

    while queue and len(visited) < max_pages and (time.time() - start) < max_seconds:
        url = queue.pop(0)
        norm = url.split("#")[0].rstrip("/")
        if norm in visited or _should_skip(url, base_host):
            continue
        visited.add(norm)

        if on_progress:
            on_progress(len(visited), max_pages, url)

        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=8000)
            await asyncio.sleep(0.6)  # let XHR/fetch calls fire
        except Exception:
            continue

        new_links = await _extract_links(page, url)
        for link in new_links:
            n = link.split("#")[0].rstrip("/")
            if n not in visited and not _should_skip(link, base_host) and link not in queue:
                queue.append(link)

    return list(visited)