"""
Connects to the persistent Chrome daemon via CDP.
No fresh browsers, no re-injected cookies — the SAME browser instance
that already passed any WAF/captcha challenge is reused for every command.
"""
from __future__ import annotations
import asyncio
from typing import Any
from urllib.parse import urlparse
from playwright.async_api import async_playwright, Page

from loki.core.browser import daemon


class NoBrowserSession(Exception):
    pass


class SameSiteNavigationError(Exception):
    """Raised when LOKI cannot get the daemon's tab off an internal
    chrome:// or about:blank page onto a real web origin. Fetches from
    such a tab are always blocked by Chrome's own CSP, so continuing
    silently only produces the misleading 'Failed to fetch' error."""


def _is_web_origin(url: str) -> bool:
    try:
        return urlparse(url).scheme in ("http", "https")
    except Exception:
        return False


async def _ensure_same_site(page: Page, host: str) -> None:
    """
    If the daemon tab is parked on a non-web page (chrome://newtab,
    about:blank, edge://...), navigate it to the target host first.
    fetch() must run from a real web origin so the site's own CSP applies
    and the right cookies are sent. Tabs already on an http(s) origin are
    left alone — a different host there is the legitimate CORS case.
    """
    if _is_web_origin(page.url):
        return
    host_url = host if host.startswith("http") else f"https://{host}"

    last_error: Exception | None = None
    for timeout_ms in (15000, 30000):
        try:
            await page.goto(host_url, wait_until="domcontentloaded", timeout=timeout_ms)
            await asyncio.sleep(0.5)
            return
        except Exception as e:
            last_error = e
            continue

    if not _is_web_origin(page.url):
        raise SameSiteNavigationError(
            f"Could not navigate the browser tab off internal page {page.url!r} "
            f"onto {host_url!r} after 2 attempts (last error: {last_error}). "
            f"Fetches from a chrome:// or about:blank tab are always blocked by "
            f"Chrome's own CSP. Try: loki session stop && loki session start {host}"
        )


async def connect_daemon(host: str | None = None, slot: str = "default") -> tuple[Any, Any, Page]:
    """
    Connect to the running Chrome daemon for the given slot.
    Optionally ensure the page is on the target origin (fixes 'Failed to
    fetch' caused by fetch() running from a chrome:// tab under Chrome's
    own CSP).
    Returns (playwright, browser, page). Caller must call `await pw.stop()`
    when done — NEVER call browser.close(), that would kill the real session.
    """
    info = daemon.get_daemon_info(slot)
    if not info or not daemon.is_alive(info["port"]):
        raise NoBrowserSession(
            f"No active browser session for slot '{slot}'. Run: loki session start --slot {slot} <host>"
        )

    pw = await async_playwright().start()
    browser = await pw.chromium.connect_over_cdp(f"http://127.0.0.1:{info['port']}")

    context = browser.contexts[0] if browser.contexts else await browser.new_context()
    page = context.pages[0] if context.pages else await context.new_page()

    if host:
        await _ensure_same_site(page, host)

    return pw, browser, page


async def browser_fetch(
    page: Page,
    url: str,
    method: str = "GET",
    body: str | None = None,
    extra_headers: dict | None = None,
) -> dict:
    """Single fetch() inside the real browser page — full cookie/TLS continuity.

    On failure, also captures Chrome's own console.error output and the
    network-level failure reason (e.g. net::ERR_FAILED, CORS policy text)
    that fetch()'s catch() hides from JS but Chrome still logs/reports.
    """
    fetch_opts: dict[str, Any] = {
        "method": method.upper(),
        "credentials": "include",
        "headers": extra_headers or {},
    }
    if body:
        fetch_opts["body"] = body

    console_lines: list[str] = []
    failed_requests: list[str] = []

    def _on_console(msg):
        try:
            if msg.type in ("error", "warning"):
                console_lines.append(f"[{msg.type}] {msg.text}")
        except Exception:
            pass

    def _on_request_failed(request):
        try:
            if request.url == url:
                failed_requests.append(request.failure or "unknown network failure")
        except Exception:
            pass

    page.on("console", _on_console)
    page.on("requestfailed", _on_request_failed)

    try:
        result = await page.evaluate(
            """async ([url, opts]) => {
                try {
                    const r = await fetch(url, { ...opts, credentials: 'include', redirect: 'follow' });
                    const text = await r.text();
                    const hdrs = {};
                    r.headers.forEach((v, k) => { hdrs[k] = v; });
                    return { status: r.status, body: text, headers: hdrs, size: text.length, error: null };
                } catch(e) {
                    return { status: 0, body: '', headers: {}, size: 0, error: String(e && e.message || e) };
                }
            }""",
            [url, fetch_opts],
        )
    finally:
        await asyncio.sleep(0.3)  # let console/requestfailed events flush
        try:
            page.remove_listener("console", _on_console)
            page.remove_listener("requestfailed", _on_request_failed)
        except Exception:
            pass

    if result.get("error"):
        extra_bits = []
        if failed_requests:
            extra_bits.append(f"network: {'; '.join(failed_requests)}")
        if console_lines:
            extra_bits.append(f"console: {' | '.join(console_lines[-3:])}")
        if extra_bits:
            result["error"] = f"{result['error']} ({'; '.join(extra_bits)})"

    return result


async def browser_fetch_unauth(page: Page, url: str, method: str = "GET") -> dict:
    """
    Same-origin fetch WITHOUT sending cookies or other credentials — used to
    test whether an endpoint answers at all with zero authentication.
    `browser_fetch()` is intentionally left untouched so nothing that already
    works can regress.

    Unlike browser_fetch() this also reports `content_type` and a short body
    prefix. On SPAs almost every unknown path returns the index.html shell
    with 200, so a size-only comparison reports every route as "exposed
    without auth". Callers need the content type to tell that apart from a
    real data-bearing response.
    """
    return await page.evaluate(
        """async ([url, method]) => {
            try {
                const r = await fetch(url, { method, credentials: 'omit', redirect: 'follow' });
                const text = await r.text();
                return {
                    status: r.status,
                    size: text.length,
                    content_type: r.headers.get('content-type') || '',
                    body_prefix: text.slice(0, 300),
                    error: null,
                };
            } catch(e) {
                return { status: 0, size: 0, content_type: '', body_prefix: '',
                         error: String(e && e.message || e) };
            }
        }""",
        [url, method],
    )


async def browser_fetch_batch(page: Page, requests: list[dict], batch_size: int = 8) -> list[dict]:
    """Run up to batch_size fetch() calls concurrently inside the real browser page."""
    return await page.evaluate(
        """async (reqs) => {
            return Promise.all(reqs.map(async req => {
                try {
                    const opts = {
                        method: req.method || 'GET',
                        credentials: 'include',
                        redirect: 'follow',
                        headers: req.headers || {},
                    };
                    if (req.body) opts.body = req.body;
                    const r = await fetch(req.url, opts);
                    const text = await r.text();
                    return { url: req.url, status: r.status, size: text.length, body: text, error: null };
                } catch(e) {
                    return { url: req.url, status: 0, size: 0, body: '', error: String(e && e.message || e) };
                }
            }));
        }""",
        requests[:batch_size],
    )