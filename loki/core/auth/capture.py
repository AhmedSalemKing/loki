"""
Manual session capture — launches the PERSISTENT Chrome daemon.
While the user logs in, LOKI listens to EVERY network request the page
makes (via Playwright's request/response events) and records the API
endpoints automatically. No manual DevTools digging needed afterward —
run `loki dump endpoints` to see everything the site actually called.
"""
from __future__ import annotations
import asyncio
from urllib.parse import urlparse
from playwright.async_api import async_playwright

from loki.core.browser import daemon
from loki.core.session.store import save_session
from loki.core.session.tokens import extract_tokens
from loki.core.recon.crawler import auto_crawl


def _is_api_like(url: str, resource_type: str) -> bool:
    """Heuristic: keep XHR/fetch calls, skip static assets."""
    if resource_type in ("xhr", "fetch", "script"):
        return True
    if resource_type in ("document", "stylesheet", "image", "font", "media"):
        return False
    return "/api/" in url or "/graphql" in url


async def capture_session(host: str, proxy: str | None = None, slot: str = "default") -> dict:
    url = f"https://{host}"

    pid, port = daemon.launch(headless=False, host_hint=host, slot=slot)

    pw = await async_playwright().start()
    browser = await pw.chromium.connect_over_cdp(f"http://127.0.0.1:{port}")
    context = browser.contexts[0] if browser.contexts else await browser.new_context()
    page = context.pages[0] if context.pages else await context.new_page()

    # ── Endpoint discovery: listen to every request the site makes ─────────
    discovered: dict[str, dict] = {}  # url -> {method, status, resource_type}
    auth_headers_by_host: dict[str, dict] = {}  # host -> {header_name: value}

    def _on_request(request):
        try:
            if _is_api_like(request.url, request.resource_type):
                discovered[request.url] = {
                    "method": request.method,
                    "resource_type": request.resource_type,
                    "status": None,
                }
            headers = request.headers
            for key in ("authorization", "x-auth-token", "x-access-token", "x-api-key"):
                if key in headers:
                    host_key = urlparse(request.url).netloc
                    if host_key and host_key not in auth_headers_by_host:
                        auth_headers_by_host[host_key] = {key: headers[key]}
                    break
        except Exception:
            pass

    def _on_response(response):
        try:
            u = response.url
            if u in discovered:
                discovered[u]["status"] = response.status
        except Exception:
            pass

    # Attach listeners to ALL current and future pages in this context
    context.on("request", _on_request)
    context.on("response", _on_response)

    try:
        await page.goto(url, wait_until="domcontentloaded", timeout=30000)
    except Exception:
        pass

    print(f"\nOpening {url}...")
    print("Browser opened — LOG IN NOW. Once you're logged in, press ENTER here")
    print("and LOKI will auto-crawl the site itself (no manual clicking needed).")
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, input)

    print("\nAuto-crawling site (up to 25 pages, ~45s)...")

    def _progress(n, total, current_url):
        print(f"  [{n}/{total}] {current_url}")

    try:
        visited = await auto_crawl(context, page, page.url, max_pages=25, max_seconds=45, on_progress=_progress)
        print(f"✓ Crawled {len(visited)} pages")
    except Exception as e:
        print(f"⚠ Crawl error (continuing anyway): {e}")

    print("\nCapturing session...")

    cookies = await context.cookies()

    local_storage = {}
    session_storage = {}
    try:
        local_storage = await page.evaluate(
            "() => Object.fromEntries(Object.entries(localStorage))"
        )
        session_storage = await page.evaluate(
            "() => Object.fromEntries(Object.entries(sessionStorage))"
        )
    except Exception:
        pass

    tokens = extract_tokens(local_storage, session_storage, cookies)

    # Detach listeners
    try:
        context.remove_listener("request", _on_request)
        context.remove_listener("response", _on_response)
    except Exception:
        pass

    resolved_host = urlparse(page.url).netloc or host

    # Build clean endpoint list (dedup by path, keep methods)
    endpoints = []
    for full_url, meta in discovered.items():
        parsed = urlparse(full_url)
        endpoints.append({
            "url": full_url,
            "path": parsed.path,
            "host": parsed.netloc,
            "method": meta["method"],
            "status": meta["status"],
            "type": meta["resource_type"],
        })
    endpoints.sort(key=lambda e: e["path"])

    session_data = {
        "host": host,
        "slot": slot,
        "resolved_host": resolved_host,
        "url": page.url,
        "cookies": cookies,
        "local_storage": local_storage,
        "session_storage": session_storage,
        "tokens": tokens,
        "endpoints": endpoints,
        "daemon_port": port,
        "daemon_pid": pid,
    }

    save_session(
        host=host,
        cookies=cookies,
        local_storage=local_storage,
        session_storage=session_storage,
        auth_headers=auth_headers_by_host,
        url=page.url,
        slot=slot,
    )

    # Persist endpoints + resolved_host into the slot's session file too
    # (save_session may not accept these kwargs — patch the file directly)
    from loki.core.session.store import _session_file
    import json
    try:
        existing = json.loads(_session_file(slot).read_text())
        existing["endpoints"] = endpoints
        existing["resolved_host"] = resolved_host
        _session_file(slot).write_text(json.dumps(existing, indent=2))
    except Exception:
        pass

    # Disconnect CDP without closing the real browser
    await pw.stop()

    return session_data