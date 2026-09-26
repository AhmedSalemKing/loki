"""
Hybrid automated login/register/OTP flow.

Tries fully headless first (zero manual interaction). If a WAF/CAPTCHA
block is detected at any checkpoint, it preserves the cookies collected
so far, kills the headless daemon, relaunches a VISIBLE daemon on the
exact same page, and waits once for the human to clear the challenge —
then resumes the rest of the flow automatically (fill, submit, OTP, crawl).

The browser only ever appears when a challenge genuinely requires a human.
"""
from __future__ import annotations
import asyncio
import json
from urllib.parse import urlparse

from playwright.async_api import async_playwright, Page

from loki.core.browser import daemon
from loki.core.captcha.detector import detect_block
from loki.core.auth.ui_nav import navigate_to_register_form, _js_click, _wait_for_react
from loki.core.session.store import save_session
from loki.core.session.tokens import extract_tokens
from loki.core.recon.crawler import auto_crawl

_EMAIL_SELECTORS = [
    'input[type="email"]', 'input[name*="email" i]', 'input[id*="email" i]',
    'input[autocomplete="email"]', 'input[autocomplete="username"]', 'input[name*="user" i]',
]
_PASSWORD_SELECTORS = ['input[type="password"]']
_SUBMIT_SELECTORS = ['button[type="submit"]', 'input[type="submit"]', 'button[name*="submit" i]']
_OTP_SELECTORS = [
    'input[autocomplete="one-time-code"]', 'input[name*="otp" i]',
    'input[name*="code" i]', 'input[id*="otp" i]',
]


async def _fill_first_visible(page: Page, selectors: list[str], value: str) -> bool:
    for sel in selectors:
        try:
            loc = page.locator(sel).first
            if await loc.count() == 0 or not await loc.is_visible():
                continue
            await loc.fill(value)
            return True
        except Exception:
            continue
    return False


async def _click_submit(page: Page) -> None:
    for sel in _SUBMIT_SELECTORS:
        try:
            loc = page.locator(sel).first
            if await loc.count() and await loc.is_visible():
                await loc.click()
                return
        except Exception:
            continue
    try:
        await page.keyboard.press("Enter")
    except Exception:
        pass


def _attach_listeners(context, discovered: dict, auth_headers_by_host: dict | None = None):
    def _on_request(request):
        try:
            if request.resource_type in ("xhr", "fetch", "script") or "/api/" in request.url:
                discovered[request.url] = {
                    "method": request.method,
                    "resource_type": request.resource_type,
                    "status": None,
                }
            if auth_headers_by_host is not None:
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
            if response.url in discovered:
                discovered[response.url]["status"] = response.status
        except Exception:
            pass

    context.on("request", _on_request)
    context.on("response", _on_response)
    return _on_request, _on_response


async def _switch_to_visible(old_pw, host: str, cookies: list, current_url: str, discovered: dict, auth_headers_by_host: dict | None = None):
    """
    Kill the headless daemon, relaunch VISIBLE with the same cookies loaded,
    navigate back to the same URL, wait once for the human to clear the
    challenge, then return the new (pw, context, page) to resume the flow.
    """
    try:
        await old_pw.stop()
    except Exception:
        pass
    daemon.stop()

    pid, port = daemon.launch(headless=False, host_hint=host)
    pw = await async_playwright().start()
    browser = await pw.chromium.connect_over_cdp(f"http://127.0.0.1:{port}")
    context = browser.contexts[0] if browser.contexts else await browser.new_context()

    if cookies:
        try:
            await context.add_cookies(cookies)
        except Exception:
            pass

    page = context.pages[0] if context.pages else await context.new_page()
    _attach_listeners(context, discovered, auth_headers_by_host)

    try:
        await page.goto(current_url, wait_until="domcontentloaded", timeout=30000)
    except Exception:
        pass

    print("\n⚠ WAF/CAPTCHA challenge detected.")
    print("A browser window opened on the SAME page with your progress preserved.")
    print("Solve the challenge (captcha / verification), then press ENTER here")
    print("— LOKI will continue automatically from where it stopped.")
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, input)

    return pw, context, page


async def auto_login_or_register(
    host: str,
    email: str,
    password: str,
    register: bool = False,
    otp_source: str | None = None,
    otp_max_wait: int = 90,
    crawl: bool = True,
    slot: str = "default",
) -> dict:
    url = f"https://{host}"
    pid, port = daemon.launch(headless=True, host_hint=host, slot=slot)

    pw = await async_playwright().start()
    browser = await pw.chromium.connect_over_cdp(f"http://127.0.0.1:{port}")
    context = browser.contexts[0] if browser.contexts else await browser.new_context()
    page = context.pages[0] if context.pages else await context.new_page()

    discovered: dict[str, dict] = {}
    auth_headers_by_host: dict[str, dict] = {}
    _attach_listeners(context, discovered, auth_headers_by_host)

    switched_to_visible = False

    async def _finish(success: bool, **extra) -> dict:
        await pw.stop()
        return {"success": success, "host": host, "used_visible_fallback": switched_to_visible, **extra}

    try:
        await page.goto(url, wait_until="domcontentloaded", timeout=30000)
    except Exception:
        pass
    await _wait_for_react(page)

    # ── Checkpoint 1: block check right after landing ───────────────────────
    block = await detect_block(page)
    if block.blocked:
        cookies_so_far = await context.cookies()
        pw, context, page = await _switch_to_visible(pw, host, cookies_so_far, page.url, discovered, auth_headers_by_host)
        switched_to_visible = True
        await _wait_for_react(page)

    # ── Navigate to register/login form ─────────────────────────────────────
    log: list[str] = []
    if register:
        nav_result = await navigate_to_register_form(type("B", (), {"page": page})(), page.url)
        log += nav_result.get("log", [])
        if not nav_result.get("success"):
            return await _finish(
                False,
                reason="Could not find registration form automatically",
                suggestion="Try: loki session start <host>  (fully manual mode)",
                log=log,
            )
    else:
        await _js_click(page, ["login", "sign in", "log in", "inloggen", "aanmelden", "account", "mijn account"])
        await asyncio.sleep(1.2)

    filled_email = await _fill_first_visible(page, _EMAIL_SELECTORS, email)
    filled_password = await _fill_first_visible(page, _PASSWORD_SELECTORS, password)

    if not filled_email:
        return await _finish(
            False,
            reason="Could not locate an email/username input field",
            suggestion="Try: loki session start <host>  (fully manual mode)",
        )

    await _click_submit(page)
    await asyncio.sleep(2.5)

    # ── Checkpoint 2: block check right after submit ────────────────────────
    block = await detect_block(page)
    if block.blocked:
        cookies_so_far = await context.cookies()
        pw, context, page = await _switch_to_visible(pw, host, cookies_so_far, page.url, discovered, auth_headers_by_host)
        switched_to_visible = True

    # ── OTP ──────────────────────────────────────────────────────────────────
    if otp_source == "gmail":
        from loki.core.mail.otp import wait_for_otp, load_gmail_config
        cfg = load_gmail_config()
        if not cfg:
            return await _finish(
                False,
                reason="No Gmail config found",
                suggestion="Run: loki mail setup <your-gmail> <app-password>",
            )
        otp = wait_for_otp(cfg["user"], cfg["app_password"], max_wait=otp_max_wait)
        if not otp:
            return await _finish(False, reason="OTP not received within timeout")
        await _fill_first_visible(page, _OTP_SELECTORS, otp)
        await _click_submit(page)
        await asyncio.sleep(2.0)

        # Checkpoint 3: block check after OTP submit
        block = await detect_block(page)
        if block.blocked:
            cookies_so_far = await context.cookies()
            pw, context, page = await _switch_to_visible(pw, host, cookies_so_far, page.url, discovered, auth_headers_by_host)
            switched_to_visible = True

    # ── Auto-crawl to discover endpoints ─────────────────────────────────────
    visited: list[str] = []
    if crawl:
        try:
            visited = await auto_crawl(context, page, page.url, max_pages=25, max_seconds=45)
        except Exception:
            pass

    cookies = await context.cookies()
    local_storage, session_storage = {}, {}
    try:
        local_storage = await page.evaluate("() => Object.fromEntries(Object.entries(localStorage))")
        session_storage = await page.evaluate("() => Object.fromEntries(Object.entries(sessionStorage))")
    except Exception:
        pass

    tokens = extract_tokens(local_storage, session_storage, cookies)
    resolved_host = urlparse(page.url).netloc or host

    save_session(host=host, cookies=cookies, local_storage=local_storage,
                 session_storage=session_storage, auth_headers=auth_headers_by_host, url=page.url, slot=slot)

    endpoints = []
    for full_url, meta in discovered.items():
        p = urlparse(full_url)
        endpoints.append({"url": full_url, "path": p.path, "host": p.netloc,
                          "method": meta["method"], "status": meta["status"],
                          "type": meta["resource_type"]})
    endpoints.sort(key=lambda e: e["path"])

    try:
        from loki.core.session.store import _session_file
        existing = json.loads(_session_file(slot).read_text())
        existing["resolved_host"] = resolved_host
        existing["endpoints"] = endpoints
        _session_file(slot).write_text(json.dumps(existing, indent=2))
    except Exception:
        pass

    return await _finish(
        True,
        resolved_host=resolved_host,
        cookies=len(cookies),
        tokens=len(tokens),
        pages_crawled=len(visited),
        endpoints_found=len(endpoints),
    )