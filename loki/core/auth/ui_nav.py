"""
UI navigation — JS-based, React-aware, SPA-compatible.
Waits for hydration before searching. Supports account-icon-only nav (no text).
"""
from __future__ import annotations
import asyncio
from playwright.async_api import Page
from loki.core.browser.manager import BrowserManager

_ACCOUNT_TRIGGERS = [
    "inloggen", "mijn gamma", "mijn account", "account", "aanmelden",
    "profiel", "login", "sign in", "log in", "meld aan", "my account",
    "log aan", "registreer", "registreren",
]

_REGISTER_TRIGGERS = [
    "account aanmaken", "aanmaken", "registreer", "registreren",
    "inschrijven", "nieuw account", "create account", "sign up",
    "register", "nieuwe klant", "gratis account", "maak een account",
    "account maken", "nieuwe gebruiker",
]

_WAIT_FOR_REACT_JS = """
() => new Promise(resolve => {
    // If no pending fetches and DOM stable for 300ms — resolve
    let stable = 0;
    const check = () => {
        const inputs = document.querySelectorAll('input, button, a[href]').length;
        if (inputs > 5) {
            stable++;
            if (stable >= 3) { resolve(true); return; }
        } else {
            stable = 0;
        }
        setTimeout(check, 100);
    };
    setTimeout(check, 200);
    // Hard timeout at 8s
    setTimeout(() => resolve(false), 8000);
})
"""

def _js_find_element(keywords: list[str]) -> str:
    """Generate JS that finds first matching visible clickable element."""
    kw_json = str(keywords).replace("'", '"')
    return f"""
    (() => {{
        const keywords = {kw_json};
        const selectors = [
            'button', 'a', '[role="button"]', '[role="link"]',
            'nav a', 'nav button', 'header a', 'header button',
            '[class*="nav"] a', '[class*="nav"] button',
            '[class*="header"] a', '[class*="header"] button',
            '[class*="account"] a', '[class*="account"] button',
            '[class*="login"] a', '[class*="login"] button',
            '[class*="user"] a', '[class*="user"] button',
            '[aria-label*="account"]', '[aria-label*="login"]',
            '[aria-label*="inloggen"]', '[aria-label*="profiel"]',
        ];
        for (const sel of selectors) {{
            let els;
            try {{ els = document.querySelectorAll(sel); }} catch(e) {{ continue; }}
            for (const el of els) {{
                // Visibility check
                const style = window.getComputedStyle(el);
                if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') continue;
                const rect = el.getBoundingClientRect();
                if (rect.width === 0 || rect.height === 0) continue;
                // Must be in viewport or near-viewport
                if (rect.top > window.innerHeight * 2) continue;

                const text = (el.textContent || '').toLowerCase().replace(/\\s+/g, ' ').trim();
                const aria = (el.getAttribute('aria-label') || '').toLowerCase();
                const title = (el.getAttribute('title') || '').toLowerCase();
                const placeholder = (el.getAttribute('placeholder') || '').toLowerCase();
                const combined = text + ' ' + aria + ' ' + title + ' ' + placeholder;

                if (keywords.some(k => combined.includes(k))) {{
                    // Build unique selector
                    if (el.id) return '#' + CSS.escape(el.id);
                    if (el.getAttribute('data-testid')) return '[data-testid="' + el.getAttribute('data-testid') + '"]';
                    if (el.getAttribute('aria-label')) return '[aria-label="' + el.getAttribute('aria-label') + '"]';
                    // nth-child path
                    const parent = el.parentElement;
                    if (parent) {{
                        const idx = Array.from(parent.children).indexOf(el) + 1;
                        const tag = el.tagName.toLowerCase();
                        return tag + ':nth-child(' + idx + ')';
                    }}
                    return el.tagName.toLowerCase();
                }}
            }}
        }}
        return null;
    }})()
    """


async def _js_click(page: Page, keywords: list[str], timeout_ms: int = 3000) -> bool:
    """Find element via JS and click it. Returns True if clicked."""
    try:
        selector = await asyncio.wait_for(
            page.evaluate(_js_find_element(keywords)),
            timeout=4.0
        )
        if not selector:
            return False
        el = page.locator(selector).first
        await el.scroll_into_view_if_needed(timeout=2000)
        await el.click(timeout=timeout_ms)
        return True
    except Exception:
        return False


async def _wait_for_react(page: Page) -> None:
    """Wait until React has hydrated and DOM is stable."""
    try:
        await asyncio.wait_for(page.evaluate(_WAIT_FOR_REACT_JS), timeout=10.0)
    except Exception:
        await asyncio.sleep(1.5)


async def navigate_to_register_form(browser: BrowserManager, base_url: str) -> dict:
    """
    Navigate to registration form on any SPA or traditional site.
    Total max: ~25 seconds across all strategies.
    """
    page = browser.page
    log = []

    # CRITICAL: Wait for React/Vue/Angular to hydrate before any interaction
    log.append("Waiting for page JS to fully load...")
    await _wait_for_react(page)
    log.append("Page ready — scanning for registration entry points...")

    # ── Strategy 1: Direct register link/button visible NOW ────────────────
    found = await _js_click(page, _REGISTER_TRIGGERS, timeout_ms=2000)
    if found:
        await asyncio.sleep(0.8)
        return {"success": True, "method": "direct_link", "message": "Direct register link", "log": log}

    # ── Strategy 2: Account/login button → dropdown/modal → register ───────
    log.append("Clicking account/login trigger...")
    account_clicked = await _js_click(page, _ACCOUNT_TRIGGERS, timeout_ms=2000)
    if account_clicked:
        log.append("Account trigger clicked — waiting for dropdown/modal...")
        await asyncio.sleep(1.2)  # Wait for animation

        # Re-scan for register link in the now-open dropdown/modal
        reg_found = await _js_click(page, _REGISTER_TRIGGERS, timeout_ms=2000)
        if reg_found:
            await asyncio.sleep(0.8)
            return {"success": True, "method": "dropdown", "message": "Via account dropdown", "log": log}

        log.append("No register link in dropdown — checking for modal...")

    # ── Strategy 3: Look for visible modal/dialog with register option ──────
    try:
        modal_sel = "[role='dialog'], .modal, [class*='modal'], [class*='dialog'], [class*='popup'], [class*='overlay'], [class*='drawer']"
        modal = page.locator(modal_sel).first
        is_vis = await asyncio.wait_for(modal.is_visible(), timeout=2.0)
        if is_vis:
            log.append("Modal detected — scanning for register link inside...")
            reg_found = await _js_click(page, _REGISTER_TRIGGERS, timeout_ms=2000)
            if reg_found:
                await asyncio.sleep(0.8)
                return {"success": True, "method": "modal", "message": "Via modal", "log": log}
    except Exception:
        pass

    # ── Strategy 4: Scroll down + retry (some sites lazy-load account nav) ──
    log.append("Scrolling page to trigger lazy elements...")
    try:
        await page.mouse.wheel(0, 300)
        await asyncio.sleep(0.5)
        await page.mouse.wheel(0, -300)
        await asyncio.sleep(0.5)

        # Retry account click after scroll
        acc2 = await _js_click(page, _ACCOUNT_TRIGGERS, timeout_ms=2000)
        if acc2:
            await asyncio.sleep(1.0)
            reg2 = await _js_click(page, _REGISTER_TRIGGERS, timeout_ms=2000)
            if reg2:
                await asyncio.sleep(0.8)
                return {"success": True, "method": "scroll_trigger", "message": "Via scroll + account", "log": log}
    except Exception:
        pass

    # ── Strategy 5: Known URL patterns for Dutch/international sites ────────
    from urllib.parse import urlparse
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    reg_paths = [
        "/registreren", "/account/registreren", "/registreer",
        "/aanmelden", "/account/aanmaken", "/inschrijven",
        "/signup", "/register", "/auth/register", "/user/register",
        "/account/register", "/create-account", "/join",
    ]
    for path in reg_paths:
        url = base + path
        log.append(f"Trying {url}...")
        try:
            resp = await asyncio.wait_for(
                page.goto(url, wait_until="domcontentloaded"),
                timeout=6.0
            )
            if resp and resp.status < 400:
                current = page.url
                # Make sure we didn't get redirected back to homepage
                if current.rstrip("/") != base.rstrip("/"):
                    await asyncio.sleep(0.6)
                    return {"success": True, "method": "url", "message": f"Found at {url}", "log": log}
        except Exception:
            continue

    # ── Strategy 6: Back to homepage + try keyboard shortcut/ESC then retry ─
    log.append("Returning to homepage for final attempt...")
    try:
        await page.goto(base_url, wait_until="domcontentloaded", timeout=15000)
        await _wait_for_react(page)
        await asyncio.sleep(1.0)

        # Final attempt with fresh page state
        acc3 = await _js_click(page, _ACCOUNT_TRIGGERS + ["account aanmaken", "nieuw"], timeout_ms=3000)
        if acc3:
            await asyncio.sleep(1.5)
            reg3 = await _js_click(page, _REGISTER_TRIGGERS, timeout_ms=3000)
            if reg3:
                await asyncio.sleep(0.8)
                return {"success": True, "method": "fresh_retry", "message": "Via fresh page + account", "log": log}
    except Exception:
        pass

    return {"success": False, "method": "none", "message": "Registration form not found via any strategy", "log": log}