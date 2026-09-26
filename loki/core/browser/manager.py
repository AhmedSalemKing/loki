"""
BrowserManager — Singleton Playwright browser instance.
MUST be created once and passed via dependency injection.
Never instantiate Playwright directly in any other module.
"""
from __future__ import annotations
import asyncio
import os
import json
from pathlib import Path
from typing import Optional, Callable, Any
from playwright.async_api import (
    async_playwright, Browser, BrowserContext, Page,
    Playwright, Request as PWRequest, Response as PWResponse
)

DEBUG_DIR = Path("/tmp/loki_debug")


class BrowserManager:
    """
    Singleton browser manager. Call start() once, then pass this instance everywhere.
    Call stop() to cleanly close Playwright.
    """

    def __init__(self, headless: bool = True, slow_mo: int = 0, stealth: bool = True, proxy: str | None = None):
        self.headless = headless
        self.slow_mo = slow_mo
        self.stealth = stealth
        self.proxy = proxy
        self._playwright: Optional[Playwright] = None
        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None
        self._page: Optional[Page] = None
        self._request_interceptors: list[Callable] = []
        self._started = False

    async def start(self) -> None:
        """Launch Playwright and open browser. Call once at application start."""
        if self._started:
            return
        DEBUG_DIR.mkdir(parents=True, exist_ok=True)
        self._playwright = await async_playwright().start()

        from loki.core.browser.stealth import apply_stealth_context, USER_AGENTS, VIEWPORTS
        import random

        launch_args = [
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--disable-setuid-sandbox",
            "--disable-blink-features=AutomationControlled",
            "--disable-features=IsolateOrigins,site-per-process",
            "--allow-running-insecure-content",
            "--disable-web-security",
            "--disable-infobars",
            "--no-default-browser-check",
            "--no-first-run",
            "--window-size=1920,1080",
        ]

        proxy_config = None
        if self.proxy:
            if "://" in self.proxy:
                proxy_config = {"server": self.proxy}
            else:
                proxy_config = {"server": f"socks5://{self.proxy}"}

        self._browser = await self._playwright.chromium.launch(
            headless=self.headless,
            slow_mo=self.slow_mo,
            args=launch_args,
            proxy=proxy_config,
        )

        ua = random.choice(USER_AGENTS)
        viewport = random.choice(VIEWPORTS)

        self._context = await self._browser.new_context(
            user_agent=ua,
            viewport=viewport,
            locale="en-US",
            timezone_id="America/New_York",
            java_script_enabled=True,
            accept_downloads=True,
            ignore_https_errors=True,
        )

        if self.stealth:
            await apply_stealth_context(self._context)
        else:
            # Minimal fallback: hide the most obvious automation trace
            await self._context.add_init_script("""
                Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
                Object.defineProperty(navigator, 'plugins', {get: () => [1,2,3,4,5]});
                window.chrome = {runtime: {}};
            """)

        self._page = await self._context.new_page()
        self._started = True

    async def stop(self) -> None:
        """Close browser and Playwright cleanly."""
        if self._page and not self._page.is_closed():
            await self._page.close()
        if self._context:
            await self._context.close()
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()
        self._started = False

    @property
    def page(self) -> Page:
        if not self._page or self._page.is_closed():
            raise RuntimeError("Browser not started. Call BrowserManager.start() first.")
        return self._page

    @property
    def context(self) -> BrowserContext:
        if not self._context:
            raise RuntimeError("Browser not started. Call BrowserManager.start() first.")
        return self._context

    async def screenshot(self, name: str) -> Path:
        """Take debug screenshot. Returns path. Never crashes."""
        path = DEBUG_DIR / f"{name}.png"
        try:
            await self.page.screenshot(path=str(path), full_page=False, timeout=8000)
        except Exception:
            pass
        return path

    async def get_cookies(self) -> list[dict]:
        """Return all cookies as list of dicts."""
        cookies = await self._context.cookies()
        return [dict(c) for c in cookies]

    async def get_local_storage(self, origin: str) -> dict:
        """Return localStorage for origin."""
        try:
            result = await self.page.evaluate("""
                () => {
                    const data = {};
                    for (let i = 0; i < localStorage.length; i++) {
                        const key = localStorage.key(i);
                        data[key] = localStorage.getItem(key);
                    }
                    return data;
                }
            """)
            return result or {}
        except Exception:
            return {}

    async def get_session_storage(self) -> dict:
        """Return sessionStorage."""
        try:
            result = await self.page.evaluate("""
                () => {
                    const data = {};
                    for (let i = 0; i < sessionStorage.length; i++) {
                        const key = sessionStorage.key(i);
                        data[key] = sessionStorage.getItem(key);
                    }
                    return data;
                }
            """)
            return result or {}
        except Exception:
            return {}

    async def get_auth_headers(self) -> dict:
        """Extract Bearer tokens and auth-related headers from storage."""
        headers: dict[str, str] = {}
        ls = await self.get_local_storage("")
        ss = await self.get_session_storage()

        for storage in [ls, ss]:
            for key, value in storage.items():
                if not isinstance(value, str):
                    continue
                key_lower = key.lower()
                # JWT token detection
                if any(k in key_lower for k in ["token", "jwt", "auth", "access", "bearer"]):
                    if value.startswith("eyJ"):  # JWT prefix
                        headers["Authorization"] = f"Bearer {value}"
                    elif "token" in key_lower:
                        headers[f"X-{key}"] = value
                # API keys
                if "api_key" in key_lower or "apikey" in key_lower:
                    headers["X-API-Key"] = value

        return headers

    async def navigate(self, url: str, wait_until: str = "load", timeout: int = 60000) -> None:
        """Navigate to URL with proper wait."""
        await self.page.goto(url, wait_until=wait_until, timeout=timeout)

    async def evaluate(self, expression: str) -> Any:
        """Evaluate JavaScript expression in page context."""
        return await self.page.evaluate(expression)

    def add_request_interceptor(self, callback: Callable) -> None:
        """Register a callback for all network requests."""
        self._request_interceptors.append(callback)
        self.page.on("request", callback)

    def remove_request_interceptors(self) -> None:
        """Remove all registered interceptors."""
        for cb in self._request_interceptors:
            self.page.remove_listener("request", cb)
        self._request_interceptors.clear()