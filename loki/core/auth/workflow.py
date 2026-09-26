"""
AuthWorkflow — Registration and login with:
- Global 120s hard timeout (asyncio.wait_for)
- Rich Live activity display (real-time progress)
- Event-based waits (no arbitrary sleeps)
- Clear failure messages with suggestions
"""
from __future__ import annotations
import asyncio
import json
import time
from datetime import datetime
from typing import Optional
import datetime as _dt

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TaskProgressColumn

from loki.core.browser.manager import BrowserManager
from loki.core.auth.forms import detect_forms, fill_field, click_submit
from loki.core.auth.detector import classify_fields
from loki.core.auth.ui_nav import navigate_to_register_form
from loki.core.storage.database import Database
from loki.models.schema import AuthState, FieldType, Session

console = Console()

_OTP_SIGNALS = [
    "otp", "one-time", "verificatiecode", "verificatie",
    "bevestigingscode", "confirmation code", "check your email",
    "e-mail verstuurd", "mail gestuurd", "controleer uw e-mail",
    "we hebben een e-mail", "we have sent", "check je mail",
    "verify your email", "bevestig",
]
_ERROR_SIGNALS = [
    "al in gebruik", "already exists", "already registered",
    "e-mailadres bestaat", "email already", "account bestaat",
    "ongeldig wachtwoord", "invalid", "onjuist", "incorrect",
    "wachtwoord te kort", "password too short", "probeer opnieuw",
]
_SUCCESS_SIGNALS = [
    "welkom", "welcome", "account aangemaakt", "account created",
    "succesvol geregistreerd", "dashboard", "uitloggen",
]

GLOBAL_TIMEOUT = 120  # seconds hard ceiling


class ActivityDisplay:
    """Rich Live display showing real-time progress of auth operations."""

    def __init__(self, host: str, email: str):
        self.host = host
        self.email = email
        self.start_time = time.monotonic()
        self.stages: list[dict] = []
        self.current_stage = ""
        self.log_lines: list[str] = []
        self._progress_pct = 0
        self._live: Optional[Live] = None

    def _elapsed(self) -> str:
        s = time.monotonic() - self.start_time
        return f"{s:.1f}s"

    def _pct_bar(self, pct: int) -> str:
        filled = int(pct / 5)
        empty = 20 - filled
        return "█" * filled + "░" * empty

    def _render(self) -> Panel:
        elapsed = time.monotonic() - self.start_time
        remaining = max(0, GLOBAL_TIMEOUT - elapsed)
        pct = self._progress_pct

        lines = [
            f"[bold]Target[/bold]   [cyan]{self.host}[/cyan]",
            f"[bold]Email[/bold]    [dim]{self.email}[/dim]",
            f"[bold]Elapsed[/bold]  {elapsed:.1f}s / {GLOBAL_TIMEOUT}s  (remaining: {remaining:.0f}s)",
            f"",
            f"[bold red]{self._pct_bar(pct)}[/bold red]  [bold]{pct}%[/bold]",
            f"",
        ]

        for stage in self.stages:
            icon = {"done": "[green]✓[/green]", "running": "[yellow]●[/yellow]", "failed": "[red]✗[/red]", "waiting": "[dim]○[/dim]"}
            st = icon.get(stage["status"], "○")
            t = f"  [dim]{stage['time']:.1f}s[/dim]" if "time" in stage else ""
            lines.append(f"{st} {stage['name']}{t}")

        if self.log_lines:
            lines.append("")
            lines.append("[dim]Activity[/dim]")
            lines.append("[dim]" + "─" * 44 + "[/dim]")
            for line in self.log_lines[-6:]:
                ts = datetime.now().strftime("%H:%M:%S")
                lines.append(f"[dim]{ts}  {line}[/dim]")

        return Panel(
            "\n".join(lines),
            title="[bold red]LOKI AUTH REGISTER[/bold red]",
            border_style="red",
            width=60,
        )

    def add_stage(self, name: str) -> None:
        for s in self.stages:
            if s["status"] == "running":
                s["status"] = "done"
                s["time"] = time.monotonic() - self.start_time
        # Fill matching pending stage in place, else first waiting one, else append
        stage = None
        for s in self.stages:
            if s["status"] == "waiting" and s["name"] == name:
                stage = s
                break
        if stage is None:
            for s in self.stages:
                if s["status"] == "waiting":
                    stage = s
                    break
        if stage is None:
            stage = {"name": name, "status": "waiting"}
            self.stages.append(stage)
        stage["status"] = "running"
        self.current_stage = name
        if self._live:
            self._live.update(self._render())

    def fail_stage(self) -> None:
        for s in self.stages:
            if s["status"] == "running":
                s["status"] = "failed"
                s["time"] = time.monotonic() - self.start_time
        if self._live:
            self._live.update(self._render())

    def log(self, msg: str) -> None:
        self.log_lines.append(msg)
        if self._live:
            self._live.update(self._render())

    def set_progress(self, pct: int) -> None:
        self._progress_pct = pct
        if self._live:
            self._live.update(self._render())

    def mark_waiting(self) -> None:
        for s in self.stages:
            if s["status"] == "waiting":
                pass
        if self._live:
            self._live.update(self._render())

    def start(self) -> None:
        # Add pending stages
        pending = ["Browser start", "Page load", "Form discovery", "Field detection", "Fill & submit", "Outcome"]
        for p in pending:
            self.stages.append({"name": p, "status": "waiting"})
        self._live = Live(self._render(), console=console, refresh_per_second=4)
        self._live.start()

    def stop(self, success: bool = True) -> None:
        if self._live:
            now = time.monotonic() - self.start_time
            for s in self.stages:
                if s["status"] == "running":
                    s["status"] = "done" if success else "failed"
                    s["time"] = now
            self._live.update(self._render())
            self._live.stop()


class AuthWorkflow:
    def __init__(self, browser: BrowserManager, db: Database):
        self.browser = browser
        self.db = db

    async def register(
        self,
        project_id: int,
        host: str,
        email: str,
        password: str = "TestPass123!",
        first_name: str = "Test",
        last_name: str = "User",
    ) -> dict:
        """Full registration with 120s global timeout and live activity display."""
        display = ActivityDisplay(host, email)
        display.start()
        t0 = time.monotonic()

        try:
            result = await asyncio.wait_for(
                self._register_inner(project_id, host, email, password, first_name, last_name, display),
                timeout=GLOBAL_TIMEOUT,
            )
        except asyncio.TimeoutError:
            display.fail_stage()
            display.log(f"⏱ GLOBAL TIMEOUT ({GLOBAL_TIMEOUT}s) — operation cancelled")
            result = {
                "state": AuthState.FAILED,
                "message": f"Timed out after {GLOBAL_TIMEOUT}s. Check screenshots: ls /tmp/loki_debug/\nTry: loki auth register --debug to see browser",
            }
        except Exception as e:
            display.fail_stage()
            display.log(f"✗ Unexpected error: {e}")
            result = {"state": AuthState.FAILED, "message": str(e)}
        finally:
            succeeded = result.get("state") == AuthState.SUCCESS
            display.set_progress(100 if succeeded else display._progress_pct)
            display.stop(success=succeeded)

        elapsed = time.monotonic() - t0
        console.print(f"\n[dim]Runtime: {elapsed:.1f}s[/dim]")
        return result

    async def _register_inner(
        self, project_id, host, email, password, first_name, last_name, display: ActivityDisplay
    ) -> dict:
        base_url = host if host.startswith("http") else f"https://{host}"
        fill_map = {
            FieldType.EMAIL: email,
            FieldType.PASSWORD: password,
            FieldType.PASSWORD_CONFIRM: password,
            FieldType.FIRST_NAME: first_name,
            FieldType.LAST_NAME: last_name,
            FieldType.USERNAME: email.split("@")[0],
            FieldType.PHONE: "+31612345678",
        }

        # ── Stage 1: Browser start ──────────────────────────────────────
        display.add_stage("Browser start")
        display.set_progress(10)
        display.log("Chromium starting...")
        await self.browser.start()
        display.log("Browser ready")

        # ── Stage 2: Page load ──────────────────────────────────────────
        display.add_stage("Page load")
        display.set_progress(20)
        display.log(f"GET {base_url}")
        try:
            await self.browser.navigate(base_url, wait_until="domcontentloaded", timeout=30000)
            display.log(f"DOM ready — {base_url}")
        except Exception as e:
            display.fail_stage()
            return {"state": AuthState.FAILED, "message": f"Failed to load {base_url}: {e}"}

        # Check for bot protection before doing anything
        from loki.core.captcha.detector import detect_block
        try:
            block = await detect_block(self.browser.page)
        except Exception:
            block = None
        if block and block.blocked:
            display.log(f"⚠ Bot protection: {block.block_type.value}")
            display.log(f"  → {block.description}")
            if not block.can_bypass:
                display.fail_stage()
                return {
                    "state": AuthState.FAILED,
                    "message": f"Blocked by: {block.description}\n{block.suggestion}",
                }
            else:
                display.log("  → Stealth mode active — attempting bypass...")

        await self.browser.screenshot("s1_homepage")

        # ── Stage 3: Form discovery ─────────────────────────────────────
        display.add_stage("Form discovery")
        display.set_progress(35)
        display.log("Searching registration controls...")

        nav_result = await navigate_to_register_form(self.browser, base_url)
        for line in nav_result.get("log", []):
            display.log(line)

        if not nav_result["success"]:
            display.fail_stage()
            await self.browser.screenshot("s3_nav_failed")
            return {
                "state": AuthState.FAILED,
                "message": (
                    f"Registration form not found via any strategy.\n"
                    f"Suggestions:\n"
                    f"  • Run with --debug to inspect manually\n"
                    f"  • Check screenshot: /tmp/loki_debug/s3_nav_failed.png\n"
                    f"  • The site may require JS interaction not yet handled"
                ),
            }

        display.log(f"✓ Form found via: {nav_result['method']}")
        await self.browser.screenshot("s3_form_found")

        # ── Stage 4: Field detection ────────────────────────────────────
        display.add_stage("Field detection")
        display.set_progress(50)
        display.log("Waiting for React form to render...")

        form = await self._wait_for_form(timeout=8.0)
        if not form:
            display.fail_stage()
            await self.browser.screenshot("s4_no_form")
            return {
                "state": AuthState.FAILED,
                "message": "Form found in navigation but no input fields detected after 8s. Screenshot: /tmp/loki_debug/s4_no_form.png",
            }

        classified = classify_fields(form)
        field_summary = ", ".join(f.field_type.value for f in classified)
        display.log(f"Fields: {field_summary}")

        # ── Stage 5: Fill & submit ──────────────────────────────────────
        display.add_stage("Fill & submit")
        display.set_progress(65)

        from loki.core.browser.stealth import human_type, human_delay
        for field in classified:
            value = fill_map.get(field.field_type)
            if value is None:
                continue
            display.log(f"Filling: {field.field_type.value}")
            try:
                # Try human-like typing first (more realistic)
                await human_delay(100, 300)
                await human_type(self.browser.page, field.selector, value)
            except Exception:
                # Fallback to regular fill
                ok = await fill_field(self.browser.page, field.selector, value)
                if not ok:
                    display.log(f"  ⚠ Fill may have failed for {field.field_type.value}")

        display.set_progress(80)
        await self.browser.screenshot("s5_before_submit")
        display.log("Submitting form...")

        try:
            if form.get("submit_selector"):
                await click_submit(self.browser.page, form["submit_selector"])
            else:
                await self.browser.page.keyboard.press("Enter")
        except Exception as e:
            display.log(f"Submit error: {e}")

        # Wait for page to react (use URL change or content change, max 5s)
        try:
            await self.browser.page.wait_for_url(lambda url: url != base_url, timeout=5000)
            display.log(f"Redirected to: {self.browser.page.url}")
        except Exception:
            await asyncio.sleep(2.0)

        await self.browser.screenshot("s5_after_submit")

        # ── Stage 6: Outcome detection ──────────────────────────────────
        display.add_stage("Outcome")
        display.set_progress(90)
        display.log("Analyzing page state...")

        page_text = (await self.browser.page.content()).lower()
        current_url = self.browser.page.url

        for sig in _OTP_SIGNALS:
            if sig in page_text:
                display.log("✓ OTP/email verification detected")
                session = await self._capture_session(project_id, host, email)
                await self.db.upsert_session(session)
                return {
                    "state": AuthState.OTP_REQUIRED,
                    "message": "📧 OTP/Email verification required — check your inbox.",
                    "session_id": session.id,
                }

        for sig in _ERROR_SIGNALS:
            if sig in page_text:
                display.fail_stage()
                display.log(f"✗ Error signal: '{sig}'")
                return {"state": AuthState.FAILED, "message": f"Registration rejected by site: '{sig}'"}

        for sig in _SUCCESS_SIGNALS:
            if sig in page_text or sig in current_url.lower():
                display.log(f"✓ Success signal: '{sig}'")
                session = await self._capture_session(project_id, host, email)
                await self.db.upsert_session(session)
                return {
                    "state": AuthState.SUCCESS,
                    "message": "✓ Registration successful!",
                    "session_id": session.id,
                }

        # URL changed = likely success or OTP
        if current_url != base_url and current_url != f"{base_url}/":
            display.log(f"URL changed → {current_url}")
            state = AuthState.OTP_REQUIRED if any(x in current_url for x in ["verif", "confirm", "otp"]) else AuthState.SUCCESS
            session = await self._capture_session(project_id, host, email)
            await self.db.upsert_session(session)
            return {
                "state": state,
                "message": f"Redirected to: {current_url}",
                "session_id": session.id,
            }

        display.log("⚠ No clear outcome — check screenshot")
        return {
            "state": AuthState.FAILED,
            "message": "Could not determine outcome. Check /tmp/loki_debug/s5_after_submit.png",
        }

    async def login(self, project_id: int, host: str, email: str, password: str) -> dict:
        """Login to existing account."""
        base_url = host if host.startswith("http") else f"https://{host}"

        console.print(f"[cyan]→ Logging in as {email} on {host}...[/cyan]")
        await self.browser.start()
        await self.browser.navigate(base_url, wait_until="domcontentloaded", timeout=30000)
        await asyncio.sleep(1.0)

        login_triggers = ["inloggen", "login", "log in", "sign in", "aanmelden"]
        from loki.core.auth.ui_nav import _js_click
        await _js_click(self.browser.page, login_triggers)
        await asyncio.sleep(0.8)

        form = await self._wait_for_form(timeout=8.0)
        if not form:
            return {"state": AuthState.FAILED, "message": "No login form found"}

        classified = classify_fields(form)
        fill_map = {FieldType.EMAIL: email, FieldType.PASSWORD: password, FieldType.USERNAME: email}
        for field in classified:
            if fill_map.get(field.field_type):
                await fill_field(self.browser.page, field.selector, fill_map[field.field_type])

        if form.get("submit_selector"):
            await click_submit(self.browser.page, form["submit_selector"])

        try:
            await self.browser.page.wait_for_url(lambda url: url != base_url, timeout=5000)
        except Exception:
            await asyncio.sleep(2.0)

        page_text = (await self.browser.page.content()).lower()
        for sig in ["welkom", "welcome", "dashboard", "uitloggen", "logout", "mijn account"]:
            if sig in page_text:
                session = await self._capture_session(project_id, host, email)
                await self.db.upsert_session(session)
                return {"state": AuthState.SUCCESS, "message": "Login successful", "session_id": session.id}

        return {"state": AuthState.FAILED, "message": "Login failed — could not detect success"}

    async def _wait_for_form(self, timeout: float = 8.0) -> Optional[dict]:
        """Poll for form with at least 2 visible input fields."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            forms = await detect_forms(self.browser.page)
            for form in forms:
                if len(form.get("fields", [])) >= 2:
                    return form
            await asyncio.sleep(0.4)
        return None

    async def _capture_session(self, project_id: int, host: str, email: str) -> Session:
        cookies = await self.browser.get_cookies()
        local_storage = await self.browser.get_local_storage("")
        session_storage = await self.browser.get_session_storage()
        auth_headers = await self.browser.get_auth_headers()
        return Session(
            project_id=project_id,
            target_domain=host,
            email=email,
            cookies=json.dumps(cookies),
            local_storage=json.dumps(local_storage),
            session_storage=json.dumps(session_storage),
            auth_headers=json.dumps(auth_headers),
            auth_state=AuthState.SUCCESS,
        )