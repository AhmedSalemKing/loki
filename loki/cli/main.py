"""
LOKI v2 CLI — Terminal-first browser security workspace.
Single asyncio.run() entry point. All commands are async.
Banner prints on EVERY command invocation.
"""
from __future__ import annotations
import asyncio
import sys
import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.text import Text

from loki.core.storage.database import Database
from loki.core.browser.manager import BrowserManager
from loki.core.auth.workflow import AuthWorkflow
from loki.core.network.interceptor import NetworkInterceptor
from loki.models.schema import Finding, AuthState

from loki.cli.session_cmd import app as session_app
from loki.cli.dump_cmd import app as dump_app
from loki.cli.req_cmd import req_app
from loki.cli.fuzz_cmd import run_fuzz
from loki.cli.race_cmd import race_cmd
from loki.cli.secrets_cmd import secrets_app
from loki.cli.mail_cmd import mail_app
from loki.cli.recon_cmd import recon_app
from loki.cli.diff_cmd import diff_cmd
from loki.cli.sweep_cmd import sweep_cmd
from loki.cli.flow_cmd import flow_app

console = Console()

# ──────────────────────────────────────────────
# BANNER (prints on EVERY command, always)
# ──────────────────────────────────────────────
BANNER = """
[bold red]██╗      ██████╗ ██╗  ██╗██╗[/bold red]
[bold red]██║     ██╔═══██╗██║ ██╔╝██║[/bold red]
[bold red]██║     ██║   ██║█████╔╝ ██║[/bold red]
[bold red]██║     ██║   ██║██╔═██╗ ██║[/bold red]
[bold red]███████╗╚██████╔╝██║  ██╗██║[/bold red]
[bold red]╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝[/bold red]
[red]▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄[/red]
[bold red]  ☠   L O C A L  O U T P U T  K E Y  I N T E R C E P T O R   ☠[/bold red]
[red]  ▸ GHOST MODE ACTIVE  ▸ TARGET LOCKED  ▸ ZERO TRACE  ▸ v2.0[/red]
[dim red]▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀[/dim red]"""


def print_banner() -> None:
    console.print(BANNER)


# ──────────────────────────────────────────────
# HELPER: require active project
# ──────────────────────────────────────────────
async def _require_project(db: Database):
    project = await db.get_active_project()
    if not project:
        console.print("[red]✗ No active project. Run: loki project init <name>[/red]")
        raise typer.Exit(1)
    return project


# ──────────────────────────────────────────────
# SUB-APPS
# ──────────────────────────────────────────────
app = typer.Typer(
    name="loki",
    help="LOKI v2 — Terminal-first browser security workspace",
    no_args_is_help=False,
    add_completion=False,
    invoke_without_command=True,
    rich_markup_mode="rich",
)

project_app = typer.Typer(help="Project management")
target_app = typer.Typer(help="Target/scope management")
auth_app = typer.Typer(help="Authentication operations")
network_app = typer.Typer(help="Network traffic capture")
storage_app = typer.Typer(help="Browser storage inspection")
endpoint_app = typer.Typer(help="Endpoint management")
finding_app = typer.Typer(help="Findings and vulnerabilities")
report_app = typer.Typer(help="Report generation")

app.add_typer(project_app, name="project")
app.add_typer(target_app, name="target")
app.add_typer(auth_app, name="auth")
app.add_typer(network_app, name="network")
app.add_typer(storage_app, name="storage")
app.add_typer(endpoint_app, name="endpoint")
app.add_typer(finding_app, name="finding")
app.add_typer(report_app, name="report")
app.add_typer(session_app, name="session", help="Manage browser sessions")
app.add_typer(dump_app, name="dump", help="Extract tokens, cookies, storage")
app.add_typer(req_app, name="req", help="Make authenticated requests via browser context")
app.add_typer(mail_app, name="mail", help="Gmail OTP integration")
app.add_typer(recon_app, name="recon", help="Analyze endpoints for IDOR candidates")
app.command(name="diff", help="Dual-session IDOR comparison (victim vs attacker)")(diff_cmd)
app.command("fuzz")(run_fuzz)
app.command("race")(race_cmd)
app.command("sweep")(sweep_cmd)
app.add_typer(flow_app, name="flow", help="Record and abuse-test multi-step business logic flows")
app.add_typer(secrets_app, name="secrets")


# ──────────────────────────────────────────────
# GLOBAL STATE — set by root callback, used by commands
# ──────────────────────────────────────────────
class _GlobalState:
    proxy: str | None = None
    stealth: bool = True
    debug: bool = False


G = _GlobalState()

_CONSOLE_ACTIVE = False  # True while the interactive REPL is re-invoking app()

_SUB_APPS = {"project", "target", "auth", "network", "storage", "endpoint", "finding", "report", "session", "dump", "req", "mail", "recon", "diff", "sweep", "flow", "secrets"}


# ──────────────────────────────────────────────
# ROOT CALLBACK — full banner only on bare `loki`, compact otherwise
# ──────────────────────────────────────────────
@app.callback()
def main_callback(
    ctx: typer.Context,
    proxy: str | None = typer.Option(None, "--proxy", "-x", help="Proxy URL (e.g. socks5://127.0.0.1:9050 or http://user:pass@host:port)"),
    no_stealth: bool = typer.Option(False, "--no-stealth", help="Disable stealth mode (not recommended)"),
    debug: bool = typer.Option(False, "--debug", "-d", help="Show browser window + verbose output"),
) -> None:
    G.proxy = proxy
    G.stealth = not no_stealth
    G.debug = debug

    if _CONSOLE_ACTIVE:
        # Re-invocation from inside the interactive console — compact header only.
        sub = ctx.invoked_subcommand
        if sub:
            console.print(f"[bold red]☠ LOKI v2[/bold red] [dim]▸[/dim] [bold]{sub.upper()}[/bold]")
        return

    argv = sys.argv[1:]
    tokens: list[str] = []
    skip_next = False
    for a in argv:
        if skip_next:
            skip_next = False
            continue
        if a in ("--proxy", "-x"):
            skip_next = True
            continue
        if a.startswith("-"):
            continue
        tokens.append(a)

    if not tokens:
        # No args — print full banner, then drop into the interactive console
        print_banner()
        console.print("[dim]Run [bold]loki --help[/bold] for available commands[/dim]")
        run_console()
        raise typer.Exit(0)
    elif tokens[0] in _SUB_APPS:
        # Grouped subcommand — app + command
        cmd = " ".join(tokens[:2]).upper()
        console.print(f"[bold red]☠ LOKI v2[/bold red] [dim]▸[/dim] [bold]{cmd}[/bold]")
    else:
        # Top-level command — command name only
        cmd = tokens[0].upper()
        console.print(f"[bold red]☠ LOKI v2[/bold red] [dim]▸[/dim] [bold]{cmd}[/bold]")

    if tokens:
        if G.proxy:
            console.print(f"  [dim]Proxy: {G.proxy}[/dim]")
        if not G.stealth:
            console.print(f"  [yellow]⚠ Stealth disabled[/yellow]")
        if G.debug:
            console.print(f"  [dim]Debug: browser window visible[/dim]")


# ══════════════════════════════════════════════
# PROJECT COMMANDS
# ══════════════════════════════════════════════

@project_app.command("init")
def project_init(name: str, description: str = typer.Argument("")):
    """Initialize a new project and set it as active."""
    async def _run():
        db = Database()
        await db.init()
        try:
            project = await db.create_project(name, description)
            await db.set_active_project(project.id)
            console.print(f"[green]✓ Project '[bold]{name}[/bold]' created and set as active (id={project.id})[/green]")
        except Exception as e:
            if "UNIQUE constraint" in str(e):
                project = await db.get_project(name)
                await db.set_active_project(project.id)
                console.print(f"[yellow]⚠ Project '[bold]{name}[/bold]' already exists — set as active[/yellow]")
            else:
                console.print(f"[red]✗ Error: {e}[/red]")
        finally:
            await db.close()
    asyncio.run(_run())


@project_app.command("list")
def project_list():
    """List all projects."""
    async def _run():
        db = Database()
        await db.init()
        try:
            projects = await db.list_projects()
            active = await db.get_active_project()
            table = Table(title="Projects", border_style="red")
            table.add_column("ID", style="dim")
            table.add_column("Name", style="bold")
            table.add_column("Description")
            table.add_column("Created")
            table.add_column("Active", justify="center")
            for p in projects:
                is_active = "★" if active and p.id == active.id else ""
                table.add_row(str(p.id), p.name, p.description,
                              str(p.created_at)[:16], f"[green]{is_active}[/green]")
            console.print(table)
        finally:
            await db.close()
    asyncio.run(_run())


@project_app.command("use")
def project_use(name: str):
    """Set active project."""
    async def _run():
        db = Database()
        await db.init()
        try:
            project = await db.get_project(name)
            if not project:
                console.print(f"[red]✗ Project '{name}' not found[/red]")
                return
            await db.set_active_project(project.id)
            console.print(f"[green]✓ Active project: [bold]{name}[/bold][/green]")
        finally:
            await db.close()
    asyncio.run(_run())


@project_app.command("status")
def project_status():
    """Show current project status."""
    async def _run():
        db = Database()
        await db.init()
        try:
            project = await db.get_active_project()
            if not project:
                console.print("[red]No active project[/red]")
                return
            targets = await db.get_targets(project.id)
            endpoints = await db.get_endpoints(project.id)
            findings = await db.list_findings(project.id)
            requests = await db.get_requests(project.id, limit=1)

            console.print(Panel(
                f"[bold]{project.name}[/bold]\n"
                f"[dim]{project.description or 'No description'}[/dim]\n\n"
                f"Targets:   [cyan]{len(targets)}[/cyan]\n"
                f"Endpoints: [cyan]{len(endpoints)}[/cyan]\n"
                f"Findings:  [cyan]{len(findings)}[/cyan]",
                title="Active Project",
                border_style="red",
            ))
        finally:
            await db.close()
    asyncio.run(_run())


# ══════════════════════════════════════════════
# TARGET COMMANDS
# ══════════════════════════════════════════════

@target_app.command("add")
def target_add(
    domain: str,
    scope: str = typer.Option("in_scope", "-s", "--scope", help="in_scope|out_of_scope|wildcard"),
):
    """Add a domain to project scope."""
    async def _run():
        db = Database()
        await db.init()
        try:
            project = await _require_project(db)
            t = await db.add_target(project.id, domain, scope)
            console.print(f"[green]✓ Added target: [bold]{domain}[/bold] ({scope})[/green]")
        finally:
            await db.close()
    asyncio.run(_run())


@target_app.command("list")
def target_list():
    """List all targets in scope."""
    async def _run():
        db = Database()
        await db.init()
        try:
            project = await _require_project(db)
            targets = await db.get_targets(project.id)
            table = Table(title="Targets", border_style="red")
            table.add_column("Domain", style="bold cyan")
            table.add_column("Scope Type")
            table.add_column("Notes")
            for t in targets:
                color = "green" if t.scope_type == "in_scope" else "red"
                table.add_row(t.domain, f"[{color}]{t.scope_type}[/{color}]", t.notes)
            console.print(table)
        finally:
            await db.close()
    asyncio.run(_run())


# ══════════════════════════════════════════════
# AUTH COMMANDS
# ══════════════════════════════════════════════

@auth_app.command("register")
def auth_register(
    host: str,
    email: str,
    password: str = typer.Option("TestPass123!", "-p", "--password"),
    first_name: str = typer.Option("Test", "--first-name"),
    last_name: str = typer.Option("User", "--last-name"),
    proxy: str | None = typer.Option(None, "--proxy", "-x", help="Proxy URL e.g. socks5://127.0.0.1:9050"),
    no_stealth: bool = typer.Option(False, "--no-stealth", help="Disable stealth mode"),
    debug: bool = typer.Option(False, "--debug", help="Open visible browser"),
):
    """Register a new account on target site."""
    async def _run():
        db = Database()
        await db.init()
        _debug = debug or G.debug
        _stealth = G.stealth and not no_stealth
        _proxy = proxy or G.proxy
        browser = BrowserManager(headless=not _debug, slow_mo=100 if _debug else 0, stealth=_stealth, proxy=_proxy)
        try:
            project = await _require_project(db)
            workflow = AuthWorkflow(browser, db)
            result = await workflow.register(
                project_id=project.id,
                host=host,
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name,
            )
            state = result["state"]
            msg = result["message"]

            if state == AuthState.SUCCESS:
                console.print(f"[bold green]✓ Registration successful![/bold green]")
                console.print(f"[dim]  {msg}[/dim]")
            elif state == AuthState.OTP_REQUIRED:
                console.print(f"[bold yellow]⚡ OTP/Email verification required[/bold yellow]")
                console.print(f"[dim]  {msg}[/dim]")
                otp = console.input("[cyan]Enter OTP code: [/cyan]")
                console.print(f"[dim]  (OTP submission not yet automated — enter it manually if browser is visible)[/dim]")
            else:
                console.print(f"[bold red]✗ Registration failed: {msg}[/bold red]")
                console.print("[dim]  Check screenshots: ls /tmp/loki_debug/[/dim]")
        finally:
            await browser.stop()
            await db.close()
    asyncio.run(_run())


@auth_app.command("login")
def auth_login(
    host: str,
    email: str,
    password: str,
    debug: bool = typer.Option(False, "--debug"),
):
    """Login to existing account and capture session."""
    async def _run():
        db = Database()
        await db.init()
        browser = BrowserManager(headless=not (debug or G.debug), slow_mo=50 if (debug or G.debug) else 0, stealth=G.stealth, proxy=G.proxy)
        try:
            project = await _require_project(db)
            workflow = AuthWorkflow(browser, db)
            result = await workflow.login(
                project_id=project.id,
                host=host,
                email=email,
                password=password,
            )
            if result["state"] == AuthState.SUCCESS:
                console.print(f"[green]✓ Login successful! Session ID: {result.get('session_id')}[/green]")
            else:
                console.print(f"[red]✗ Login failed: {result['message']}[/red]")
        finally:
            await browser.stop()
            await db.close()
    asyncio.run(_run())


@auth_app.command("status")
def auth_status(host: str):
    """Show current auth session status for a host."""
    async def _run():
        db = Database()
        await db.init()
        try:
            project = await _require_project(db)
            session = await db.get_session(project.id, host)
            if not session:
                console.print(f"[yellow]No session found for {host}[/yellow]")
                return
            headers = json.loads(session.auth_headers)
            cookies = json.loads(session.cookies)
            console.print(Panel(
                f"Host: [bold]{host}[/bold]\n"
                f"Email: [cyan]{session.email}[/cyan]\n"
                f"State: [green]{session.auth_state.value}[/green]\n"
                f"Cookies: [dim]{len(cookies)} stored[/dim]\n"
                f"Auth Headers: [dim]{list(headers.keys()) or 'none'}[/dim]\n"
                f"Updated: [dim]{str(session.updated_at)[:19]}[/dim]",
                title="Auth Session",
                border_style="red",
            ))
        finally:
            await db.close()
    asyncio.run(_run())


# ══════════════════════════════════════════════
# NETWORK COMMANDS
# ══════════════════════════════════════════════

@network_app.command("live")
def network_live(
    url: str,
    duration: int = typer.Option(30, "-t", "--time", help="Capture duration in seconds"),
    debug: bool = typer.Option(False, "--debug"),
):
    """Live network traffic capture — real-time table in terminal."""
    async def _run():
        db = Database()
        await db.init()
        browser = BrowserManager(headless=not (debug or G.debug), stealth=G.stealth, proxy=G.proxy)
        try:
            project = await _require_project(db)
            await browser.start()

            table = Table(title="Live Network Traffic", border_style="red", expand=True)
            table.add_column("Method", style="bold", width=8)
            table.add_column("Status", width=7)
            table.add_column("Path", style="cyan")
            table.add_column("Domain", width=25)
            table.add_column("Time(ms)", width=10)

            entries: list[dict] = []

            def on_traffic(entry: dict) -> None:
                status = entry["status"]
                status_style = "green" if 200 <= status < 300 else "yellow" if 300 <= status < 400 else "red"
                table.add_row(
                    entry["method"],
                    f"[{status_style}]{status}[/{status_style}]",
                    entry["path"],
                    entry["domain"],
                    str(entry["time_ms"]) + "ms",
                )
                entries.append(entry)

            interceptor = NetworkInterceptor(browser.page, db, project.id)
            interceptor.add_live_callback(on_traffic)
            await interceptor.start()

            with Live(table, refresh_per_second=4, console=console):
                await browser.navigate(url)
                await asyncio.sleep(duration)

            await interceptor.stop()
            console.print(f"[green]✓ Captured {interceptor.captured_count} requests in {duration}s[/green]")
        finally:
            await browser.stop()
            await db.close()
    asyncio.run(_run())


@network_app.command("capture")
def network_capture(
    url: str,
    duration: int = typer.Option(60, "-t", "--time"),
    debug: bool = typer.Option(False, "--debug"),
):
    """Capture network traffic silently and store to database."""
    async def _run():
        db = Database()
        await db.init()
        browser = BrowserManager(headless=not (debug or G.debug), stealth=G.stealth, proxy=G.proxy)
        try:
            project = await _require_project(db)
            await browser.start()
            interceptor = NetworkInterceptor(browser.page, db, project.id)
            await interceptor.start()
            console.print(f"[cyan]Capturing traffic for {duration}s on {url}...[/cyan]")
            await browser.navigate(url)
            await asyncio.sleep(duration)
            await interceptor.stop()
            console.print(f"[green]✓ Captured {interceptor.captured_count} unique endpoints[/green]")
        finally:
            await browser.stop()
            await db.close()
    asyncio.run(_run())


# ══════════════════════════════════════════════
# STORAGE / BROWSER STATE COMMANDS
# ══════════════════════════════════════════════

@storage_app.command("list")
def storage_list(
    host: str,
    debug: bool = typer.Option(False, "--debug"),
):
    """Show localStorage and sessionStorage — like DevTools Application tab."""
    async def _run():
        db = Database()
        await db.init()
        browser = BrowserManager(headless=not (debug or G.debug), stealth=G.stealth, proxy=G.proxy)
        try:
            project = await _require_project(db)
            await browser.start()
            url = host if host.startswith("http") else f"https://{host}"
            await browser.navigate(url)
            await asyncio.sleep(2)

            local_storage = await browser.get_local_storage("")
            session_storage = await browser.get_session_storage()

            # localStorage table
            ls_table = Table(title="localStorage", border_style="red")
            ls_table.add_column("Key", style="cyan")
            ls_table.add_column("Value (truncated)", style="dim")
            for k, v in local_storage.items():
                ls_table.add_row(k, str(v)[:120])
            console.print(ls_table)

            # sessionStorage table
            ss_table = Table(title="sessionStorage", border_style="red")
            ss_table.add_column("Key", style="cyan")
            ss_table.add_column("Value (truncated)", style="dim")
            for k, v in session_storage.items():
                ss_table.add_row(k, str(v)[:120])
            console.print(ss_table)
        finally:
            await browser.stop()
            await db.close()
    asyncio.run(_run())


@app.command("cookies")
def cookies_cmd(
    host: str,
    debug: bool = typer.Option(False, "--debug"),
):
    """Show browser cookies for host — like DevTools Cookies tab."""
    async def _run():
        db = Database()
        await db.init()
        browser = BrowserManager(headless=not (debug or G.debug), stealth=G.stealth, proxy=G.proxy)
        try:
            project = await _require_project(db)
            await browser.start()
            url = host if host.startswith("http") else f"https://{host}"
            await browser.navigate(url)
            await asyncio.sleep(2)

            cookies = await browser.get_cookies()
            table = Table(title=f"Cookies — {host}", border_style="red")
            table.add_column("Name", style="bold cyan")
            table.add_column("Value", style="dim", max_width=50)
            table.add_column("Domain")
            table.add_column("Path", width=8)
            table.add_column("HttpOnly", justify="center")
            table.add_column("Secure", justify="center")
            for c in cookies:
                table.add_row(
                    c.get("name", ""),
                    str(c.get("value", ""))[:50],
                    c.get("domain", ""),
                    c.get("path", "/"),
                    "✓" if c.get("httpOnly") else "",
                    "✓" if c.get("secure") else "",
                )
            console.print(table)
        finally:
            await browser.stop()
            await db.close()
    asyncio.run(_run())


@app.command("js")
def js_cmd(
    expression: str,
    host: str = typer.Option("", "-h", "--host"),
    debug: bool = typer.Option(False, "--debug"),
):
    """Evaluate JavaScript in browser context — like DevTools Console."""
    async def _run():
        db = Database()
        await db.init()
        browser = BrowserManager(headless=not (debug or G.debug), stealth=G.stealth, proxy=G.proxy)
        try:
            await browser.start()
            if host:
                url = host if host.startswith("http") else f"https://{host}"
                await browser.navigate(url)
                await asyncio.sleep(2)
            result = await browser.evaluate(expression)
            console.print(Panel(
                str(result),
                title="[bold red]JS Result[/bold red]",
                border_style="red",
            ))
        finally:
            await browser.stop()
            await db.close()
    asyncio.run(_run())


# ══════════════════════════════════════════════
# ENDPOINT COMMANDS
# ══════════════════════════════════════════════

@endpoint_app.command("list")
def endpoint_list(
    domain: str = typer.Option("", "-d", "--domain"),
    method: str = typer.Option("", "-m", "--method"),
):
    """List discovered endpoints."""
    async def _run():
        db = Database()
        await db.init()
        try:
            project = await _require_project(db)
            endpoints = await db.get_endpoints(project.id, domain or None)
            if method:
                endpoints = [e for e in endpoints if e.method.upper() == method.upper()]

            table = Table(title="Endpoints", border_style="red", expand=True)
            table.add_column("Method", style="bold", width=8)
            table.add_column("Path", style="cyan")
            table.add_column("Domain", width=25)
            table.add_column("Hits", justify="right", width=6)
            table.add_column("Last Seen", width=16)
            for ep in endpoints:
                method_style = {
                    "GET": "green", "POST": "yellow", "PUT": "blue",
                    "DELETE": "red", "PATCH": "magenta"
                }.get(ep.method, "white")
                table.add_row(
                    f"[{method_style}]{ep.method}[/{method_style}]",
                    ep.path,
                    ep.target_domain,
                    str(ep.hit_count),
                    str(ep.last_seen)[:16],
                )
            console.print(table)
            console.print(f"[dim]Total: {len(endpoints)} endpoints[/dim]")
        finally:
            await db.close()
    asyncio.run(_run())


@endpoint_app.command("show")
def endpoint_show(endpoint_id: int):
    """Show detailed info for an endpoint including recent requests."""
    async def _run():
        db = Database()
        await db.init()
        try:
            project = await _require_project(db)
            requests = await db.get_requests(project.id, limit=200)
            ep_requests = [r for r in requests if r.endpoint_id == endpoint_id][:10]
            if not ep_requests:
                console.print(f"[yellow]No captured requests for endpoint #{endpoint_id}[/yellow]")
                return
            for r in ep_requests:
                console.print(Panel(
                    f"[bold]{r.method} {r.url}[/bold]\n"
                    f"Status: [{'green' if r.response_status < 300 else 'red'}]{r.response_status}[/]\n"
                    f"Time: {r.response_time_ms}ms\n"
                    f"Headers: {r.request_headers[:200]}\n"
                    f"Body: {r.request_body[:500] or '[empty]'}",
                    title=f"Request #{r.id}",
                    border_style="red",
                ))
        finally:
            await db.close()
    asyncio.run(_run())


# ══════════════════════════════════════════════
# FINDING COMMANDS
# ══════════════════════════════════════════════

@finding_app.command("add")
def finding_add(
    title: str,
    severity: str = typer.Option("medium", "-s", "--severity"),
    category: str = typer.Option("", "-c", "--category"),
    description: str = typer.Option("", "-d", "--desc"),
):
    """Add a new finding/vulnerability."""
    async def _run():
        db = Database()
        await db.init()
        try:
            project = await _require_project(db)
            finding = Finding(
                project_id=project.id,
                title=title,
                severity=severity,
                category=category,
                description=description,
            )
            finding = await db.create_finding(finding)
            console.print(f"[green]✓ Finding #{finding.id} created: [bold]{title}[/bold] [{severity}][/green]")
        finally:
            await db.close()
    asyncio.run(_run())


@finding_app.command("list")
def finding_list():
    """List all findings for current project."""
    async def _run():
        db = Database()
        await db.init()
        try:
            project = await _require_project(db)
            findings = await db.list_findings(project.id)
            table = Table(title="Findings", border_style="red")
            table.add_column("ID", width=5)
            table.add_column("Severity", width=10)
            table.add_column("Title", style="bold")
            table.add_column("Category")
            table.add_column("Status")
            SEV_COLORS = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan", "info": "dim"}
            for f in findings:
                color = SEV_COLORS.get(f.severity, "white")
                table.add_row(str(f.id), f"[{color}]{f.severity}[/{color}]",
                              f.title, f.category, f.status)
            console.print(table)
        finally:
            await db.close()
    asyncio.run(_run())


@finding_app.command("show")
def finding_show(finding_id: int):
    """Show detailed finding information."""
    async def _run():
        db = Database()
        await db.init()
        try:
            finding = await db.get_finding(finding_id)
            if not finding:
                console.print(f"[red]Finding #{finding_id} not found[/red]")
                return
            console.print(Panel(
                f"[bold]{finding.title}[/bold]\n\n"
                f"Severity: [bold]{finding.severity}[/bold]\n"
                f"Category: {finding.category}\n"
                f"Status: {finding.status}\n"
                f"CVSS: {finding.cvss_score}\n\n"
                f"Description:\n{finding.description}\n\n"
                f"Notes:\n{finding.notes}",
                title=f"Finding #{finding.id}",
                border_style="red",
            ))
        finally:
            await db.close()
    asyncio.run(_run())


# ══════════════════════════════════════════════
# REPORT COMMANDS
# ══════════════════════════════════════════════

@report_app.command("export")
def report_export(
    output: str = typer.Option("report.md", "-o", "--output"),
    fmt: str = typer.Option("markdown", "-f", "--format", help="markdown|json"),
):
    """Export findings report to file."""
    async def _run():
        import datetime as _dt
        db = Database()
        await db.init()
        try:
            project = await _require_project(db)
            findings = await db.list_findings(project.id)
            targets = await db.get_targets(project.id)
            endpoints = await db.get_endpoints(project.id)

            if fmt == "json":
                data = {
                    "project": project.name,
                    "generated": str(_dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None)),
                    "findings": [f.model_dump() for f in findings],
                    "targets": [t.model_dump() for t in targets],
                    "endpoints": [e.model_dump() for e in endpoints],
                }
                Path(output).write_text(json.dumps(data, indent=2, default=str))
            else:
                lines = [
                    f"# LOKI Security Report — {project.name}\n",
                    f"Generated: {_dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None).strftime('%Y-%m-%d %H:%M UTC')}\n\n",
                    f"## Scope\n",
                ]
                for t in targets:
                    lines.append(f"- `{t.domain}` ({t.scope_type})\n")
                lines.append(f"\n## Summary\n")
                lines.append(f"- **Findings:** {len(findings)}\n")
                lines.append(f"- **Endpoints:** {len(endpoints)}\n\n")
                lines.append(f"## Findings\n\n")
                for f in findings:
                    lines.append(f"### [{f.severity.upper()}] {f.title}\n\n")
                    lines.append(f"**Category:** {f.category}  \n")
                    lines.append(f"**Status:** {f.status}  \n")
                    lines.append(f"**CVSS:** {f.cvss_score}\n\n")
                    if f.description:
                        lines.append(f"{f.description}\n\n")
                    lines.append("---\n\n")
                Path(output).write_text("".join(lines))

            console.print(f"[green]✓ Report exported to [bold]{output}[/bold] ({len(findings)} findings)[/green]")
        finally:
            await db.close()
    asyncio.run(_run())


# ══════════════════════════════════════════════
# TEST COMMANDS
# ══════════════════════════════════════════════

@app.command("test")
def test_idor(
    endpoint_path: str,
    start_id: int = typer.Option(1, "--start"),
    count: int = typer.Option(10, "--count"),
    base_url: str = typer.Option("", "--base"),
):
    """Test for IDOR vulnerabilities by iterating IDs on an endpoint."""
    async def _run():
        import httpx
        db = Database()
        await db.init()
        try:
            project = await _require_project(db)
            session_records = await db.get_requests(project.id, limit=50)

            # Try to get auth headers from most recent session
            auth_headers: dict = {}
            if session_records:
                req = session_records[0]
                req_h = json.loads(req.request_headers)
                if "authorization" in {k.lower() for k in req_h}:
                    for k, v in req_h.items():
                        if k.lower() == "authorization":
                            auth_headers["Authorization"] = v

            console.print(f"[cyan]Testing IDOR on {endpoint_path} (IDs {start_id}–{start_id + count - 1})[/cyan]")
            table = Table(title="IDOR Test Results", border_style="red")
            table.add_column("ID", width=8)
            table.add_column("Status", width=8)
            table.add_column("Response Size", width=14)
            table.add_column("Note")

            base = base_url or ""
            async with httpx.AsyncClient(headers=auth_headers, follow_redirects=True) as client:
                for id_val in range(start_id, start_id + count):
                    path = endpoint_path.replace("{id}", str(id_val))
                    url = base + path
                    try:
                        resp = await client.get(url, timeout=10)
                        size = len(resp.content)
                        status = resp.status_code
                        status_style = "green" if status == 200 else "yellow" if status < 400 else "red"
                        note = "⚠ Potential IDOR!" if status == 200 and size > 50 else ""
                        table.add_row(str(id_val), f"[{status_style}]{status}[/{status_style}]",
                                      f"{size} bytes", f"[yellow]{note}[/yellow]")
                    except httpx.RequestError as e:
                        table.add_row(str(id_val), "[red]ERR[/red]", "-", str(e)[:40])

            console.print(table)
        finally:
            await db.close()
    asyncio.run(_run())


# ══════════════════════════════════════════════
# INTERACTIVE CONSOLE (like msfconsole)
# ══════════════════════════════════════════════

def run_console() -> None:
    """Interactive REPL — type commands directly, no 'loki' prefix needed."""
    import shlex
    global _CONSOLE_ACTIVE
    _CONSOLE_ACTIVE = True

    console.print("[dim]Type 'help' for commands, 'exit' or 'quit' to leave.[/dim]")
    console.print("[dim]Session state persists across commands (daemon stays alive).[/dim]\n")

    try:
        while True:
            try:
                line = console.input("[bold red]loki[/bold red][dim]>[/dim] ").strip()
            except (EOFError, KeyboardInterrupt):
                console.print()
                break

            if not line:
                continue
            if line in ("exit", "quit", "q"):
                break
            if line in ("clear", "cls"):
                console.clear()
                continue

            try:
                args = shlex.split(line)
            except ValueError as e:
                console.print(f"[red]Parse error: {e}[/red]")
                continue

            if not args:
                continue
            if args[0] == "loki":
                args = args[1:]  # tolerate "loki session start ..." inside the shell too

            try:
                app(prog_name="loki", args=args, standalone_mode=False)
            except SystemExit:
                pass
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")
    finally:
        _CONSOLE_ACTIVE = False

    console.print("[dim]Bye.[/dim]")


# ══════════════════════════════════════════════
# ENTRY POINT — asyncio.run() called ONCE here
# ══════════════════════════════════════════════

def app_entry() -> None:
    """
    Single entry point for LOKI.
    asyncio.run() is only called inside each command's async wrapper.
    Typer itself is synchronous; each command calls asyncio.run(_run()) internally.
    """
    app()


if __name__ == "__main__":
    app_entry()