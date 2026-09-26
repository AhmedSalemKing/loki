"""
loki session — manage persistent browser sessions.
"""
import asyncio
import json
import shutil
import typer
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from loki.core.browser import daemon
from loki.core.session.store import load_session, clear_session, session_exists, SESSION_FILE
from loki.core.session.tokens import extract_tokens

console = Console()
app = typer.Typer(help="Manage browser sessions")


@app.command("start")
def session_start(
    host: str = typer.Argument(..., help="Target host e.g. gamma.nl"),
    auto: bool = typer.Option(False, "--auto", "-a", help="Try automated login/register (headless-first, visible only if blocked)"),
    register: bool = typer.Option(False, "--register", "-r", help="Register a new account instead of logging in"),
    proxy: str = typer.Option("", "--proxy", "-x", help="Proxy URL"),
    email: str = typer.Option("", "--email", help="Email for auto login"),
    password: str = typer.Option("", "--password", help="Password for auto login"),
    otp_source: str = typer.Option("", "--otp-source", help="OTP source e.g. gmail"),
    slot: str = typer.Option("default", "--slot", help="Session slot name (isolated profile, e.g. victim/attacker)"),
):
    """Start a new session. Opens browser for manual login by default."""
    if auto:
        _auto_login(host, email, password, register, otp_source, proxy, slot)
    else:
        _manual_capture(host, proxy, slot)


def _manual_capture(host: str, proxy: str, slot: str) -> None:
    """Open persistent browser daemon for manual auth capture."""
    from loki.core.auth.capture import capture_session
    result = asyncio.run(capture_session(host, proxy=proxy or None, slot=slot))

    tokens = result["tokens"]
    console.print(f"\n[green]✓ Session captured![/green]")
    console.print(f"  Host:    [cyan]{result['host']}[/cyan]")
    console.print(f"  Slot:    [cyan]{slot}[/cyan]")
    console.print(f"  Cookies: {len(result['cookies'])}")
    console.print(f"  Storage: {len(result['local_storage'])} local + {len(result['session_storage'])} session keys")
    console.print(f"  Tokens:  [bold]{len(tokens)}[/bold] auth tokens found")
    if tokens:
        for t in tokens[:3]:
            st = t.get("status", "")
            console.print(f"    [green]✓[/green] {t['key']} [{st}]")
    dinfo = daemon.get_daemon_info(slot)
    if dinfo:
        console.print(f"  Daemon:  [green]running[/green] (pid {dinfo['pid']}, CDP :{dinfo['port']})")
    console.print(f"\n[dim]Run [bold]loki dump --tokens[/bold] to see all tokens[/dim]")


def _auto_login(host: str, email: str, password: str, register: bool, otp_source: str, proxy: str, slot: str) -> None:
    """Hybrid automated login/register — headless first, visible only if blocked."""
    from loki.core.auth.login_flow import auto_login_or_register

    result = asyncio.run(auto_login_or_register(
        host=host,
        email=email,
        password=password,
        register=register,
        otp_source=otp_source or None,
        crawl=True,
        slot=slot,
    ))

    fallback_note = " (needed manual challenge solve once)" if result.get("used_visible_fallback") else ""
    if result.get("success"):
        console.print(f"\n[green]✓ Session captured automatically!{fallback_note}[/green]")
        console.print(f"  Host:     [cyan]{host}[/cyan]")
        console.print(f"  Slot:     [cyan]{slot}[/cyan]")
        console.print(f"  Resolved: [cyan]{result.get('resolved_host', host)}[/cyan]")
        console.print(f"  Cookies:  {result.get('cookies', 0)}")
        console.print(f"  Tokens:   [bold]{result.get('tokens', 0)}[/bold] auth tokens found")
        console.print(f"  Pages:    {result.get('pages_crawled', 0)} crawled")
        console.print(f"  Endpoints:{result.get('endpoints_found', 0)} discovered")
    else:
        console.print(f"[yellow]⚠ Auto flow failed: {result.get('reason', 'unknown')}[/yellow]")
        if result.get("suggestion"):
            console.print(f"[dim]{result['suggestion']}[/dim]")
        console.print(f"[dim]Try manual: loki session start {host}[/dim]")


@app.command("status")
def session_status(slot: str = typer.Option("default", "--slot", help="Session slot name")):
    """Show current session info."""
    s = load_session(slot)
    if not s:
        console.print("[dim]No active session. Run: loki session start <host>[/dim]")
        return
    tokens = extract_tokens(s.get("local_storage", {}), s.get("session_storage", {}), s.get("cookies", []))
    dinfo = daemon.get_daemon_info(slot)
    daemon_line = ""
    if dinfo and daemon.is_alive(dinfo.get("port", 0)):
        daemon_line = f"[bold]Daemon:[/bold]  [green]running[/green] (pid {dinfo['pid']}, CDP :{dinfo['port']})\n"
    else:
        daemon_line = f"[bold]Daemon:[/bold]  [red]NOT running[/red]\n"
    console.print(Panel(
        f"[bold]Host:[/bold]    [cyan]{s['host']}[/cyan]\n"
        f"[bold]Resolved:[/bold] [green]{s.get('resolved_host') or '(not stored)'}[/green]\n"
        f"[bold]URL:[/bold]     [dim]{s.get('url', '?')}[/dim]\n"
        f"{daemon_line}"
        f"[bold]Cookies:[/bold] {len(s.get('cookies', []))}\n"
        f"[bold]Storage:[/bold] {len(s.get('local_storage', {}))} localStorage + {len(s.get('session_storage', {}))} sessionStorage\n"
        f"[bold]Tokens:[/bold]  {len(tokens)} found",
        title="[red]☠ LOKI[/red] — Active Session",
        border_style="red",
    ))


@app.command("save")
def session_save(output: str = typer.Argument(..., help="Output file path e.g. gamma.loki")):
    """Save current session to file for later use."""
    if not session_exists():
        console.print("[red]✗ No active session[/red]")
        raise typer.Exit(1)
    shutil.copy(SESSION_FILE, output)
    console.print(f"[green]✓ Session saved to {output}[/green]")


@app.command("load")
def session_load(input_file: str = typer.Argument(..., help="Session file to load")):
    """Load a previously saved session."""
    shutil.copy(input_file, SESSION_FILE)
    s = load_session()
    console.print(f"[green]✓ Session loaded — host: {s['host']}[/green]")


@app.command("stop")
def session_stop(slot: str = typer.Option("default", "--slot", help="Session slot name")):
    """Clear the active session + stop the persistent browser daemon."""
    killed = daemon.stop(slot)
    clear_session(slot)
    if killed:
        console.print(f"[green]✓ Session cleared — browser daemon stopped (slot: {slot})[/green]")
    else:
        console.print(f"[dim]Session cleared (no running daemon)[/dim]")