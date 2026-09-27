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
[red]  ▸ SESSION ACTIVE  ▸ AUTHENTICATED  ▸ BROWSER-DRIVEN  ▸ v2.0[/red]
[dim red]▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀[/dim red]"""


def print_banner() -> None:
    console.print(BANNER)


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

_SUB_APPS = {"session", "dump", "req", "mail", "recon", "diff", "sweep", "flow", "secrets"}


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
        print_banner()
        console.print("[dim]Run [bold]loki --help[/bold] for available commands[/dim]")
        run_console()
        raise typer.Exit(0)
    elif tokens[0] in _SUB_APPS:
        cmd = " ".join(tokens[:2]).upper()
        console.print(f"[bold red]☠ LOKI v2[/bold red] [dim]▸[/dim] [bold]{cmd}[/bold]")
    else:
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
            if line in ("help", "h", "?"):
                line = "--help"

            try:
                args = shlex.split(line)
            except ValueError as e:
                console.print(f"[red]Parse error: {e}[/red]")
                continue

            if not args:
                continue
            if args[0] == "loki":
                args = args[1:]

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
