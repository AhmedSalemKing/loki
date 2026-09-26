"""
loki secrets scan — scan the active session's localStorage/sessionStorage/
cookies for leaked credentials (AWS keys, Stripe keys, JWTs, generic secrets).
"""
from __future__ import annotations
import typer
from rich.console import Console
from rich.table import Table

from loki.core.session.store import load_session
from loki.core.recon.secret_patterns import scan_text, mask

console = Console()
secrets_app = typer.Typer(help="Scan captured session storage for leaked secrets")


@secrets_app.command("scan")
def scan(
    slot: str = typer.Option("default", "--slot", help="Session slot to scan"),
    show_full: bool = typer.Option(False, "--show-full", help="Show unmasked values (careful!)"),
):
    """Scan localStorage, sessionStorage, and cookies for leaked secrets."""
    session = load_session(slot=slot)
    if not session:
        console.print(f"[red]✗ No active session in slot '{slot}' — run: loki session start <host> --slot {slot}[/red]")
        raise typer.Exit(1)

    all_hits: list[dict] = []
    local_storage = session.get("local_storage", {}) or {}
    session_storage = session.get("session_storage", {}) or {}
    cookies = session.get("cookies", []) or []

    for k, v in local_storage.items():
        all_hits += scan_text("localStorage", k, str(v))
    for k, v in session_storage.items():
        all_hits += scan_text("sessionStorage", k, str(v))
    for c in cookies:
        all_hits += scan_text("cookie", c.get("name", ""), str(c.get("value", "")))

    console.print(f"\n[bold red]☠ LOKI SECRET SCAN[/bold red] — slot: {slot}\n")

    if not all_hits:
        console.print("[green]✓ No known secret patterns found in localStorage/sessionStorage/cookies[/green]")
        console.print("[dim]Note: this only checks browser storage, not JS bundle source. "
                       "See 'loki recon hidden' for JS-based discovery.[/dim]")
        return

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Source", width=16)
    table.add_column("Key", width=24)
    table.add_column("Pattern", width=28)
    table.add_column("Value")

    seen = set()
    for hit in all_hits:
        dedupe_key = (hit["source"], hit["key"], hit["pattern"])
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        display_val = hit["match"] if show_full else mask(hit["match"])
        table.add_row(hit["source"], hit["key"], f"[yellow]{hit['pattern']}[/yellow]", display_val)

    console.print(table)
    console.print(f"\n[bold yellow]⚠ {len(seen)} potential secret(s) found.[/bold yellow]")
    console.print("[dim]Verify manually before reporting — some may be public/test keys "
                  "(e.g. Stripe test keys, public Firebase config) and not real vulnerabilities.[/dim]")
    if not show_full:
        console.print("[dim]Use --show-full to see unmasked values.[/dim]")