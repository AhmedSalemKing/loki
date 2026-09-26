"""
loki race — fire N identical requests at the exact same instant to test
race conditions (coupon reuse, double-spend, vote/limit bypass).
Free alternative to Burp's paid Turbo Intruder extension: true
single-tick concurrency via a real browser's fetch(), not sequential
HTTP client calls.
"""
from __future__ import annotations
import asyncio
import typer
from rich.console import Console
from rich.table import Table

from loki.core.session.store import load_session, get_auth_header_for_host
from loki.core.browser.persistent import connect_daemon, browser_fetch_batch, NoBrowserSession, SameSiteNavigationError

console = Console()

MAX_CONCURRENT = 50


def race_cmd(
    path: str = typer.Argument(..., help="Path or full URL to hit repeatedly"),
    count: int = typer.Option(10, "--count", "-c", help="Number of simultaneous requests"),
    method: str = typer.Option("GET", "--method", "-X"),
    data: str | None = typer.Option(None, "--data", "-d", help="Request body for POST/PUT"),
    header: list[str] = typer.Option([], "--header", "-h", help="Extra header: 'Key: Value'"),
    slot: str = typer.Option("default", "--slot", help="Session slot to use"),
    host_override: str | None = typer.Option(None, "--host", "-H"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be sent, without sending it"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation prompt (for scripting)"),
):
    """Fire N identical requests simultaneously to test for race conditions."""
    if count > MAX_CONCURRENT:
        console.print(f"[yellow]⚠ Capped at {MAX_CONCURRENT} concurrent requests for browser stability[/yellow]")
        count = MAX_CONCURRENT
    if count < 2:
        console.print("[red]✗ --count must be at least 2 to test a race[/red]")
        raise typer.Exit(1)

    session = load_session(slot=slot)
    if not session:
        console.print(f"[red]✗ No active session in slot '{slot}' — run: loki session start <host> --slot {slot}[/red]")
        raise typer.Exit(1)

    host = host_override or session.get("resolved_host") or session.get("host", "")
    url = path if path.startswith("http") else f"https://{host}{path if path.startswith('/') else '/' + path}"

    extra_headers: dict[str, str] = {}
    extra_headers.update(get_auth_header_for_host(session, host))
    for h in header:
        k, _, v = h.partition(":")
        extra_headers[k.strip()] = v.strip()

    if dry_run:
        console.print(f"\n[cyan]DRY RUN — would send {count}x {method} to:[/cyan] {url}")
        if extra_headers:
            console.print(f"[dim]Headers: {extra_headers}[/dim]")
        if data:
            console.print(f"[dim]Body: {data}[/dim]")
        raise typer.Exit(0)

    if not yes:
        console.print(f"\n[bold yellow]⚠ This will send {count} REAL {method} requests to {url}[/bold yellow]")
        console.print("[yellow]If this endpoint changes real data (enroll, purchase, vote, redeem), "
                      "this WILL happen for real, possibly multiple times.[/yellow]")
        if not typer.confirm("Continue?"):
            raise typer.Exit(0)

    requests = [
        {"url": url, "method": method, "headers": extra_headers, "body": data}
        for _ in range(count)
    ]

    console.print(f"\n[bold red]☠ LOKI RACE[/bold red] — firing {count} simultaneous {method} requests")
    console.print(f"[dim]{url}[/dim] [dim](slot: {slot})[/dim]\n")

    async def _run():
        try:
            pw, browser, page = await connect_daemon(host, slot=slot)
        except (NoBrowserSession, SameSiteNavigationError) as e:
            console.print(f"[red]✗ {e}[/red]")
            raise typer.Exit(1)
        try:
            return await browser_fetch_batch(page, requests, batch_size=count)
        finally:
            await pw.stop()

    results = asyncio.run(_run())

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("#", width=4)
    table.add_column("Status", width=8)
    table.add_column("Size", width=10)
    table.add_column("Error")

    success_count = 0
    for i, r in enumerate(results, 1):
        status = r.get("status", 0)
        color = "green" if 200 <= status < 300 else ("yellow" if 300 <= status < 400 else "red")
        if 200 <= status < 300:
            success_count += 1
        table.add_row(str(i), f"[{color}]{status}[/{color}]", str(r.get("size", 0)), r.get("error") or "")

    console.print(table)
    console.print(f"\n[bold]{success_count}/{count} requests succeeded (2xx)[/bold]")

    if success_count > 1:
        console.print(
            "[yellow]⚠ Multiple requests succeeded at the same instant. "
            "If this endpoint should only allow ONE success (redeem a coupon, "
            "withdraw funds, submit a vote, claim a reward), this is a "
            "race condition vulnerability.[/yellow]"
        )
    elif success_count == 1:
        console.print("[green]✓ Only one request succeeded — no race condition on single-use logic[/green]")
    else:
        console.print("[dim]No requests succeeded — check auth/endpoint validity first[/dim]")