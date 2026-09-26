"""
loki fuzz — IDOR fuzzer using browser-native fetch().
Runs batches of fetch() calls inside Playwright — bypasses all WAF.
§ID§ / §FUZZ§ / §PARAM§ markers replaced per payload.
"""
from __future__ import annotations
import asyncio
import json
import re
import time
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TaskProgressColumn, TextColumn
from rich.table import Table

from loki.core.session.store import load_session, get_auth_header_for_host
from loki.core.browser.persistent import connect_daemon, browser_fetch_batch, NoBrowserSession, SameSiteNavigationError

console = Console()

FUZZ_MARK = re.compile(r"§(FUZZ|ID|PARAM)§", re.IGNORECASE)
BATCH = 8   # concurrent fetches per page.evaluate() call


def _build_payloads(range_str: str | None, wordlist: str | None) -> list[str]:
    payloads: list[str] = []
    if range_str:
        try:
            lo, hi = range_str.split("-")
            payloads = [str(i) for i in range(int(lo), int(hi) + 1)]
        except ValueError:
            console.print("[red]Invalid range format — use: 1-100[/red]")
            raise typer.Exit(1)
    if wordlist:
        p = Path(wordlist)
        if not p.exists():
            console.print(f"[red]Wordlist not found: {wordlist}[/red]")
            raise typer.Exit(1)
        payloads += p.read_text().splitlines()
    if not payloads:
        console.print("[red]Need --range or --wordlist[/red]")
        raise typer.Exit(1)
    return payloads


def _make_url(template: str, host: str, payload: str) -> str:
    path = FUZZ_MARK.sub(payload, template)
    if path.startswith("http"):
        return path
    return f"https://{host}{path if path.startswith('/') else '/' + path}"


def _filter_status(status_filter: str | None, status: int) -> bool:
    if not status_filter:
        return True
    allowed = [int(s.strip()) for s in status_filter.split(",")]
    return status in allowed


def run_fuzz(
    url_template: str = typer.Argument(..., metavar="{url_template}",
                                        help="URL with §ID§ marker e.g. /api/user/§ID§"),
    range_str: str | None = typer.Option(None, "--range", "-r", help="ID range e.g. 1000-1010"),
    wordlist: str | None = typer.Option(None, "--wordlist", "-w", help="Path to wordlist"),
    method: str = typer.Option("GET", "--method", "-X"),
    diff: bool = typer.Option(False, "--diff", "-D", help="Show only responses different from baseline"),
    filter_status: str | None = typer.Option(None, "--filter-status", "-fs",
                                              help="Show only these status codes e.g. 200,403"),
    filter_size: str | None = typer.Option(None, "--filter-size", "-fz",
                                            help="Hide responses of this exact size"),
    output: str | None = typer.Option(None, "--output", "-o", help="Save results to JSON"),
    no_auth: bool = typer.Option(False, "--no-auth"),
    host_override: str | None = typer.Option(None, "--host", "-H"),
    slot: str = typer.Option("default", "--slot", help="Session slot to use"),
):
    """Fuzz a URL with IDOR testing via browser fetch (bypasses WAF)."""
    session = load_session(slot)
    if not session and not no_auth:
        console.print(f"[red]✗ No active session for slot '{slot}' — run: loki session start --slot {slot} <host>[/red]")
        raise typer.Exit(1)

    host = host_override or (session.get("resolved_host") or session.get("host", "") if session else "")
    payloads = _build_payloads(range_str, wordlist)

    # Build full URL for display
    first_payload = payloads[0]
    sample_url = _make_url(url_template, host, first_payload)
    console.print(f"\n[bold red]☠ LOKI FUZZ[/bold red] — {len(payloads)} payloads → [dim]{sample_url.replace(first_payload, '§§')}[/dim]")
    auth_label = "from session" if (session and not no_auth) else "none"
    console.print(f"[dim]Auth: {auth_label} | Batch: {BATCH} parallel fetches[/dim]\n")

    auth_headers = get_auth_header_for_host(session, host) if session else {}
    results: list[dict[str, Any]] = []
    baseline_size: int | None = None

    async def _run() -> None:
        nonlocal baseline_size
        try:
            pw, browser, page = await connect_daemon(host, slot=slot)
        except (NoBrowserSession, SameSiteNavigationError) as e:
            console.print(f"[red]✗ {e}[/red]")
            raise typer.Exit(1)
        try:
            # Baseline request (first payload) for --diff
            if diff and payloads:
                base_url = _make_url(url_template, host, payloads[0])
                base_batch = await browser_fetch_batch(page, [{"url": base_url, "method": method, "headers": auth_headers}], 1)
                baseline_size = base_batch[0].get("size", 0) if base_batch else None
                console.print(f"[dim]Baseline size: {baseline_size} bytes[/dim]")

            # Process in batches
            with Progress(
                SpinnerColumn(),
                "[progress.description]{task.description}",
                BarColumn(),
                TaskProgressColumn(),
                console=console,
            ) as progress:
                task = progress.add_task(f"  Fuzzing {len(payloads)} payloads...", total=len(payloads))

                for i in range(0, len(payloads), BATCH):
                    chunk = payloads[i:i + BATCH]
                    reqs = [
                        {"url": _make_url(url_template, host, p), "method": method, "headers": auth_headers}
                        for p in chunk
                    ]
                    batch_results = await browser_fetch_batch(page, reqs, BATCH)

                    for payload, res in zip(chunk, batch_results):
                        status = res.get("status", 0)
                        size = res.get("size", 0)
                        url = res.get("url", "")
                        error = res.get("error")

                        # Apply filters
                        if diff and baseline_size is not None and size == baseline_size:
                            progress.advance(task)
                            continue
                        if filter_status and not _filter_status(filter_status, status):
                            progress.advance(task)
                            continue
                        if filter_size and str(size) == filter_size:
                            progress.advance(task)
                            continue

                        results.append({
                            "payload": payload,
                            "status": status,
                            "size": size,
                            "url": url,
                            "error": error,
                        })
                        progress.advance(task)

        finally:
            await pw.stop()

    asyncio.run(_run())

    # Display results table
    if not results:
        console.print("[dim]No interesting responses found.[/dim]")
        return

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Payload", style="dim", width=20)
    table.add_column("Status", width=8)
    table.add_column("Size", width=10)
    table.add_column("URL")

    for r in results:
        status = r["status"]
        color = "green" if 200 <= status < 300 else ("yellow" if 300 <= status < 400 else "red")
        table.add_row(
            r["payload"],
            f"[{color}]{status}[/{color}]",
            str(r["size"]),
            r["url"],
        )

    console.print(table)
    console.print(f"\n[green]Found {len(results)} interesting responses[/green]")

    if output:
        Path(output).write_text(json.dumps(results, indent=2))
        console.print(f"[dim]Results saved → {output}[/dim]")