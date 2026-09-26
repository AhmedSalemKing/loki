"""
loki sweep — one-shot Authorization Sweep across every endpoint discovered
during the crawl. Tests each endpoint as: the owner account, an optional
second account, and with zero credentials. Reports only anomalies:
- exposed without auth (unauth status is 2xx and size close to owner's)
- possible IDOR (other account got a near-identical response to the owner)

Safety: GET-only by default (mutations skipped unless --include-mutations),
capped endpoint count, small delay between batches, small batch size —
built to avoid tripping WAFs/rate limits or violating "no automated
high-traffic scanning" bug bounty scope rules.
"""
from __future__ import annotations
import asyncio
import typer
from rich.console import Console
from rich.table import Table

from loki.core.session.store import load_session, get_auth_header_for_host
from loki.core.browser.persistent import (
    connect_daemon, browser_fetch, browser_fetch_unauth,
    NoBrowserSession,
)
try:
    from loki.core.browser.persistent import SameSiteNavigationError
except ImportError:
    class SameSiteNavigationError(Exception):
        pass

console = Console()

SIZE_TOLERANCE = 0.15  # within 15% size counts as "near-identical"


def _sizes_close(a: int, b: int) -> bool:
    if a == 0 and b == 0:
        return True
    if a == 0 or b == 0:
        return False
    return abs(a - b) / max(a, b) <= SIZE_TOLERANCE


def sweep_cmd(
    slot_owner: str = typer.Option("default", "--slot", "--slot-owner", help="Your own authenticated session slot"),
    slot_other: str = typer.Option(None, "--slot-other", help="Optional second account slot to test IDOR against"),
    include_mutations: bool = typer.Option(False, "--include-mutations", help="Also test POST/PUT/DELETE endpoints (DANGEROUS — may trigger real actions)"),
    limit: int = typer.Option(150, "--limit", help="Max endpoints to test (safety cap)"),
    delay: float = typer.Option(0.4, "--delay", help="Seconds to wait between requests (be polite to the target)"),
    show_all: bool = typer.Option(False, "--show-all", help="Show every endpoint tested, not just anomalies"),
):
    """Sweep every discovered endpoint for broken access control (auth bypass + cross-account IDOR)."""
    owner_session = load_session(slot=slot_owner)
    if not owner_session:
        console.print(f"[red]✗ No active session in slot '{slot_owner}' — run: loki session start <host> --slot {slot_owner}[/red]")
        raise typer.Exit(1)

    other_session = load_session(slot=slot_other) if slot_other else None
    if slot_other and not other_session:
        console.print(f"[yellow]⚠ No session in slot '{slot_other}' — continuing without cross-account testing[/yellow]")
        slot_other = None

    endpoints = owner_session.get("endpoints", [])
    if not endpoints:
        console.print("[yellow]⚠ No endpoints recorded in this session. Run 'loki session start' first (it auto-crawls).[/yellow]")
        raise typer.Exit(0)

    seen_paths = set()
    targets = []
    for e in endpoints:
        method = (e.get("method") or "GET").upper()
        path = e.get("path") or ""
        if not path or path in seen_paths:
            continue
        if method != "GET" and not include_mutations:
            continue
        seen_paths.add(path)
        targets.append({"path": path, "method": method, "host": e.get("host")})

    if len(targets) > limit:
        console.print(f"[yellow]⚠ {len(targets)} candidate endpoints found, capping to {limit} for safety (use --limit to raise).[/yellow]")
        targets = targets[:limit]

    if not include_mutations:
        console.print("[dim]Mutation methods (POST/PUT/DELETE) skipped by default — use --include-mutations to test them (be careful on live targets).[/dim]")

    console.print(f"\n[bold red]☠ LOKI AUTHORIZATION SWEEP[/bold red] — {len(targets)} endpoint(s), owner slot: {slot_owner}"
                  + (f", other slot: {slot_other}" if slot_other else "") + "\n")

    async def _run():
        try:
            pw_a, browser_a, page_a = await connect_daemon(host=owner_session.get("resolved_host") or owner_session.get("host"), slot=slot_owner)
        except (NoBrowserSession, SameSiteNavigationError) as e:
            console.print(f"[red]✗ Owner session error: {e}[/red]")
            raise typer.Exit(1)

        page_b = None
        pw_b = None
        if slot_other:
            try:
                pw_b, browser_b, page_b = await connect_daemon(host=other_session.get("resolved_host") or other_session.get("host"), slot=slot_other)
            except (NoBrowserSession, SameSiteNavigationError) as e:
                console.print(f"[yellow]⚠ Other-account session error, skipping cross-account test: {e}[/yellow]")
                page_b = None

        results = []
        default_host = owner_session.get("resolved_host") or owner_session.get("host")
        for t in targets:
            target_host = t.get("host") or default_host
            url = f"https://{target_host}{t['path']}"
            auth_hdrs = get_auth_header_for_host(owner_session, target_host)
            try:
                owner_res = await browser_fetch(page_a, url, method=t["method"], extra_headers=auth_hdrs)
            except Exception as e:
                owner_res = {"status": 0, "size": 0, "error": str(e)}

            other_res = None
            if page_b is not None:
                other_auth_hdrs = get_auth_header_for_host(other_session, target_host) if other_session else {}
                try:
                    other_res = await browser_fetch(page_b, url, method=t["method"], extra_headers=other_auth_hdrs)
                except Exception as e:
                    other_res = {"status": 0, "size": 0, "error": str(e)}

            try:
                unauth_res = await browser_fetch_unauth(page_a, url, method=t["method"])
            except Exception as e:
                unauth_res = {"status": 0, "size": 0, "error": str(e)}

            results.append({"path": t["path"], "method": t["method"],
                             "owner": owner_res, "other": other_res, "unauth": unauth_res})
            await asyncio.sleep(delay)

        await pw_a.stop()
        if pw_b:
            await pw_b.stop()
        return results

    results = asyncio.run(_run())

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Path", width=40)
    table.add_column("Owner", width=8)
    table.add_column("Other", width=8)
    table.add_column("Unauth", width=8)
    table.add_column("Flag")

    flagged = 0
    for r in results:
        owner_status = r["owner"].get("status", 0)
        owner_size = r["owner"].get("size", 0)
        other_status = r["other"].get("status", 0) if r["other"] else None
        other_size = r["other"].get("size", 0) if r["other"] else None
        unauth_status = r["unauth"].get("status", 0)
        unauth_size = r["unauth"].get("size", 0)

        flags = []
        if 200 <= unauth_status < 300 and _sizes_close(owner_size, unauth_size):
            flags.append("[red]⚠ EXPOSED W/O AUTH[/red]")
        if other_status is not None and 200 <= other_status < 300 and _sizes_close(owner_size, other_size):
            flags.append("[yellow]⚠ POSSIBLE IDOR[/yellow]")

        if flags or show_all:
            flagged += 1 if flags else 0
            table.add_row(
                r["path"],
                str(owner_status),
                str(other_status) if other_status is not None else "-",
                str(unauth_status),
                " ".join(flags) if flags else "[dim]ok[/dim]",
            )

    console.print(table)
    console.print(f"\n[bold]{flagged} anomal{'y' if flagged == 1 else 'ies'} found out of {len(results)} endpoint(s) tested[/bold]")
    console.print("[dim]Verify every flagged endpoint manually — matching size/status is a heuristic, not proof "
                  "(some endpoints are meant to be public).[/dim]")
