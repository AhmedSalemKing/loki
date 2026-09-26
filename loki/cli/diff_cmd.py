"""
loki diff — Dual-session IDOR comparator.

Runs the SAME request against two fully-isolated browser slots (e.g.
victim + attacker, each with its own Chrome profile and cookie store)
and prints both results side-by-side with a first-pass verdict.

Verdict logic (status codes only, no deep content analysis):
  - attacker gets 200 on victim-only resource        -> ⚠ POSSIBLE IDOR
  - attacker gets 401/403/404                        -> ✓ Properly protected
  - anything else                                    -> inconclusive
"""
from __future__ import annotations
import asyncio

import typer
from rich.console import Console
from rich.table import Table

from loki.core.session.store import load_session, get_auth_header_for_host
from loki.core.browser.persistent import connect_daemon, browser_fetch, NoBrowserSession, SameSiteNavigationError

console = Console()

_PROTECTED = (401, 403, 404)
_ALLOWED = (200, 201, 204)


def _build_url(session: dict, path: str, host_override: str | None) -> str:
    host = host_override or session.get("resolved_host") or session.get("host", "")
    if path.startswith("http://") or path.startswith("https://"):
        return path
    return f"https://{host}{path if path.startswith('/') else '/' + path}"


async def _fetch_one(host_url: str, method: str, slot: str, extra_headers: dict | None = None) -> dict:
    pw, browser, page = await connect_daemon(host_url, slot=slot)
    try:
        return await browser_fetch(page, host_url, method=method, extra_headers=extra_headers or {})
    finally:
        await pw.stop()


def _status_str(r: dict) -> str:
    st = r.get("status") or 0
    color = "green" if 200 <= st < 300 else ("yellow" if 300 <= st < 400 else "red")
    return f"[{color}]{st}[/{color}]"


def _verdict(a: dict, b: dict) -> tuple[str, str]:
    """Return (label, color). Compares status codes only — first-pass indicator."""
    st_b = b.get("status") or 0
    if st_b in _PROTECTED:
        return "✓ PROPERLY PROTECTED (attacker denied)", "green"
    if st_b in _ALLOWED:
        st_a = a.get("status") or 0
        if st_a in _ALLOWED:
            size_a = a.get("size") or 0
            size_b = b.get("size") or 0
            similar = abs(size_a - size_b) <= max(64, int(size_a * 0.15))
            if similar:
                return "⚠ POSSIBLE IDOR — attacker got identical response", "red"
            return "⚠ POSSIBLE IDOR — attacker got 200 (different response)", "red"
        return "⚠ POSSIBLE IDOR — attacker got 200 on victim's resource", "red"
    if st_b == 0 and b.get("error"):
        return f"ERROR — {b.get('error', '')[:90]}", "yellow"
    return f"◇ INCONCLUSIVE (attacker status {st_b})", "yellow"


def diff_cmd(
    path: str = typer.Argument(..., help="Path or URL to test, e.g. /api/orders/1001"),
    slot_a: str = typer.Option("victim", "--slot-a", help="First slot (resource owner)"),
    slot_b: str = typer.Option("attacker", "--slot-b", help="Second slot (attacker)"),
    method: str = typer.Option("GET", "--method", "-X", help="HTTP method"),
    host_override: str | None = typer.Option(None, "--host", "-H", help="Override host"),
):
    """Same request through two isolated sessions -> IDOR verdict."""
    sa = load_session(slot_a)
    if not sa:
        console.print(f"[red]✗ No session for slot '{slot_a}' — run: loki session start --slot {slot_a} <host>[/red]")
        raise typer.Exit(1)
    sb = load_session(slot_b)
    if not sb:
        console.print(f"[red]✗ No session for slot '{slot_b}' — run: loki session start --slot {slot_b} <host>[/red]")
        raise typer.Exit(1)

    url = _build_url(sa, path, host_override)
    target_host = host_override or sa.get("resolved_host") or sa.get("host", "")
    console.print(f"\n[bold red]☠ LOKI DIFF[/bold red] — [{method}] [dim]{url}[/dim]")
    console.print(f"[dim]slot-a: {slot_a}  |  slot-b: {slot_b}[/dim]\n")

    async def _run() -> tuple[dict, dict]:
        try:
            ra = await _fetch_one(url, method, slot_a, get_auth_header_for_host(sa, target_host))
        except (NoBrowserSession, SameSiteNavigationError) as e:
            console.print(f"[red]✗ {e}[/red]")
            raise typer.Exit(1)
        try:
            rb = await _fetch_one(url, method, slot_b, get_auth_header_for_host(sb, target_host))
        except (NoBrowserSession, SameSiteNavigationError) as e:
            console.print(f"[red]✗ {e}[/red]")
            raise typer.Exit(1)
        return ra, rb

    ra, rb = asyncio.run(_run())

    table = Table(show_header=True, header_style="bold cyan", border_style="dim")
    table.add_column("Slot", width=12)
    table.add_column("Status", width=8)
    table.add_column("Size", justify="right", width=12)
    table.add_column("Error / Notes")

    table.add_row(slot_a, _status_str(ra), f"{ra.get('size') or 0:,} B", (ra.get("error") or "")[:80])
    table.add_row(slot_b, _status_str(rb), f"{rb.get('size') or 0:,} B", (rb.get("error") or "")[:80])
    console.print(table)

    label, color = _verdict(ra, rb)
    console.print(f"[{color}]{label}[/{color}]\n")