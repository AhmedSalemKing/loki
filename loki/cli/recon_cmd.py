"""
loki recon suggest — scans discovered endpoints for numeric/UUID-like
path segments and prints ready-to-run `loki fuzz` commands.
"""
from __future__ import annotations
import re
import typer
from rich.console import Console
from rich.table import Table

recon_app = typer.Typer(name="recon", help="Analyze discovered endpoints for IDOR candidates")
console = Console()

_NUMERIC_SEG = re.compile(r'^\d+$')
_UUID_SEG = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)
_HEX_ID_SEG = re.compile(r'^[0-9a-f]{16,}$', re.IGNORECASE)


def _templatize(path: str) -> str | None:
    """Replace numeric/UUID/hex-id path segments with §ID§. Returns None if none found."""
    segments = path.split("/")
    changed = False
    out = []
    for seg in segments:
        if _NUMERIC_SEG.match(seg) or _UUID_SEG.match(seg) or _HEX_ID_SEG.match(seg):
            out.append("§ID§")
            changed = True
        else:
            out.append(seg)
    return "/".join(out) if changed else None


@recon_app.command("suggest")
def recon_suggest(
    slot: str = typer.Option("default", "--slot", help="Session slot to use"),
):
    """Find IDOR-candidate endpoints (numeric/UUID IDs in path) and print fuzz commands."""
    from loki.core.session.store import load_session

    session = load_session(slot=slot)
    if not session:
        console.print(f"[red]✗ No active session in slot '{slot}' — run: loki session start <host> --slot {slot}[/red]")
        raise typer.Exit(1)

    endpoints = session.get("endpoints", [])
    if not endpoints:
        console.print("[yellow]⚠ No endpoints captured yet. Run: loki session start <host>[/yellow]")
        return

    candidates: dict[str, dict] = {}
    for e in endpoints:
        template = _templatize(e["path"])
        if template:
            key = f"{e['method']} {template}"
            candidates[key] = {"method": e["method"], "template": template, "example": e["path"]}

    if not candidates:
        console.print("[yellow]⚠ No numeric/UUID IDs found in captured endpoints.[/yellow]")
        console.print("[dim]Try browsing into a specific order/item detail page during "
                      "'loki session start' so LOKI captures an ID-based URL.[/dim]")
        return

    table = Table(show_header=True, header_style="bold red", title=f"IDOR Candidates ({len(candidates)})")
    table.add_column("Method", width=8)
    table.add_column("Template")
    table.add_column("Example seen")

    for c in candidates.values():
        table.add_row(c["method"], c["template"], c["example"])

    console.print(table)
    console.print("\n[bold]Ready-to-run fuzz commands:[/bold]")
    for c in candidates.values():
        if c["method"] == "GET":
            console.print(f"  [cyan]loki fuzz '{c['template']}' --range 1-500 --diff[/cyan]")


@recon_app.command("hidden")
def recon_hidden(
    slot: str = typer.Option("default", "--slot", help="Session slot to use"),
):
    """Find API endpoints referenced in JS bundles but never called during the crawl."""
    import asyncio, json
    from loki.core.session.store import load_session, SESSION_FILE
    from loki.core.browser.persistent import connect_daemon, NoBrowserSession, SameSiteNavigationError
    from loki.core.recon.js_scanner import scan_js_bundles, diff_hidden_endpoints

    session = load_session(slot=slot)
    if not session:
        console.print(f"[red]✗ No active session in slot '{slot}' — run: loki session start <host> --slot {slot}[/red]")
        raise typer.Exit(1)

    endpoints = session.get("endpoints", [])
    js_urls = [e["url"] for e in endpoints if e.get("type") == "script" or e["url"].endswith(".js")]

    if not js_urls:
        console.print("[yellow]⚠ No JS bundle URLs recorded in this session.[/yellow]")
        console.print("[dim]Re-run 'loki session start' so script requests get recorded.[/dim]")
        raise typer.Exit(0)

    console.print(f"\n[bold red]☠ LOKI HIDDEN ENDPOINTS[/bold red] — scanning {len(js_urls)} JS bundle(s), slot: {slot}\n")

    async def _run():
        try:
            pw, browser, page = await connect_daemon(slot=slot)
        except (NoBrowserSession, SameSiteNavigationError) as e:
            console.print(f"[red]✗ {e}[/red]")
            raise typer.Exit(1)
        try:
            return await scan_js_bundles(page, js_urls)
        finally:
            await pw.stop()

    js_paths_by_file = asyncio.run(_run())
    hidden = diff_hidden_endpoints(js_paths_by_file, endpoints)

    if not hidden:
        console.print("[green]✓ No hidden endpoints found[/green]")
        return

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Path", width=50)
    table.add_column("Found in")
    for h in hidden:
        table.add_row(h["path"], h["found_in"].split("/")[-1][:40])
    console.print(table)
    console.print(f"\n[bold yellow]⚠ {len(hidden)} endpoint(s) referenced in code but never called during crawl[/bold yellow]")
    console.print("[dim]Try them manually with: loki req get <path>[/dim]")

    try:
        existing = json.loads(SESSION_FILE.read_text())
        existing["hidden_endpoints"] = hidden
        SESSION_FILE.write_text(json.dumps(existing, indent=2))
    except Exception:
        pass


@recon_app.command("snapshot")
def recon_snapshot(
    slot: str = typer.Option("default", "--slot", help="Session slot to use"),
    label: str = typer.Option(None, "--label", help="Optional label for this snapshot (e.g. 'before-patch')"),
):
    """Save a point-in-time snapshot of endpoints + JS bundle hashes for later comparison."""
    import asyncio
    from loki.core.session.store import load_session
    from loki.core.browser.persistent import connect_daemon, NoBrowserSession
    from loki.core.recon.snapshot import take_snapshot
    try:
        from loki.core.browser.persistent import SameSiteNavigationError
    except ImportError:
        class SameSiteNavigationError(Exception):
            pass

    session = load_session(slot=slot)
    if not session:
        console.print(f"[red]✗ No active session in slot '{slot}' — run: loki session start <host> --slot {slot}[/red]")
        raise typer.Exit(1)

    endpoints = session.get("endpoints", [])
    js_urls = [e["url"] for e in endpoints if e.get("type") == "script" or e["url"].endswith(".js")]
    host = session.get("resolved_host") or session.get("host")

    async def _run():
        try:
            pw, browser, page = await connect_daemon(host=host, slot=slot)
        except (NoBrowserSession, SameSiteNavigationError) as e:
            console.print(f"[red]✗ {e}[/red]")
            raise typer.Exit(1)
        try:
            return await take_snapshot(page, host, endpoints, js_urls, label=label)
        finally:
            await pw.stop()

    fpath = asyncio.run(_run())
    console.print(f"\n[green]✓ Snapshot saved:[/green] {fpath}")
    console.print(f"[dim]{len(endpoints)} endpoint path(s), {len(js_urls)} JS bundle(s) hashed[/dim]")


@recon_app.command("diff-snapshot")
def recon_diff_snapshot(
    host: str = typer.Argument(..., help="Host to compare snapshots for (e.g. deveway-teal.vercel.app)"),
):
    """Compare the two most recent snapshots for a host and report what changed."""
    import time
    from loki.core.recon.snapshot import list_snapshots, diff_snapshots

    snaps = list_snapshots(host)
    if len(snaps) < 2:
        console.print(f"[yellow]⚠ Need at least 2 snapshots for {host} to diff. "
                      f"Currently have {len(snaps)}. Run 'loki recon snapshot' again later.[/yellow]")
        raise typer.Exit(0)

    old_path, new_path = snaps[-2], snaps[-1]
    result = diff_snapshots(old_path, new_path)

    console.print(f"\n[bold red]☠ LOKI RECON DIFF[/bold red] — {host}")
    age = (result.get("new_taken_at") or 0) - (result.get("old_taken_at") or 0)
    console.print(f"[dim]{old_path.name}  ->  {new_path.name}  ({age:.0f}s apart)[/dim]\n")

    if result["added_paths"]:
        console.print("[green]+ New endpoints:[/green]")
        for p in result["added_paths"]:
            console.print(f"    {p}")
    if result["removed_paths"]:
        console.print("[dim]- Removed endpoints:[/dim]")
        for p in result["removed_paths"]:
            console.print(f"    {p}")
    if result["new_js_files"]:
        console.print("[cyan]+ New JS bundles:[/cyan]")
        for j in result["new_js_files"]:
            console.print(f"    {j}")
    if result.get("missing_js"):
        console.print("[dim]- JS bundles no longer referenced:[/dim]")
        for j in result["missing_js"]:
            console.print(f"    {j}")
    if result["changed_js"]:
        console.print("[yellow]~ Changed JS bundles (new deploy):[/yellow]")
        for j in result["changed_js"]:
            console.print(f"    {j}")

    if not any([result["added_paths"], result["removed_paths"], result["new_js_files"],
                result["changed_js"], result.get("missing_js")]):
        console.print("[dim]No changes detected between the two snapshots.[/dim]")