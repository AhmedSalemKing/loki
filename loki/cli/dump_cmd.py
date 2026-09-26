"""
loki dump — extract everything from captured browser session.
No browser needed — reads from saved session file.
"""
import json
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from loki.core.session.store import load_session, get_session_host
from loki.core.session.tokens import extract_tokens

console = Console()
app = typer.Typer(help="Extract data from captured session")


def _require_session(slot: str = "default"):
    s = load_session(slot)
    if not s:
        console.print(f"[red]✗ No active session in slot '{slot}'. Run:[/red] "
                      f"[bold]loki session start <host> --slot {slot}[/bold]")
        raise typer.Exit(1)
    return s


_SLOT_OPTION = typer.Option("default", "--slot", help="Session slot to use")


@app.command("tokens")
def dump_tokens(
    raw: bool = typer.Option(False, "--raw", help="Print raw token values"),
    copy: bool = typer.Option(False, "--copy", "-c", help="Copy first token to clipboard"),
    filter_key: str = typer.Option("", "--filter", "-f", help="Filter by key name"),
    slot: str = _SLOT_OPTION,
):
    """Extract and display all auth tokens (JWT, Bearer, API keys)."""
    s = _require_session(slot)
    tokens = extract_tokens(s["local_storage"], s["session_storage"], s["cookies"])

    if filter_key:
        tokens = [t for t in tokens if filter_key.lower() in t["key"].lower()]

    if not tokens:
        console.print("[yellow]⚠ No auth tokens found in session[/yellow]")
        return

    table = Table(title=f"Auth Tokens — {s['host']}", border_style="red", show_lines=True)
    table.add_column("Source", style="dim", width=14)
    table.add_column("Key", style="cyan", width=22)
    table.add_column("Type", width=8)
    table.add_column("Preview / Status", style="white")

    for t in tokens:
        status = t.get("status", "")
        subject = t.get("subject", "")
        preview = t["preview"]
        detail = f"{preview}"
        if status:
            color = "red" if "EXPIRED" in status else "green" if "valid" in status else "yellow"
            detail += f"\n  [{color}]{status}[/{color}]"
        if subject:
            detail += f"\n  [dim]sub: {subject}[/dim]"

        table.add_row(t["source"], t["key"], t["type"], detail)

    console.print(table)

    if raw:
        console.print("\n[bold]Raw values:[/bold]")
        for t in tokens:
            console.print(f"\n[cyan]{t['key']}[/cyan]:")
            console.print(t["value"])

    if copy and tokens:
        try:
            import subprocess
            subprocess.run(["xclip", "-selection", "clipboard"],
                           input=tokens[0]["value"].encode(), check=True)
            console.print(f"\n[green]✓ Copied {tokens[0]['key']} to clipboard[/green]")
        except Exception:
            console.print(f"\n[dim]First token: {tokens[0]['value'][:80]}...[/dim]")


@app.command("storage")
def dump_storage(
    source: str = typer.Option("all", "--source", "-s", help="local|session|all"),
    filter_key: str = typer.Option("", "--filter", "-f", help="Filter keys by pattern"),
    json_out: bool = typer.Option(False, "--json", "-j", help="Output as JSON"),
    slot: str = _SLOT_OPTION,
):
    """Dump localStorage and sessionStorage contents."""
    s = _require_session(slot)
    data = {}

    if source in ("local", "all"):
        data["localStorage"] = s.get("local_storage", {})
    if source in ("session", "all"):
        data["sessionStorage"] = s.get("session_storage", {})

    if filter_key:
        for k in data:
            data[k] = {key: val for key, val in data[k].items()
                       if filter_key.lower() in key.lower()}

    if json_out:
        console.print_json(json.dumps(data))
        return

    for store_name, store_data in data.items():
        if not store_data:
            console.print(f"[dim]{store_name}: empty[/dim]")
            continue
        table = Table(title=store_name, border_style="dim", show_lines=False)
        table.add_column("Key", style="cyan", width=30)
        table.add_column("Value", style="white")

        for key, val in store_data.items():
            val_str = str(val)
            display = val_str[:80] + "..." if len(val_str) > 80 else val_str
            table.add_row(key, display)

        console.print(table)


@app.command("cookies")
def dump_cookies(
    filter_key: str = typer.Option("", "--filter", "-f", help="Filter by name"),
    show_value: bool = typer.Option(False, "--values", "-v", help="Show full cookie values"),
    json_out: bool = typer.Option(False, "--json", "-j", help="Output as JSON"),
    slot: str = _SLOT_OPTION,
):
    """List all cookies from captured session."""
    s = _require_session(slot)
    cookies = s.get("cookies", [])

    if filter_key:
        cookies = [c for c in cookies if filter_key.lower() in c.get("name", "").lower()]

    if json_out:
        console.print_json(json.dumps(cookies))
        return

    table = Table(title=f"Cookies — {s['host']}", border_style="red")
    table.add_column("Name", style="cyan", width=25)
    table.add_column("Domain", style="dim", width=20)
    table.add_column("Flags", width=15)
    table.add_column("Value" if show_value else "Preview", style="white")

    for c in cookies:
        flags = []
        if c.get("httpOnly"):
            flags.append("[red]httpOnly[/red]")
        if c.get("secure"):
            flags.append("[green]secure[/green]")
        if c.get("sameSite"):
            flags.append(f"[dim]{c['sameSite']}[/dim]")

        val = c.get("value", "")
        display = val if show_value else (val[:40] + "..." if len(val) > 40 else val)
        table.add_row(c.get("name", ""), c.get("domain", ""), " ".join(flags), display)

    console.print(table)
    console.print(f"[dim]Total: {len(cookies)} cookies[/dim]")


@app.command("all")
def dump_all(json_out: bool = typer.Option(False, "--json", "-j"), slot: str = _SLOT_OPTION):
    """Dump everything: tokens + storage + cookies."""
    dump_tokens(raw=False, copy=False, filter_key="", slot=slot)
    console.print()
    dump_storage(source="all", filter_key="", json_out=json_out, slot=slot)
    console.print()
    dump_cookies(filter_key="", show_value=False, json_out=json_out, slot=slot)


@app.command("endpoints")
def dump_endpoints(
    filter_str: str | None = typer.Option(None, "--filter", "-f", help="Filter by substring in path"),
    json_out: bool = typer.Option(False, "--json", help="Output as JSON"),
    slot: str = _SLOT_OPTION,
):
    """Show every API endpoint discovered automatically during session capture."""
    import json as _json

    session = load_session(slot)
    if not session:
        console.print(f"[red]✗ No active session in slot '{slot}' — run: "
                      f"loki session start <host> --slot {slot}[/red]")
        raise typer.Exit(1)

    endpoints = session.get("endpoints", [])
    if filter_str:
        endpoints = [e for e in endpoints if filter_str.lower() in e["path"].lower()]

    if not endpoints:
        console.print("[yellow]⚠ No endpoints captured. Click around the site more during "
                      "'loki session start' before pressing ENTER — LOKI records real "
                      "XHR/fetch calls as you browse.[/yellow]")
        return

    if json_out:
        console.print(_json.dumps(endpoints, indent=2))
        return

    from rich.table import Table
    table = Table(show_header=True, header_style="bold cyan", title=f"Discovered Endpoints ({len(endpoints)})")
    table.add_column("Method", width=8)
    table.add_column("Status", width=8)
    table.add_column("Path")
    table.add_column("Type", width=10)

    for e in endpoints:
        status = e.get("status")
        color = "green" if status and 200 <= status < 300 else ("yellow" if status else "dim")
        table.add_row(
            e["method"],
            f"[{color}]{status or '?'}[/{color}]",
            e["path"],
            e["type"],
        )
    console.print(table)
    console.print(f"\n[dim]Use: loki req get '<path>' or loki fuzz '<path with §ID§>'[/dim]")