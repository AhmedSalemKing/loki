"""
loki req — Authenticated HTTP requests via browser fetch().
Uses the saved LOKI session — bypasses WAF/Vercel/Cloudflare.
"""
from __future__ import annotations
import asyncio
import json
import typer
from rich.console import Console
from rich.syntax import Syntax
from rich.panel import Panel

from loki.core.session.store import load_session, get_auth_header_for_host, resolve_host_for_path
from loki.core.browser.persistent import connect_daemon, browser_fetch, NoBrowserSession, SameSiteNavigationError

req_app = typer.Typer(name="req", help="Make authenticated requests via browser context")
console = Console()


def _build_url(host: str, path: str) -> str:
    if path.startswith("http://") or path.startswith("https://"):
        return path
    return f"https://{host}{path if path.startswith('/') else '/' + path}"


def _parse_headers(header_list: list[str]) -> dict:
    result = {}
    for h in header_list:
        k, _, v = h.partition(":")
        result[k.strip()] = v.strip()
    return result


def _display_response(result: dict, raw: bool, url: str) -> None:
    status = result.get("status", 0)
    size = result.get("size", 0)
    body = result.get("body", "")
    error = result.get("error")

    color = "green" if 200 <= status < 300 else ("yellow" if 300 <= status < 400 else "red")
    console.print(f"[{color}]HTTP {status}[/{color}]  {size} bytes  [dim]{url}[/dim]")

    if error:
        console.print(f"[red]Error: {error}[/red]")
        return

    if raw:
        console.print(body)
        return

    # Try pretty-print JSON
    try:
        parsed = json.loads(body)
        syntax = Syntax(json.dumps(parsed, indent=2, ensure_ascii=False), "json",
                        theme="monokai", line_numbers=False)
        console.print(Panel(syntax, border_style="dim"))
    except Exception:
        # Show first 2000 chars
        preview = body[:2000] + ("..." if len(body) > 2000 else "")
        console.print(Panel(preview, border_style="dim"))


def _run_request(method: str, path: str, host: str | None,
                 header: list[str], data: str | None, raw: bool, slot: str = "default") -> None:
    session = load_session(slot)
    if not session:
        console.print(f"[red]✗ No active session for slot '{slot}' — run: loki session start --slot {slot} <host>[/red]")
        raise typer.Exit(1)

    resolved_host, host_mode = resolve_host_for_path(session, path, host)
    if host_mode == "auto":
        console.print(f"[dim]Auto-detected host for this path: {resolved_host}[/dim]")
    url = _build_url(resolved_host, path)
    extra_headers = get_auth_header_for_host(session, resolved_host)
    extra_headers.update(_parse_headers(header))

    async def _run():
        console.print(f"[dim]{method.upper()} {url}[/dim]")
        try:
            pw, browser, page = await connect_daemon(url, slot=slot)
        except (NoBrowserSession, SameSiteNavigationError) as e:
            console.print(f"[red]✗ {e}[/red]")
            raise typer.Exit(1)
        try:
            result = await browser_fetch(page, url, method=method,
                                         body=data, extra_headers=extra_headers)
            _display_response(result, raw, url)
        finally:
            await pw.stop()

    asyncio.run(_run())


@req_app.command("get")
def req_get(
    path: str = typer.Argument(..., help="Path or full URL e.g. /api/profile/me"),
    host: str | None = typer.Option(None, "--host", "-H", help="Override host"),
    header: list[str] = typer.Option([], "--header", "-h", help="Extra header: 'Key: Value'"),
    raw: bool = typer.Option(False, "--raw", "-r", help="Print raw response"),
    slot: str = typer.Option("default", "--slot", help="Session slot to use"),
):
    """GET request using saved session."""
    _run_request("GET", path, host, header, None, raw, slot)


@req_app.command("post")
def req_post(
    path: str = typer.Argument(...),
    data: str = typer.Option(..., "--data", "-d", help="Request body JSON string"),
    host: str | None = typer.Option(None, "--host", "-H"),
    header: list[str] = typer.Option([], "--header", "-h"),
    raw: bool = typer.Option(False, "--raw", "-r"),
    slot: str = typer.Option("default", "--slot", help="Session slot to use"),
):
    """POST request using saved session."""
    _run_request("POST", path, host, header, data, raw, slot)


@req_app.command("put")
def req_put(
    path: str = typer.Argument(...),
    data: str = typer.Option(..., "--data", "-d"),
    host: str | None = typer.Option(None, "--host", "-H"),
    header: list[str] = typer.Option([], "--header", "-h"),
    raw: bool = typer.Option(False, "--raw", "-r"),
    slot: str = typer.Option("default", "--slot", help="Session slot to use"),
):
    """PUT request using saved session."""
    _run_request("PUT", path, host, header, data, raw, slot)


@req_app.command("delete")
def req_delete(
    path: str = typer.Argument(...),
    host: str | None = typer.Option(None, "--host", "-H"),
    header: list[str] = typer.Option([], "--header", "-h"),
    raw: bool = typer.Option(False, "--raw", "-r"),
    slot: str = typer.Option("default", "--slot", help="Session slot to use"),
):
    """DELETE request using saved session."""
    _run_request("DELETE", path, host, header, None, raw, slot)