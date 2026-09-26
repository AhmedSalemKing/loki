"""
loki flow record <name>  — record a multi-step flow's requests
loki flow abuse <name>   — replay it broken: skip steps, replay old
                            steps after completion, fire the last step
                            concurrently (race on the final action).
loki flow list            — list recorded flows
"""
from __future__ import annotations
import asyncio
import typer
from rich.console import Console
from rich.table import Table

from loki.core.session.store import load_session
from loki.core.browser.persistent import connect_daemon, browser_fetch, browser_fetch_batch, NoBrowserSession
from loki.core.recon.flow_recorder import record_flow, load_flow, list_flows
try:
    from loki.core.browser.persistent import SameSiteNavigationError
except ImportError:
    class SameSiteNavigationError(Exception):
        pass

console = Console()
flow_app = typer.Typer(help="Record and abuse-test multi-step business logic flows")


@flow_app.command("record")
def flow_record(
    name: str = typer.Argument(..., help="Name to save this flow under"),
    slot: str = typer.Option("default", "--slot", help="Session slot whose browser to record from"),
):
    """Record a multi-step flow by performing it manually in the daemon's browser."""
    mutating = [s for s in steps if s["method"] not in ("GET", "HEAD", "OPTIONS")]

    if dry_run:
        console.print(f"\n[cyan]DRY RUN — '{name}' has {len(steps)} step(s), {len(mutating)} of them mutating (POST/PUT/PATCH/DELETE):[/cyan]")
        for i, s in enumerate(steps, 1):
            tag = "[red](mutating)[/red]" if s["method"] not in ("GET", "HEAD", "OPTIONS") else ""
            console.print(f"  {i}. {s['method']} {s['url']} {tag}")
        raise typer.Exit(0)

    if mutating and not yes:
        console.print(f"\n[bold yellow]⚠ This flow has {len(mutating)} mutating request(s) (POST/PUT/PATCH/DELETE) "
                      f"that will be REPLAYED FOR REAL, possibly multiple times (baseline + skip-step + replay + race).[/bold yellow]")
        for s in mutating:
            console.print(f"    {s['method']} {s['url']}")
        if not typer.confirm("Continue and actually send these?"):
            raise typer.Exit(0)

    session = load_session(slot=slot)
    if not session:
        console.print(f"[red]✗ No active session in slot '{slot}' — run: loki session start <host> --slot {slot}[/red]")
        raise typer.Exit(1)

    async def _run():
        try:
            pw, browser, page = await connect_daemon(host=session.get("resolved_host") or session.get("host"), slot=slot)
        except (NoBrowserSession, SameSiteNavigationError) as e:
            console.print(f"[red]✗ {e}[/red]")
            raise typer.Exit(1)
        context = page.context
        steps = await record_flow(context, page, name)
        await pw.stop()
        return steps

    steps = asyncio.run(_run())
    console.print(f"\n[green]✓ Recorded {len(steps)} step(s) as flow '{name}'[/green]")
    for i, s in enumerate(steps, 1):
        console.print(f"  {i}. {s['method']} {s['url']}")


@flow_app.command("list")
def flow_list():
    """List saved flows."""
    flows = list_flows()
    if not flows:
        console.print("[dim]No flows recorded yet. Use: loki flow record <name>[/dim]")
        return
    for f in flows:
        console.print(f"  - {f}")


@flow_app.command("abuse")
def flow_abuse(
    name: str = typer.Argument(..., help="Name of a recorded flow"),
    slot: str = typer.Option("default", "--slot", help="Session slot to replay with"),
    race_final: int = typer.Option(5, "--race-final", help="How many times to fire the final step concurrently (0 to skip)"),
    dry_run: bool = typer.Option(False, "--dry-run", help="List the steps without sending any requests"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation prompt (for scripting)"),
):
    """Replay a recorded flow in broken ways: skip a step, replay an early step after completion, race the final step."""
    steps = load_flow(name)
    if not steps:
        console.print(f"[red]✗ No flow named '{name}' found. Use: loki flow record {name}[/red]")
        raise typer.Exit(1)
    if len(steps) < 2:
        console.print("[yellow]⚠ Flow has fewer than 2 steps — nothing meaningful to abuse-test.[/yellow]")
        raise typer.Exit(0)

    session = load_session(slot=slot)
    if not session:
        console.print(f"[red]✗ No active session in slot '{slot}'[/red]")
        raise typer.Exit(1)

    console.print(f"\n[bold red]☠ LOKI FLOW ABUSE[/bold red] — '{name}' ({len(steps)} step(s)), slot: {slot}\n")

    async def _replay(page, subset_steps, label):
        console.print(f"[cyan]--- {label} ---[/cyan]")
        for i, s in enumerate(subset_steps, 1):
            try:
                res = await browser_fetch(page, s["url"], method=s["method"], body=s.get("body"),
                                           extra_headers={k: v for k, v in s.get("headers", {}).items()
                                                          if k.lower() not in ("cookie", "content-length", "host")})
                console.print(f"  [{i}] {s['method']} {s['url']} -> {res.get('status')} ({res.get('size')}B)")
            except Exception as e:
                console.print(f"  [{i}] {s['method']} {s['url']} -> [red]error: {e}[/red]")

    async def _run():
        try:
            pw, browser, page = await connect_daemon(host=session.get("resolved_host") or session.get("host"), slot=slot)
        except (NoBrowserSession, SameSiteNavigationError) as e:
            console.print(f"[red]✗ {e}[/red]")
            raise typer.Exit(1)

        # 1. Full flow, in order (baseline)
        await _replay(page, steps, "Baseline: full flow in order")

        # 2. Skip the second-to-last step (common: skip payment/verification before the final action)
        if len(steps) >= 2:
            skipped = steps[:-2] + [steps[-1]]
            await _replay(page, skipped, f"Skip step {len(steps)-1}, then final step")

        # 3. Replay the FIRST step again after the flow already completed
        await _replay(page, [steps[0]], "Replay step 1 again (already completed once above)")

        # 4. Race the final step N times concurrently
        if race_final > 1:
            console.print(f"[cyan]--- Race final step x{race_final} ---[/cyan]")
            final = steps[-1]
            requests = [{"url": final["url"], "method": final["method"], "body": final.get("body"),
                         "headers": {k: v for k, v in final.get("headers", {}).items()
                                     if k.lower() not in ("cookie", "content-length", "host")}}
                        for _ in range(race_final)]
            results = await browser_fetch_batch(page, requests, batch_size=race_final)
            success = sum(1 for r in results if 200 <= r.get("status", 0) < 300)
            for i, r in enumerate(results, 1):
                console.print(f"  [{i}] -> {r.get('status')} ({r.get('size')}B)")
            console.print(f"  {success}/{race_final} succeeded")
            if success > 1:
                console.print("[yellow]⚠ Final step succeeded more than once concurrently — possible race condition on this action.[/yellow]")

        await pw.stop()

    asyncio.run(_run())

    console.print("\n[dim]Review each section above manually: did the skip-step or replay-step-1 sections "
                  "succeed when they should have been rejected? That's the actual finding, not just the status code.[/dim]")
