"""
LOKI Flow Recorder — records an ordered sequence of XHR/fetch requests
made during a manual walkthrough of a multi-step flow (checkout,
registration, coupon redemption, etc.), so `loki flow abuse` can replay
them out of order, skip steps, or replay old steps after completion.
"""
from __future__ import annotations
import asyncio
import json
from pathlib import Path

FLOWS_DIR = Path.home() / ".loki" / "flows"


def _flow_file(name: str) -> Path:
    FLOWS_DIR.mkdir(parents=True, exist_ok=True)
    return FLOWS_DIR / f"{name}.json"


async def record_flow(context, page, name: str, max_seconds: int = 120) -> list[dict]:
    """
    Attach a request listener, let the user manually perform the flow,
    and stop on ENTER. Returns the ordered list of captured steps.
    """
    steps: list[dict] = []

    def _on_request(request):
        try:
            if request.resource_type in ("xhr", "fetch") and request.method in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                steps.append({
                    "url": request.url,
                    "method": request.method,
                    "headers": dict(request.headers),
                    "body": request.post_data,
                })
        except Exception:
            pass

    context.on("request", _on_request)

    print(f"\n☠ Recording flow '{name}'. Perform the flow now in the opened browser window "
          f"(e.g. add to cart -> apply coupon -> checkout).")
    print("Press ENTER here when the flow is complete.")
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, input)

    try:
        context.remove_listener("request", _on_request)
    except Exception:
        pass

    _flow_file(name).write_text(json.dumps(steps, indent=2))
    return steps


def load_flow(name: str) -> list[dict] | None:
    f = _flow_file(name)
    if not f.exists():
        return None
    return json.loads(f.read_text())


def list_flows() -> list[str]:
    if not FLOWS_DIR.exists():
        return []
    return sorted(p.stem for p in FLOWS_DIR.glob("*.json"))
