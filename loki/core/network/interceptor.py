"""
Network traffic interceptor with smart URL normalization and deduplication.
Patterns: /users/123 → /users/{id}, /posts/abc-def → /posts/{slug}
"""
from __future__ import annotations
import asyncio
import json
import re
import time
import datetime as _dt
from datetime import datetime
from typing import Optional, Callable
from urllib.parse import urlparse, parse_qs
from playwright.async_api import Page, Request as PWRequest, Response as PWResponse

from loki.core.storage.database import Database
from loki.models.schema import Endpoint, Request

# Patterns to normalize path segments
_NORMALIZATION_RULES = [
    # UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    (re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I), "{uuid}"),
    # Pure numeric IDs
    (re.compile(r"(?<![a-z])\d{1,12}(?![a-z])"), "{id}"),
    # Slug patterns (words-separated-by-hyphens-with-multiple-parts)
    (re.compile(r"[a-z0-9]{2,}-[a-z0-9]{2,}(?:-[a-z0-9]{2,})+"), "{slug}"),
    # Hash-like strings (32-64 hex chars)
    (re.compile(r"[0-9a-f]{32,64}", re.I), "{hash}"),
    # JWT tokens in path
    (re.compile(r"eyJ[A-Za-z0-9_-]{10,}"), "{jwt}"),
    # Base64-ish strings
    (re.compile(r"[A-Za-z0-9+/]{20,}={0,2}"), "{b64}"),
]

# Request/resource types to ignore (noise)
_IGNORE_TYPES = {"image", "stylesheet", "font", "media", "websocket", "manifest"}

# Extensions to ignore
_IGNORE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".mp3", ".webm", ".avi",
}

# Static file paths that aren't interesting
_IGNORE_PATHS = {"/favicon.ico", "/robots.txt", "/sitemap.xml"}


def normalize_path(path: str) -> tuple[str, str]:
    """
    Normalize a URL path by replacing dynamic segments with placeholders.
    Returns (normalized_path, regex_pattern).
    """
    segments = path.split("/")
    normalized = []
    pattern_parts = []

    for seg in segments:
        if not seg:
            normalized.append(seg)
            pattern_parts.append(seg)
            continue

        replaced = seg
        for pattern, placeholder in _NORMALIZATION_RULES:
            if pattern.fullmatch(replaced):
                replaced = placeholder
                break

        normalized.append(replaced)
        if replaced.startswith("{"):
            pattern_parts.append(r"[^/]+")
        else:
            pattern_parts.append(re.escape(replaced))

    norm_path = "/".join(normalized)
    regex = "^" + "/".join(pattern_parts) + "$"
    return norm_path, regex


def should_capture(url: str, resource_type: str, in_scope_check: Optional[Callable] = None) -> bool:
    """Determine if this request should be captured."""
    if resource_type in _IGNORE_TYPES:
        return False

    parsed = urlparse(url)
    path = parsed.path.lower()

    if path in _IGNORE_PATHS:
        return False

    ext = "." + path.split(".")[-1] if "." in path.split("/")[-1] else ""
    if ext in _IGNORE_EXTENSIONS:
        return False

    # Only capture API-like requests and HTML pages
    if path.startswith("/api/") or path.startswith("/v1/") or path.startswith("/v2/"):
        return True

    # Capture XHR/fetch
    if resource_type in {"xhr", "fetch", "document"}:
        return True

    return False


class NetworkInterceptor:
    """Captures network traffic from Playwright and stores to SQLite with deduplication."""

    def __init__(self, browser_page: Page, db: Database, project_id: int):
        self.page = browser_page
        self.db = db
        self.project_id = project_id
        self._active = False
        self._captured_count = 0
        self._live_callbacks: list[Callable] = []
        self._pending: list[dict] = []  # for live display

    async def start(self) -> None:
        """Begin intercepting network traffic."""
        self._active = True
        self.page.on("request", self._on_request)
        self.page.on("response", self._on_response)

    async def stop(self) -> None:
        """Stop intercepting."""
        self._active = False
        self.page.remove_listener("request", self._on_request)
        self.page.remove_listener("response", self._on_response)

    def add_live_callback(self, callback: Callable) -> None:
        """Register callback for real-time traffic display."""
        self._live_callbacks.append(callback)

    def _on_request(self, request: PWRequest) -> None:
        """Store request timing start."""
        if not self._active:
            return
        # Store start time in request object's data
        request._start_time = time.monotonic()

    def _on_response(self, response: PWResponse) -> None:
        """Handle response and store to DB."""
        if not self._active:
            return
        asyncio.create_task(self._process_response(response))

    async def _process_response(self, response: PWResponse) -> None:
        """Process captured response and store to database."""
        try:
            request = response.request
            url = request.url
            resource_type = request.resource_type
            method = request.method

            if not should_capture(url, resource_type):
                return

            parsed = urlparse(url)
            domain = parsed.netloc
            path = parsed.path or "/"

            # Timing
            start = getattr(request, "_start_time", time.monotonic())
            response_time = int((time.monotonic() - start) * 1000)

            # Normalize path
            norm_path, pattern = normalize_path(path)

            # Build endpoint
            ep = Endpoint(
                project_id=self.project_id,
                target_domain=domain,
                method=method,
                path=norm_path,
                path_pattern=pattern,
            )
            ep = await self.db.upsert_endpoint(ep)

            # Capture request/response bodies (limit size)
            try:
                req_body = await request.post_data() or ""
                if len(req_body) > 10000:
                    req_body = req_body[:10000] + "... [truncated]"
            except Exception as e:
                req_body = ""

            try:
                resp_body = await response.text()
                if len(resp_body) > 50000:
                    resp_body = resp_body[:50000] + "... [truncated]"
            except Exception as e:
                resp_body = ""

            req_headers = dict(request.headers)
            resp_headers = dict(response.headers)

            # Save full request
            req_record = Request(
                project_id=self.project_id,
                endpoint_id=ep.id,
                method=method,
                url=url,
                request_headers=json.dumps(req_headers),
                request_body=req_body,
                response_status=response.status,
                response_headers=json.dumps(resp_headers),
                response_body=resp_body,
                response_time_ms=response_time,
            )
            await self.db.save_request(req_record)
            self._captured_count += 1

            # Notify live callbacks
            entry = {
                "method": method,
                "status": response.status,
                "path": norm_path,
                "domain": domain,
                "time_ms": response_time,
                "timestamp": datetime.now(_dt.timezone.utc).replace(tzinfo=None).isoformat(),
            }
            self._pending.append(entry)
            for cb in self._live_callbacks:
                try:
                    cb(entry)
                except Exception as e:
                    pass

        except Exception as e:
            pass  # Never crash on interception error

    @property
    def captured_count(self) -> int:
        return self._captured_count