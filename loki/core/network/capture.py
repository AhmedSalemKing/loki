"""
Playwright network interception — captures requests/responses,
normalizes, deduplicates, classifies, stores to DB.
"""
from __future__ import annotations
import asyncio
import json
import re
from datetime import datetime
from typing import Callable, Optional
from urllib.parse import urlparse

from playwright.async_api import Page, Request as PWReq, Response as PWResp

from ..storage.models import CapturedRequest, Endpoint, EndpointClass, RiskLevel
from ..storage.manager import StorageManager
from .normalize import (
    normalize_url, extract_host, extract_path,
    is_filtered, USER_DATA_SEGMENTS, API_SEGMENTS
)


def _classify(method: str, url: str, path: str,
               status: int | None, response_body: str | None) -> tuple[EndpointClass, RiskLevel, list[str]]:
    signals: list[str] = []
    path_l = path.lower()
    url_l = url.lower()
    segs = set(re.split(r'[/\-_.]', path_l))

    # Classification
    classification = EndpointClass.UNKNOWN

    if any(ap in url_l for ap in API_SEGMENTS):
        classification = EndpointClass.API
        signals.append("api_path")

    user_hit = segs & USER_DATA_SEGMENTS
    if user_hit:
        classification = EndpointClass.USER_DATA
        signals.append(f"user_data_segment:{','.join(list(user_hit)[:3])}")

    if any(w in path_l for w in ["login","auth","signin","token","oauth","sso","session"]):
        classification = EndpointClass.AUTH
        signals.append("auth_path")

    if any(w in path_l for w in ["config","settings","preferences","feature","flag"]):
        if classification == EndpointClass.UNKNOWN:
            classification = EndpointClass.CONFIG
        signals.append("config_path")

    # Risk signals
    risk = RiskLevel.NONE

    if status in (401, 403):
        signals.append("auth_protected")
        risk = RiskLevel.MEDIUM

    if method in ("POST","PUT","PATCH","DELETE"):
        signals.append(f"mutating:{method}")
        if risk == RiskLevel.NONE:
            risk = RiskLevel.LOW

    # Numeric ID in path (4+ digits, not version-like)
    if re.search(r'/\d{4,}', path) and not re.search(r'/v\d+/', path):
        signals.append("numeric_id_in_path")
        if risk.value in ("none","low"):
            risk = RiskLevel.MEDIUM

    # UUID
    if re.search(r'[0-9a-f]{8}-[0-9a-f]{4}-', path, re.I):
        signals.append("uuid_in_path")

    # JSON response with user keys
    if response_body:
        try:
            obj = json.loads(response_body[:4096])
            if isinstance(obj, dict):
                keys_l = {k.lower() for k in obj}
                user_keys = keys_l & {"userid","user_id","email","name","phone",
                                       "address","id","accountid","customerid"}
                if user_keys:
                    signals.append(f"user_json_keys:{','.join(list(user_keys)[:3])}")
                    risk = RiskLevel.HIGH if risk != RiskLevel.HIGH else risk
                    classification = EndpointClass.USER_DATA
        except Exception:
            pass

    # Upgrade risk for user data API
    if classification == EndpointClass.USER_DATA and risk == RiskLevel.NONE:
        risk = RiskLevel.LOW

    return classification, risk, signals


class NetworkCapture:
    """
    Attaches to a Playwright Page and captures all network traffic.
    Stores unique endpoints (deduped) and raw requests.
    """
    def __init__(self, storage: StorageManager, project_id: str, host: str,
                 on_candidate: Optional[Callable] = None):
        self.storage = storage
        self.project_id = project_id
        self.host = host
        self.on_candidate = on_candidate
        self._pending: dict[str, dict] = {}   # url -> partial
        self._captured: list[CapturedRequest] = []

    def attach(self, page: Page) -> None:
        page.on("request", self._on_request)
        page.on("response", self._on_response)

    async def _on_request(self, req: PWReq) -> None:
        url = req.url
        filtered, reason = is_filtered(url, req.method)
        if filtered:
            return
        self._pending[url] = {
            "method": req.method.upper(),
            "url": normalize_url(url),
            "raw_url": url,
            "path": extract_path(url),
            "host_val": extract_host(url),
            "headers": dict(req.headers),
            "body": req.post_data,
            "page_url": req.frame.url if req.frame else None,
        }

    async def _on_response(self, resp: PWResp) -> None:
        url = resp.url
        pending = self._pending.pop(url, None)
        if not pending:
            return
        status = resp.status
        r_headers = dict(resp.headers)
        body: Optional[str] = None
        ctype = r_headers.get("content-type","")
        if "json" in ctype or "text" in ctype:
            try:
                body = await asyncio.wait_for(resp.text(), timeout=3)
                if len(body) > 50_000:
                    body = body[:50_000]
            except Exception:
                body = None
        size = int(r_headers.get("content-length", len(body or "")))

        req_model = CapturedRequest(
            project_id=self.project_id,
            host=pending["host_val"] or self.host,
            method=pending["method"],
            url=pending["url"],
            path=pending["path"],
            query="",
            request_headers=pending["headers"],
            request_body=pending["body"],
            status=status,
            response_headers=r_headers,
            response_body=body,
            response_size=size,
            page_url=pending["page_url"],
        )
        req_id = await self.storage.save_request(req_model)
        self._captured.append(req_model)

        # Classify + upsert endpoint
        cls, risk, signals = _classify(
            pending["method"], pending["url"], pending["path"], status, body
        )
        ep = Endpoint(
            project_id=self.project_id,
            host=pending["host_val"] or self.host,
            method=pending["method"],
            url=pending["url"],
            path=pending["path"],
            classification=cls,
            risk=risk,
            signals=signals,
            status_codes=[status] if status else [],
            response_sizes=[size],
            request_ids=[req_id],
        )
        saved = await self.storage.upsert_endpoint(ep)

        if self.on_candidate and risk.value in ("high","medium"):
            await self.on_candidate(saved)

    @property
    def captured(self) -> list[CapturedRequest]:
        return self._captured
