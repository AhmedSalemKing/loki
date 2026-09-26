"""
Pydantic v2 models — single source of truth for all data shapes.
"""
from __future__ import annotations
import uuid
import datetime as _dt
from datetime import datetime
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field, field_validator


def _now() -> datetime:
    return datetime.now(_dt.timezone.utc).replace(tzinfo=None)


def _uid() -> str:
    return str(uuid.uuid4())


# ── Enums ────────────────────────────────────────────────────────────────────

class EndpointClass(str, Enum):
    API         = "api"
    AUTH        = "auth"
    USER_DATA   = "user_data"
    CONFIG      = "config"
    NAVIGATION  = "navigation"
    STATIC      = "static"
    ASSET       = "asset"
    ANALYTICS   = "analytics"
    TELEMETRY   = "telemetry"
    WEBSOCKET   = "websocket"
    UNKNOWN     = "unknown"


class RiskLevel(str, Enum):
    HIGH    = "high"
    MEDIUM  = "medium"
    LOW     = "low"
    INFO    = "info"
    NONE    = "none"


class AuthState(str, Enum):
    START               = "start"
    DISCOVER_FORM       = "discover_form"
    FILL                = "fill"
    SUBMIT              = "submit"
    SUCCESS             = "success"
    PASSWORD_REQUIRED   = "password_required"
    OTP_REQUIRED        = "otp_required"
    EMAIL_VERIFY        = "email_verify"
    CAPTCHA             = "captcha"
    ERROR               = "error"


class FindingStatus(str, Enum):
    CANDIDATE   = "candidate"
    CONFIRMED   = "confirmed"
    FALSE_POS   = "false_positive"
    REPORTED    = "reported"


# ── Project / Target ─────────────────────────────────────────────────────────

class Project(BaseModel):
    id:         str         = Field(default_factory=_uid)
    name:       str
    created_at: datetime    = Field(default_factory=_now)
    active:     bool        = True
    notes:      str         = ""


class Target(BaseModel):
    id:         str         = Field(default_factory=_uid)
    project_id: str
    host:       str                      # e.g. gamma.nl
    base_url:   str                      # e.g. https://www.gamma.nl
    scope:      list[str]   = Field(default_factory=list)   # allowed glob patterns
    excluded:   list[str]   = Field(default_factory=list)
    tech_stack: list[str]   = Field(default_factory=list)
    added_at:   datetime    = Field(default_factory=_now)


# ── Session ───────────────────────────────────────────────────────────────────

class SessionToken(BaseModel):
    name:       str
    value:      str
    token_type: str = "unknown"   # jwt | cookie | bearer | refresh | access


class BrowserSession(BaseModel):
    id:             str         = Field(default_factory=_uid)
    project_id:     str
    host:           str
    email:          Optional[str]   = None
    authenticated:  bool            = False
    cookies:        list[dict]      = Field(default_factory=list)
    local_storage:  dict[str, str]  = Field(default_factory=dict)
    session_storage:dict[str, str]  = Field(default_factory=dict)
    tokens:         list[SessionToken] = Field(default_factory=list)
    created_at:     datetime        = Field(default_factory=_now)
    updated_at:     datetime        = Field(default_factory=_now)

    def token_count(self) -> int:
        return len(self.tokens)

    def masked_tokens(self) -> list[dict]:
        return [{"name": t.name, "type": t.token_type, "value": "****"} for t in self.tokens]


# ── Network ───────────────────────────────────────────────────────────────────

class CapturedRequest(BaseModel):
    id:             str         = Field(default_factory=_uid)
    project_id:     str
    host:           str
    method:         str
    url:            str
    path:           str
    query:          str         = ""
    request_headers:dict        = Field(default_factory=dict)
    request_body:   Optional[str] = None
    status:         Optional[int] = None
    response_headers: dict      = Field(default_factory=dict)
    response_body:  Optional[str] = None
    response_size:  int         = 0
    page_url:       Optional[str] = None   # which page triggered this
    captured_at:    datetime    = Field(default_factory=_now)


class Endpoint(BaseModel):
    """De-duplicated endpoint — one entry per (method, normalized_url)."""
    id:             str         = Field(default_factory=_uid)
    project_id:     str
    host:           str
    method:         str
    url:            str           # canonical URL (no tracking params)
    path:           str
    classification: EndpointClass = EndpointClass.UNKNOWN
    risk:           RiskLevel     = RiskLevel.NONE
    signals:        list[str]     = Field(default_factory=list)
    observed_count: int           = 1
    status_codes:   list[int]     = Field(default_factory=list)
    response_sizes: list[int]     = Field(default_factory=list)
    first_seen:     datetime      = Field(default_factory=_now)
    last_seen:      datetime      = Field(default_factory=_now)
    request_ids:    list[str]     = Field(default_factory=list)
    notes:          str           = ""


# ── Findings ──────────────────────────────────────────────────────────────────

class Finding(BaseModel):
    id:             str         = Field(default_factory=_uid)
    project_id:     str
    endpoint_id:    str
    title:          str
    description:    str         = ""
    status:         FindingStatus = FindingStatus.CANDIDATE
    risk:           RiskLevel   = RiskLevel.MEDIUM
    signals:        list[str]   = Field(default_factory=list)
    confidence:     float       = 0.0    # 0.0 – 1.0
    evidence:       list[dict]  = Field(default_factory=list)
    created_at:     datetime    = Field(default_factory=_now)


