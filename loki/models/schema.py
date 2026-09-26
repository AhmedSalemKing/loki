"""
Pydantic models for all LOKI data structures.
These are the single source of truth — never use raw dicts.
"""
from __future__ import annotations
import datetime as _dt
from datetime import datetime
from enum import Enum
from typing import Optional, Any
from pydantic import BaseModel, Field


class AuthState(str, Enum):
    IDLE = "idle"
    NAVIGATING = "navigating"
    FORM_DETECTED = "form_detected"
    FILLING = "filling"
    SUBMITTED = "submitted"
    OTP_REQUIRED = "otp_required"
    SUCCESS = "success"
    FAILED = "failed"


class FieldType(str, Enum):
    EMAIL = "email"
    PASSWORD = "password"
    PASSWORD_CONFIRM = "password_confirm"
    FIRST_NAME = "first_name"
    LAST_NAME = "last_name"
    USERNAME = "username"
    PHONE = "phone"
    DATE_OF_BIRTH = "date_of_birth"
    UNKNOWN = "unknown"


class FormField(BaseModel):
    selector: str
    field_type: FieldType = FieldType.UNKNOWN
    label: str = ""
    placeholder: str = ""
    input_type: str = "text"
    autocomplete: str = ""
    name_attr: str = ""
    required: bool = False


class DetectedForm(BaseModel):
    form_index: int
    fields: list[FormField]
    submit_selector: str = ""
    action: str = ""


class Project(BaseModel):
    id: int = 0
    name: str
    description: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(_dt.timezone.utc).replace(tzinfo=None))
    active: bool = True


class Target(BaseModel):
    id: int = 0
    project_id: int
    domain: str
    scope_type: str = "in_scope"  # in_scope, out_of_scope, wildcard
    notes: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(_dt.timezone.utc).replace(tzinfo=None))


class Session(BaseModel):
    id: int = 0
    project_id: int
    target_domain: str
    email: str = ""
    cookies: str = "[]"      # JSON string
    local_storage: str = "{}"  # JSON string
    session_storage: str = "{}"
    auth_headers: str = "{}"   # JSON string
    auth_state: AuthState = AuthState.IDLE
    created_at: datetime = Field(default_factory=lambda: datetime.now(_dt.timezone.utc).replace(tzinfo=None))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(_dt.timezone.utc).replace(tzinfo=None))


class Endpoint(BaseModel):
    id: int = 0
    project_id: int
    target_domain: str
    method: str
    path: str             # normalized, e.g. /users/{id}
    path_pattern: str     # regex pattern for matching
    first_seen: datetime = Field(default_factory=lambda: datetime.now(_dt.timezone.utc).replace(tzinfo=None))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(_dt.timezone.utc).replace(tzinfo=None))
    hit_count: int = 1
    tags: str = "[]"       # JSON list of strings


class Request(BaseModel):
    id: int = 0
    project_id: int
    endpoint_id: int = 0
    method: str
    url: str
    request_headers: str = "{}"
    request_body: str = ""
    response_status: int = 0
    response_headers: str = "{}"
    response_body: str = ""
    response_time_ms: int = 0
    captured_at: datetime = Field(default_factory=lambda: datetime.now(_dt.timezone.utc).replace(tzinfo=None))


class Finding(BaseModel):
    id: int = 0
    project_id: int
    title: str
    severity: str = "info"  # critical, high, medium, low, info
    category: str = ""      # IDOR, XSS, Auth Bypass, etc.
    description: str = ""
    request_id: Optional[int] = None
    evidence_paths: str = "[]"  # JSON list of file paths
    cvss_score: float = 0.0
    status: str = "open"   # open, confirmed, false_positive, fixed
    created_at: datetime = Field(default_factory=lambda: datetime.now(_dt.timezone.utc).replace(tzinfo=None))
    notes: str = ""


class Evidence(BaseModel):
    id: int = 0
    finding_id: int
    evidence_type: str   # screenshot, request, response, note
    file_path: str = ""
    content: str = ""
    captured_at: datetime = Field(default_factory=lambda: datetime.now(_dt.timezone.utc).replace(tzinfo=None))