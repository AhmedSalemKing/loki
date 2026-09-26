"""
Auth token extraction — finds JWT, Bearer tokens, API keys in browser storage.
Works on localStorage, sessionStorage, and cookies.
"""
from __future__ import annotations
import json
import re
from typing import Any


JWT_PATTERN = re.compile(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')
BEARER_PATTERN = re.compile(r'Bearer\s+([A-Za-z0-9\-._~+/]+=*)', re.IGNORECASE)
API_KEY_KEYS = ["api_key", "apikey", "api-key", "x-api-key", "token", "auth", "access_token",
                "id_token", "idtoken", "refresh_token", "refreshtoken", "jwt", "bearer",
                "authorization", "auth_token", "authtoken", "session_token", "sessiontoken",
                "user_token", "usertoken", "client_token", "clienttoken"]


def _is_jwt(value: str) -> bool:
    return bool(JWT_PATTERN.match(str(value)))


def _decode_jwt_payload(token: str) -> dict:
    """Decode JWT payload without verification."""
    try:
        import base64
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        payload = parts[1]
        # Add padding
        payload += "=" * (4 - len(payload) % 4)
        decoded = base64.urlsafe_b64decode(payload).decode("utf-8", errors="replace")
        return json.loads(decoded)
    except Exception:
        return {}


def _check_expiry(payload: dict) -> str:
    """Return human-readable token status."""
    import time
    exp = payload.get("exp")
    if not exp:
        return "no expiry"
    remaining = exp - time.time()
    if remaining < 0:
        return f"EXPIRED {abs(int(remaining))//60}m ago"
    if remaining < 300:
        return f"expires in {int(remaining)}s ⚠"
    if remaining < 3600:
        return f"valid {int(remaining)//60}m"
    return f"valid {int(remaining)//3600}h {(int(remaining)%3600)//60}m"


def extract_tokens(local_storage: dict, session_storage: dict, cookies: list) -> list[dict]:
    """Extract all auth tokens from browser storage."""
    found = []

    def _scan_dict(storage: dict, source: str) -> None:
        for key, value in storage.items():
            val_str = str(value)

            # Check key name
            key_lower = key.lower()
            is_auth_key = any(k in key_lower for k in API_KEY_KEYS)

            # Check value contains JWT
            jwt_match = JWT_PATTERN.search(val_str)

            if jwt_match or is_auth_key:
                token_val = jwt_match.group(0) if jwt_match else val_str
                entry = {
                    "source": source,
                    "key": key,
                    "value": token_val,
                    "type": "jwt" if _is_jwt(token_val) else "token",
                    "preview": token_val[:40] + "..." if len(token_val) > 40 else token_val,
                }
                if _is_jwt(token_val):
                    payload = _decode_jwt_payload(token_val)
                    entry["subject"] = payload.get("sub", payload.get("email", ""))
                    entry["status"] = _check_expiry(payload)
                    entry["payload_keys"] = list(payload.keys())[:8]
                found.append(entry)

    _scan_dict(local_storage, "localStorage")
    _scan_dict(session_storage, "sessionStorage")

    # Scan cookies
    for cookie in cookies:
        name = cookie.get("name", "").lower()
        val = str(cookie.get("value", ""))
        if any(k in name for k in API_KEY_KEYS) or _is_jwt(val):
            entry = {
                "source": "cookie",
                "key": cookie.get("name"),
                "value": val,
                "type": "jwt" if _is_jwt(val) else "cookie",
                "preview": val[:40] + "..." if len(val) > 40 else val,
                "domain": cookie.get("domain", ""),
                "httpOnly": cookie.get("httpOnly", False),
                "secure": cookie.get("secure", False),
            }
            if _is_jwt(val):
                payload = _decode_jwt_payload(val)
                entry["subject"] = payload.get("sub", payload.get("email", ""))
                entry["status"] = _check_expiry(payload)
            found.append(entry)

    return found