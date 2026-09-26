"""
Auth state detection — snapshot before/after to detect success.
"""
from __future__ import annotations
import re
from dataclasses import dataclass
from playwright.async_api import Page
from ..browser.javascript import DETECT_AUTH_STATE_JS


@dataclass
class AuthSnapshot:
    url: str
    cookie_names: set[str]
    local_keys: set[str]
    session_keys: set[str]
    success_score: int
    error_score: int
    otp_score: int
    captcha_score: int
    email_verify_score: int


async def snapshot(page: Page, bm) -> AuthSnapshot:
    result = await page.evaluate(DETECT_AUTH_STATE_JS)
    cookies = await bm.get_cookies()
    storage = await bm.get_storage(page)
    return AuthSnapshot(
        url=result.get("url",""),
        cookie_names={c.get("name","") for c in cookies},
        local_keys=set(storage["local"].keys()),
        session_keys=set(storage["session"].keys()),
        success_score=result.get("success",0),
        error_score=result.get("error",0),
        otp_score=result.get("otp",0),
        captcha_score=result.get("captcha",0),
        email_verify_score=result.get("emailVerify",0),
    )


AUTH_COOKIE_PATTERNS = re.compile(
    r'(sess|token|auth|jwt|access|refresh|bearer|user_id|userid|uid|'
    r'sid|login|logged|signed)', re.I
)


def detect_state_change(before: AuthSnapshot, after: AuthSnapshot) -> str:
    """
    Compare before/after snapshots → return new auth state string.
    """
    if after.otp_score >= 2:
        return "otp_required"
    if after.captcha_score >= 2:
        return "captcha"
    if after.email_verify_score >= 2:
        return "email_verify"
    if after.error_score >= 2 and after.success_score == 0:
        return "error"

    # New cookies appeared?
    new_cookies = after.cookie_names - before.cookie_names
    auth_cookies = {c for c in new_cookies if AUTH_COOKIE_PATTERNS.search(c)}

    # New storage keys?
    new_local = after.local_keys - before.local_keys
    auth_local = {k for k in new_local if AUTH_COOKIE_PATTERNS.search(k)}

    # URL changed to a non-auth page?
    url_changed = after.url != before.url and not any(
        w in after.url.lower() for w in ["login","signin","register","signup","join","auth"]
    )

    success_signals = (
        bool(auth_cookies) or
        bool(auth_local) or
        after.success_score >= 2 or
        url_changed
    )

    if success_signals:
        return "success"

    return "unknown"
