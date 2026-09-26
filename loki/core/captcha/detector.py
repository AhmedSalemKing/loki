"""
CAPTCHA & Bot-Protection Detector
Identifies what's blocking LOKI on a given page.
"""
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from playwright.async_api import Page


class BlockType(str, Enum):
    RECAPTCHA_V2     = "recaptcha_v2"
    RECAPTCHA_V3     = "recaptcha_v3"
    HCAPTCHA         = "hcaptcha"
    TURNSTILE        = "cloudflare_turnstile"
    CLOUDFLARE_WAF   = "cloudflare_waf"
    DATADOME         = "datadome"
    PERIMETERX       = "perimeterx"
    AKAMAI           = "akamai_bot_manager"
    RATE_LIMIT       = "rate_limit_429"
    NONE             = "none"


@dataclass
class BlockResult:
    blocked: bool
    block_type: BlockType
    description: str
    can_bypass: bool       # LOKI stealth mode can handle this
    suggestion: str        # What to do


async def detect_block(page: Page) -> BlockResult:
    """Analyze current page for CAPTCHA / bot protection."""
    url = page.url.lower()
    content = (await page.content()).lower()

    # ── Cloudflare WAF / Under Attack Mode ──────────────────────────────────
    if any(x in content for x in [
        "cf-chl-bypass", "challenge-form", "jschl_vc", "cloudflare ray id",
        "cf_chl_opt", "checking your browser", "please wait",
        "enable javascript and cookies", "cf-turnstile",
    ]):
        if "cf-turnstile" in content or "turnstile" in content:
            return BlockResult(
                blocked=True, block_type=BlockType.TURNSTILE,
                description="Cloudflare Turnstile CAPTCHA detected",
                can_bypass=False,
                suggestion="Use --proxy with a residential IP, or wait and retry. Turnstile requires JS challenge solving.",
            )
        return BlockResult(
            blocked=True, block_type=BlockType.CLOUDFLARE_WAF,
            description="Cloudflare WAF / Under Attack Mode — JS challenge required",
            can_bypass=True,
            suggestion="Stealth mode + residential proxy usually bypasses this. Try: loki --proxy socks5://IP:PORT auth register ...",
        )

    # ── reCAPTCHA ────────────────────────────────────────────────────────────
    rc_v2 = await page.locator("iframe[src*='recaptcha/api2']").count()
    rc_v3 = "grecaptcha.execute" in content or "recaptcha/api.js" in content

    if rc_v2 > 0:
        return BlockResult(
            blocked=True, block_type=BlockType.RECAPTCHA_V2,
            description="reCAPTCHA v2 checkbox detected — requires human interaction",
            can_bypass=False,
            suggestion="Use --captcha-key to integrate 2captcha/CapSolver service (coming in v3). For now: run with --debug and solve manually.",
        )
    if rc_v3:
        return BlockResult(
            blocked=True, block_type=BlockType.RECAPTCHA_V3,
            description="reCAPTCHA v3 score-based detected — invisible but blocks submission",
            can_bypass=True,
            suggestion="Stealth mode often gets a passing score (≥0.5). Enable with default settings and retry.",
        )

    # ── hCaptcha ─────────────────────────────────────────────────────────────
    hc = await page.locator("iframe[src*='hcaptcha.com']").count()
    if hc > 0 or "hcaptcha" in content:
        return BlockResult(
            blocked=True, block_type=BlockType.HCAPTCHA,
            description="hCaptcha detected",
            can_bypass=False,
            suggestion="hCaptcha requires solving. Use --captcha-key with CapSolver (coming in v3).",
        )

    # ── DataDome ──────────────────────────────────────────────────────────────
    if "datadome" in content or "dd_cookie" in content or "datadome" in url:
        return BlockResult(
            blocked=True, block_type=BlockType.DATADOME,
            description="DataDome bot protection detected",
            can_bypass=True,
            suggestion="Stealth mode + residential proxy usually works. Add --proxy socks5://...",
        )

    # ── PerimeterX / HUMAN ────────────────────────────────────────────────────
    if any(x in content for x in ["perimeterx", "px-captcha", "_pxde", "pxvid"]):
        return BlockResult(
            blocked=True, block_type=BlockType.PERIMETERX,
            description="PerimeterX / HUMAN bot protection detected",
            can_bypass=True,
            suggestion="Stealth mode with randomized fingerprint usually bypasses PerimeterX. Ensure stealth is enabled.",
        )

    # ── Rate limit 429 ────────────────────────────────────────────────────────
    try:
        status = await page.evaluate("() => window.__lokiLastStatus || 200")
        if status == 429 or "429" in content or "too many requests" in content or "te veel verzoeken" in content:
            return BlockResult(
                blocked=True, block_type=BlockType.RATE_LIMIT,
                description="HTTP 429 Too Many Requests — IP rate limited",
                can_bypass=True,
                suggestion="Wait 60s and retry, or use --proxy to rotate IP. gamma.nl throttles headless browsers aggressively.",
            )
    except Exception:
        pass

    return BlockResult(
        blocked=False, block_type=BlockType.NONE,
        description="No bot protection detected",
        can_bypass=True,
        suggestion="",
    )