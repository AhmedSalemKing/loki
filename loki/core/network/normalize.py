"""
URL normalization and endpoint deduplication.
"""
from __future__ import annotations
import re
from urllib.parse import urlparse, urlunparse, urlencode, parse_qsl


# Tracking/noise query params to strip
_STRIP_PARAMS = {
    "utm_source","utm_medium","utm_campaign","utm_term","utm_content",
    "fbclid","gclid","msclkid","dclid","_ga","_gl","ref","source",
    "v","cb","t","ts","_","nocache","cachebust",
}

# Domains always filtered
CDN_DOMAINS = {
    "connect.facebook.net","doubleclick.net","google-analytics.com",
    "googletagmanager.com","cookielaw.org","cdn.cookielaw.org",
    "zitcha.app","zitcha.com","cloudflare.com","cloudflareinsights.com",
    "clarity.ms","hotjar.com","intercom.io","segment.com",
    "sentry.io","datadoghq.com","datadog-browser-agent.com",
    "nr-data.net","newrelic.com","dynatrace.com",
    "akamai.com","fastly.net","jsdelivr.net","unpkg.com",
    "cdnjs.cloudflare.com","fonts.googleapis.com","fonts.gstatic.com",
    "maps.googleapis.com","recaptcha.net","gstatic.com",
    "onetrust.com","cookiebot.com","cookieinformation.com",
    "contentsquare.net","quantum-metric.com",
    "contentful.com",  # headless CMS API — usually not target
}

# Subdomains that indicate CDN / static
CDN_SUBDOMAINS = {"cdn","static","assets","media","img","images",
                  "fonts","scripts","files","uploads","s3","storage"}

# Path prefixes that are always static/asset
ASSET_PATHS = {
    "/dam/","/assets/","/static/","/images/","/img/","/fonts/",
    "/media/","/scripttemplates/","/signals/config/",
    "/locales/","/locale/","/i18n/","/translations/","/lang/",
    "/FE/","/carinfo/","/consent/","/sst/",
}

# File extensions that are always static
ASSET_EXTS = {
    ".jpg",".jpeg",".png",".gif",".webp",".avif",".svg",".ico",
    ".woff",".woff2",".ttf",".eot",".otf",
    ".mp4",".mp3",".wav",".pdf",
    ".css",".map",".chunk.js",
}


def normalize_url(url: str) -> str:
    """Strip tracking params; lowercase scheme+host; keep path+meaningful params."""
    try:
        p = urlparse(url)
        host = p.hostname or ""
        path = p.path or "/"
        params = [(k, v) for k, v in parse_qsl(p.query) if k.lower() not in _STRIP_PARAMS]
        query = urlencode(sorted(params))
        return urlunparse((p.scheme.lower(), host.lower(), path, "", query, ""))
    except Exception:
        return url


def extract_host(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def extract_path(url: str) -> str:
    try:
        return urlparse(url).path or "/"
    except Exception:
        return "/"


def is_filtered(url: str, method: str = "GET") -> tuple[bool, str]:
    """Returns (should_filter, reason)."""
    try:
        p = urlparse(url)
        host = p.hostname or ""
        path = p.path or "/"
        ext = ""
        if "." in path.split("/")[-1]:
            ext = "." + path.split(".")[-1].lower()
    except Exception:
        return True, "parse_error"

    # CDN domain
    if host in CDN_DOMAINS:
        return True, "cdn_domain"
    # CDN subdomain
    sub = host.split(".")[0] if "." in host else ""
    if sub in CDN_SUBDOMAINS:
        return True, "cdn_subdomain"
    # Asset extension
    if ext in ASSET_EXTS:
        return True, f"asset_ext:{ext}"
    # Asset path prefix
    for ap in ASSET_PATHS:
        if path.startswith(ap):
            return True, f"asset_path:{ap}"
    # JS/CSS/font in path
    if re.search(r'\.(js|css|woff2?|ttf|eot|otf)(\?|$)', path, re.I):
        return True, "static_resource"
    # UUIDs in consent/analytics paths
    if re.match(r'^/[0-9a-f]{8}-', path):
        return True, "uuid_path"
    # gtag / analytics collect
    if any(x in path for x in ["/collect", "/gtag/", "/analytics.js"]):
        return True, "analytics_collect"

    return False, ""


# Path segments that indicate user data
USER_DATA_SEGMENTS = {
    "user","users","account","accounts","profile","order","orders",
    "customer","member","address","payment","invoice","ticket",
    "booking","document","file","record","resource","cart",
    "wishlist","subscription","settings","me","preferences",
    "session","session-data","session_data","auth","token",
}

API_SEGMENTS = {"/api/","/v1/","/v2/","/v3/","/graphql","/rest/",
                "/service/","/services/","/rpc/","/gql"}
