"""Tests for resolve_host_for_path() and get_auth_header_for_host() —
the multi-host auth/routing logic added to fix today's cross-host bugs."""
from loki.core.session.store import resolve_host_for_path, get_auth_header_for_host


def _session(endpoints=None, auth_headers=None, resolved_host="frontend.example.com"):
    return {
        "host": "frontend.example.com",
        "resolved_host": resolved_host,
        "endpoints": endpoints or [],
        "auth_headers": auth_headers or {},
    }


class TestResolveHostForPath:
    def test_explicit_host_override_wins(self):
        session = _session()
        host, mode = resolve_host_for_path(session, "/api/wallet", host_override="custom.example.com")
        assert host == "custom.example.com"
        assert mode == "explicit"

    def test_full_url_extracts_own_host(self):
        session = _session()
        host, mode = resolve_host_for_path(session, "https://api.example.com/api/wallet")
        assert host == "api.example.com"
        assert mode == "url"

    def test_auto_detects_host_from_single_matching_endpoint(self):
        session = _session(endpoints=[
            {"path": "/api/wallet", "host": "api.example.com", "method": "GET"},
        ])
        host, mode = resolve_host_for_path(session, "/api/wallet")
        assert host == "api.example.com"
        assert mode == "auto"

    def test_falls_back_to_default_when_no_endpoint_matches(self):
        session = _session(endpoints=[
            {"path": "/api/other", "host": "api.example.com", "method": "GET"},
        ])
        host, mode = resolve_host_for_path(session, "/api/wallet")
        assert host == "frontend.example.com"
        assert mode == "default"

    def test_falls_back_to_default_when_path_ambiguous_across_hosts(self):
        # Same path recorded on two different hosts — must not guess.
        session = _session(endpoints=[
            {"path": "/api/wallet", "host": "api-a.example.com", "method": "GET"},
            {"path": "/api/wallet", "host": "api-b.example.com", "method": "GET"},
        ])
        host, mode = resolve_host_for_path(session, "/api/wallet")
        assert host == "frontend.example.com"
        assert mode == "default"

    def test_strips_query_string_before_matching(self):
        session = _session(endpoints=[
            {"path": "/api/courses", "host": "api.example.com", "method": "GET"},
        ])
        host, mode = resolve_host_for_path(session, "/api/courses?limit=6")
        assert host == "api.example.com"
        assert mode == "auto"

    def test_empty_endpoints_falls_back_to_default(self):
        session = _session(endpoints=[])
        host, mode = resolve_host_for_path(session, "/api/anything")
        assert host == "frontend.example.com"
        assert mode == "default"


class TestGetAuthHeaderForHost:
    def test_returns_captured_header_for_known_host(self):
        session = _session(auth_headers={
            "api.example.com": {"authorization": "Bearer abc123"},
        })
        headers = get_auth_header_for_host(session, "api.example.com")
        assert headers == {"authorization": "Bearer abc123"}

    def test_returns_empty_dict_for_unknown_host(self):
        session = _session(auth_headers={
            "api.example.com": {"authorization": "Bearer abc123"},
        })
        headers = get_auth_header_for_host(session, "other.example.com")
        assert headers == {}

    def test_returns_empty_dict_when_no_auth_headers_captured(self):
        session = _session(auth_headers={})
        headers = get_auth_header_for_host(session, "api.example.com")
        assert headers == {}

    def test_returned_dict_is_a_copy_not_a_reference(self):
        session = _session(auth_headers={
            "api.example.com": {"authorization": "Bearer abc123"},
        })
        headers = get_auth_header_for_host(session, "api.example.com")
        headers["authorization"] = "tampered"
        assert session["auth_headers"]["api.example.com"]["authorization"] == "Bearer abc123"
