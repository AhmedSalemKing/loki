"""Tests for req_cmd's URL building and header parsing."""
from loki.cli.req_cmd import _build_url, _parse_headers


class TestBuildUrl:
    def test_relative_path(self):
        assert _build_url("example.com", "/api/me") == "https://example.com/api/me"

    def test_adds_leading_slash_if_missing(self):
        assert _build_url("example.com", "api/me") == "https://example.com/api/me"

    def test_full_url_unchanged(self):
        url = "https://other.com/api/x"
        assert _build_url("example.com", url) == url


class TestParseHeaders:
    def test_parses_single_header(self):
        assert _parse_headers(["Authorization: Bearer abc"]) == {"Authorization": "Bearer abc"}

    def test_parses_multiple_headers(self):
        result = _parse_headers(["X-Foo: bar", "X-Baz: qux"])
        assert result == {"X-Foo": "bar", "X-Baz": "qux"}

    def test_strips_whitespace(self):
        assert _parse_headers(["X-Foo:   bar  "]) == {"X-Foo": "bar"}

    def test_empty_list_returns_empty_dict(self):
        assert _parse_headers([]) == {}
