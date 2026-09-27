"""Tests for fuzz_cmd's payload building and URL templating."""
import pytest
import typer
from loki.cli.fuzz_cmd import _build_payloads, _make_url, _filter_status


class TestBuildPayloads:
    def test_range_expands_inclusive(self):
        assert _build_payloads("1-5", None) == ["1", "2", "3", "4", "5"]

    def test_wordlist_and_range_can_combine(self, tmp_path):
        wl = tmp_path / "words.txt"
        wl.write_text("admin\nroot\n")
        result = _build_payloads("1-2", str(wl))
        assert result == ["1", "2", "admin", "root"]

    def test_missing_both_exits(self):
        with pytest.raises(typer.Exit):
            _build_payloads(None, None)

    def test_missing_wordlist_file_exits(self):
        with pytest.raises(typer.Exit):
            _build_payloads(None, "/no/such/file.txt")


class TestMakeUrl:
    def test_replaces_id_marker(self):
        assert _make_url("/api/user/§ID§", "example.com", "42") == "https://example.com/api/user/42"

    def test_full_url_template_passthrough_of_host(self):
        assert _make_url("https://x.com/u/§ID§", "example.com", "1") == "https://x.com/u/1"

    def test_adds_leading_slash(self):
        assert _make_url("api/§ID§", "example.com", "1") == "https://example.com/api/1"


class TestFilterStatus:
    def test_no_filter_allows_everything(self):
        assert _filter_status(None, 500) is True

    def test_filters_to_allowed_list(self):
        assert _filter_status("200,403", 200) is True
        assert _filter_status("200,403", 404) is False
