"""Tests for diff_cmd's URL building and IDOR verdict logic."""
from loki.cli.diff_cmd import _build_url, _verdict


class TestBuildUrl:
    def test_relative_path_gets_https_and_host(self):
        assert _build_url("api.example.com", "/api/orders/1") == "https://api.example.com/api/orders/1"

    def test_path_without_leading_slash_gets_one_added(self):
        assert _build_url("api.example.com", "api/orders/1") == "https://api.example.com/api/orders/1"

    def test_full_url_passed_through_unchanged(self):
        url = "https://other.example.com/api/x"
        assert _build_url("api.example.com", url) == url


class TestVerdict:
    def test_attacker_denied_is_properly_protected(self):
        label, color = _verdict({"status": 200, "size": 100}, {"status": 403, "size": 20})
        assert "PROPERLY PROTECTED" in label
        assert color == "green"

    def test_attacker_gets_identical_200_is_possible_idor(self):
        label, color = _verdict({"status": 200, "size": 500}, {"status": 200, "size": 505})
        assert "POSSIBLE IDOR" in label
        assert color == "red"

    def test_attacker_gets_different_size_200_still_flagged(self):
        label, color = _verdict({"status": 200, "size": 500}, {"status": 200, "size": 50})
        assert "POSSIBLE IDOR" in label

    def test_error_response_is_reported_as_error(self):
        label, color = _verdict({"status": 200}, {"status": 0, "error": "Failed to fetch"})
        assert "ERROR" in label
        assert color == "yellow"

    def test_unexpected_status_is_inconclusive(self):
        label, color = _verdict({"status": 200}, {"status": 500})
        assert "INCONCLUSIVE" in label
