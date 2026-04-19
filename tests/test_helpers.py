"""
Unit tests for pure helper functions in main.py.
These tests require no maubot fixtures or async context.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import (  # noqa: E402
    URLFilterBot,
    _format_age,
    _split_domain_args,
    _valid_domain,
)


# ---------------------------------------------------------------------------
# _split_domain_args
# ---------------------------------------------------------------------------


class TestSplitDomainArgs:
    def test_single_domain(self):
        assert _split_domain_args("example.com") == ["example.com"]

    def test_multiple_space_separated(self):
        assert _split_domain_args("a.com b.com c.com") == ["a.com", "b.com", "c.com"]

    def test_comma_separated(self):
        assert _split_domain_args("a.com,b.com") == ["a.com", "b.com"]

    def test_semicolon_separated(self):
        assert _split_domain_args("a.com;b.com") == ["a.com", "b.com"]

    def test_lowercases(self):
        assert _split_domain_args("EXAMPLE.COM") == ["example.com"]

    def test_empty_string(self):
        assert _split_domain_args("") == []

    def test_extra_whitespace(self):
        assert _split_domain_args("  a.com   b.com  ") == ["a.com", "b.com"]

    def test_wildcard_preserved(self):
        assert _split_domain_args("*.evil.com") == ["*.evil.com"]


# ---------------------------------------------------------------------------
# _valid_domain
# ---------------------------------------------------------------------------


class TestValidDomain:
    def test_valid_plain(self):
        assert _valid_domain("example.com") is True

    def test_valid_subdomain(self):
        assert _valid_domain("sub.example.com") is True

    def test_valid_wildcard(self):
        assert _valid_domain("*.example.com") is True

    def test_invalid_no_dot(self):
        assert _valid_domain("nodot") is False

    def test_invalid_empty(self):
        assert _valid_domain("") is False

    def test_skip_localhost(self):
        assert _valid_domain("localhost") is False

    def test_skip_loopback(self):
        assert _valid_domain("127.0.0.1") is False


# ---------------------------------------------------------------------------
# _format_age
# ---------------------------------------------------------------------------


class TestFormatAge:
    def test_seconds(self):
        result = _format_age(45)
        assert "45" in result or "Sekunde" in result

    def test_minutes(self):
        result = _format_age(120)
        assert "2" in result

    def test_hours(self):
        result = _format_age(7200)
        assert "2" in result

    def test_zero(self):
        result = _format_age(0)
        assert isinstance(result, str)


# ---------------------------------------------------------------------------
# URLFilterBot._matches_apex / _matches_wildcards  (static methods)
# ---------------------------------------------------------------------------


class TestMatchesApex:
    def test_subdomain_matches_apex(self):
        assert URLFilterBot._matches_apex("sub.evil.com", {"evil.com"}) is True

    def test_deep_subdomain_matches_apex(self):
        assert URLFilterBot._matches_apex("a.b.evil.com", {"evil.com"}) is True

    def test_apex_itself_no_match(self):
        # apex of "evil.com" is "com" — must not match TLD
        assert URLFilterBot._matches_apex("evil.com", {"evil.com"}) is False

    def test_unrelated_domain_no_match(self):
        assert URLFilterBot._matches_apex("other.com", {"evil.com"}) is False


class TestMatchesWildcards:
    def test_subdomain_matches_wildcard(self):
        assert URLFilterBot._matches_wildcards("sub.evil.com", {"evil.com"}) is True

    def test_apex_does_not_match_wildcard(self):
        assert URLFilterBot._matches_wildcards("evil.com", {"evil.com"}) is False

    def test_unrelated_no_match(self):
        assert URLFilterBot._matches_wildcards("other.com", {"evil.com"}) is False


# ---------------------------------------------------------------------------
# URL normalization used in !urlstatus (inline logic)
# ---------------------------------------------------------------------------


def _normalize(raw: str) -> str:
    """Mirrors the normalization in cmd_status."""
    return raw.split("://", 1)[-1].split("/")[0]


class TestUrlNormalization:
    def test_strips_https(self):
        assert _normalize("https://example.com") == "example.com"

    def test_strips_http(self):
        assert _normalize("http://example.com") == "example.com"

    def test_strips_trailing_slash(self):
        assert _normalize("https://example.com/") == "example.com"

    def test_strips_path(self):
        assert _normalize("https://example.com/some/path") == "example.com"

    def test_plain_domain_unchanged(self):
        assert _normalize("example.com") == "example.com"

    def test_www_preserved(self):
        assert _normalize("https://www.example.com/") == "www.example.com"

    def test_full_url_facebook(self):
        assert _normalize("https://www.facebook.com/") == "www.facebook.com"
