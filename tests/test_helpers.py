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
    _is_matrix_to_deeplink,
    _is_onion_host,
    _looks_like_matrix_identifier,
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

    def test_rejects_matrix_user_id(self):
        assert _valid_domain("@spammer:matrix.org") is False

    def test_rejects_matrix_user_id_wildcard(self):
        assert _valid_domain("*.@spammer:matrix.org") is False

    def test_rejects_host_colon_port(self):
        assert _valid_domain("user:matrix.org") is False
        assert _valid_domain("spammer:matrix.org") is False

    def test_rejects_host_colon_port_wildcard(self):
        assert _valid_domain("*.user:matrix.org") is False

    def test_rejects_full_url(self):
        assert _valid_domain("https://evil.com") is False
        assert _valid_domain("http://evil.com") is False

    def test_rejects_url_with_subdomain(self):
        assert _valid_domain("https://sub.evil.com") is False

    def test_rejects_url_with_port(self):
        assert _valid_domain("https://evil.com:8080") is False


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


# ---------------------------------------------------------------------------
# _is_onion_host
# ---------------------------------------------------------------------------


class TestIsOnionHost:
    def test_simple_onion(self):
        assert _is_onion_host("abc.onion") is True

    def test_long_v3_onion(self):
        assert (
            _is_onion_host(
                "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"
            )
            is True
        )

    def test_uppercase_onion(self):
        assert _is_onion_host("EXAMPLE.ONION") is True

    def test_with_subdomain(self):
        assert _is_onion_host("sub.abc.onion") is True

    def test_trailing_dot(self):
        assert _is_onion_host("abc.onion.") is True

    def test_clearnet_com(self):
        assert _is_onion_host("example.com") is False

    def test_bare_onion(self):
        # nur das Suffix selbst zählt nicht
        assert _is_onion_host("onion") is False
        assert _is_onion_host(".onion") is False

    def test_empty(self):
        assert _is_onion_host("") is False

    def test_onion_in_middle(self):
        assert _is_onion_host("onion.com") is False


# ---------------------------------------------------------------------------
# URLFilterBot._extract_domains — .onion-Erkennung
# ---------------------------------------------------------------------------


class TestExtractDomainsOnion:
    def test_naked_onion(self):
        domains = URLFilterBot._extract_domains("Check this abc123xyz.onion link")
        assert any(d.endswith(".onion") for d in domains)

    def test_http_onion(self):
        domains = URLFilterBot._extract_domains("Visit http://abc123xyz.onion/path")
        assert any(d.endswith(".onion") for d in domains)

    def test_href_onion(self):
        formatted = '<a href="http://abc123xyz.onion">Mirror</a>'
        domains = URLFilterBot._extract_domains("Mirror link", formatted)
        assert any(d.endswith(".onion") for d in domains)

    def test_no_onion_does_not_break_normal_extraction(self):
        domains = URLFilterBot._extract_domains("Visit https://example.com today")
        assert "example.com" in domains
        assert not any(d.endswith(".onion") for d in domains)


# ---------------------------------------------------------------------------
# matrix.to-Deeplinks — auch im neuen Matrix-v12 / MSC4291 Format ohne :server
# ---------------------------------------------------------------------------


class TestLooksLikeMatrixIdentifier:
    def test_classic_room_id(self):
        assert _looks_like_matrix_identifier("!abc:example.org") is True

    def test_serverless_room_id(self):
        assert (
            _looks_like_matrix_identifier(
                "!Jos2YAuOgkGhsGbcJNx7CpQxneXZNcu5hJN1OrSVgwc"
            )
            is True
        )

    def test_classic_user_id(self):
        assert _looks_like_matrix_identifier("@alice:example.org") is True

    def test_user_id_without_server_rejected(self):
        assert _looks_like_matrix_identifier("@alice") is False

    def test_classic_room_alias(self):
        assert _looks_like_matrix_identifier("#room:example.org") is True

    def test_room_alias_without_server_rejected(self):
        assert _looks_like_matrix_identifier("#room") is False

    def test_event_id(self):
        assert _looks_like_matrix_identifier("$abc123") is True

    def test_no_sigil_rejected(self):
        assert _looks_like_matrix_identifier("randomstring") is False

    def test_empty_rejected(self):
        assert _looks_like_matrix_identifier("") is False

    def test_only_sigil_rejected(self):
        assert _looks_like_matrix_identifier("!") is False

    def test_room_id_strips_query(self):
        assert (
            _looks_like_matrix_identifier(
                "!Jos2YAuOgkGhsGbcJNx7CpQxneXZNcu5hJN1OrSVgwc?via=matrix.org"
            )
            is True
        )


class TestIsMatrixToDeeplink:
    def test_serverless_room_with_via_params(self):
        url = (
            "https://matrix.to/#/!Jos2YAuOgkGhsGbcJNx7CpQxneXZNcu5hJN1OrSVgwc"
            "?via=matrix.org&via=tchncs.de&via=nope.chat"
        )
        assert _is_matrix_to_deeplink(url) is True

    def test_serverless_room_no_via(self):
        assert (
            _is_matrix_to_deeplink(
                "https://matrix.to/#/!Jos2YAuOgkGhsGbcJNx7CpQxneXZNcu5hJN1OrSVgwc"
            )
            is True
        )

    def test_classic_room_with_via(self):
        assert (
            _is_matrix_to_deeplink(
                "https://matrix.to/#/!abc:example.org?via=matrix.org"
            )
            is True
        )

    def test_classic_user(self):
        assert _is_matrix_to_deeplink("https://matrix.to/#/@alice:example.org") is True

    def test_classic_alias(self):
        assert _is_matrix_to_deeplink("https://matrix.to/#/#room:example.org") is True

    def test_non_matrix_to_host_rejected(self):
        assert _is_matrix_to_deeplink("https://example.com/#/!abc:foo.org") is False

    def test_garbage_fragment_rejected(self):
        assert _is_matrix_to_deeplink("https://matrix.to/#/randomstring") is False


class TestExtractDomainsMatrixTo:
    """Regression: via= server hints must NOT be extracted as separate domains."""

    def test_serverless_room_id_via_params_not_extracted(self):
        body = (
            "https://matrix.to/#/!Jos2YAuOgkGhsGbcJNx7CpQxneXZNcu5hJN1OrSVgwc"
            "?via=matrix.org&via=tchncs.de&via=nope.chat"
        )
        domains = URLFilterBot._extract_domains(body)
        assert "matrix.org" not in domains
        assert "tchncs.de" not in domains
        assert "nope.chat" not in domains
        assert "matrix.to" not in domains

    def test_serverless_room_id_in_reply_quote(self):
        body = (
            "> Mika\n"
            "> https://matrix.to/#/!Jos2YAuOgkGhsGbcJNx7CpQxneXZNcu5hJN1OrSVgwc"
            "?via=matrix.org&via=tchncs.de&via=nope.chat\n"
            "Antwort"
        )
        formatted = (
            '<mx-reply><blockquote><a href="https://matrix.to/#/'
            "!Jos2YAuOgkGhsGbcJNx7CpQxneXZNcu5hJN1OrSVgwc"
            '?via=matrix.org&via=tchncs.de&via=nope.chat">#general</a>'
            "</blockquote></mx-reply>Antwort"
        )
        domains = URLFilterBot._extract_domains(body, formatted)
        assert "matrix.org" not in domains
        assert "tchncs.de" not in domains
        assert "nope.chat" not in domains
        assert "matrix.to" not in domains

    def test_normal_external_links_still_work(self):
        body = "Schau mal https://example.com vorbei"
        domains = URLFilterBot._extract_domains(body)
        assert "example.com" in domains
