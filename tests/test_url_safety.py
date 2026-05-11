"""
Unit tests for _check_url_safety (Google Safe Browsing v5, Protobuf wire format).
Uses unittest.mock to avoid real HTTP calls.

GSB v5 REST API returns application/x-protobuf — we build minimal Protobuf
binary responses by hand to test the manual parser.
"""

import asyncio
import hashlib
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest.mock import AsyncMock, MagicMock, patch


class FakePlugin:
    """Minimal stand-in for URLFilterBot so _check_url_safety can run."""

    def __init__(self, config):
        self.config = config
        self.log = MagicMock()

    async def _check_url_safety(self, domain):
        from main import URLFilterBot

        return await URLFilterBot._check_url_safety(self, domain)


class FakeValidatePlugin:
    """Minimal stand-in for URLFilterBot so _validate_gsb_config can run."""

    def __init__(self, config):
        self.config = config
        self.log = MagicMock()

    async def _validate_gsb_config(self):
        from main import URLFilterBot

        return await URLFilterBot._validate_gsb_config(self)


# ---------------------------------------------------------------------------
# Protobuf Wire-Format Helpers (encode side — for building test fixtures)
# ---------------------------------------------------------------------------


def _pb_encode_varint(n: int) -> bytes:
    """Encode a non-negative integer as a Protobuf varint."""
    out = bytearray()
    while n > 0x7F:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n & 0x7F)
    return bytes(out)


def _pb_tag(field_num: int, wire_type: int) -> bytes:
    return _pb_encode_varint((field_num << 3) | wire_type)


def _build_full_hash_detail(threat_type_int: int) -> bytes:
    """Build a FullHashDetail message with the given ThreatType enum value."""
    # field 1 (threat_type, varint)
    return _pb_tag(1, 0) + _pb_encode_varint(threat_type_int)


def _build_full_hash(domain: str, threat_type_int: int) -> bytes:
    """Build a FullHash message with the SHA-256 of https://domain/ and a threat detail."""
    digest = hashlib.sha256(f"https://{domain}/".encode()).digest()
    detail = _build_full_hash_detail(threat_type_int)
    # field 1 (full_hash, bytes) + field 2 (full_hash_details, message)
    return (
        _pb_tag(1, 2)
        + _pb_encode_varint(len(digest))
        + digest
        + _pb_tag(2, 2)
        + _pb_encode_varint(len(detail))
        + detail
    )


def _build_search_hashes_response(*full_hashes: bytes) -> bytes:
    """Build a SearchHashesResponse containing the given FullHash messages."""
    body = b""
    for fh in full_hashes:
        body += _pb_tag(1, 2) + _pb_encode_varint(len(fh)) + fh
    return body


def _hit_response(domain: str, threat_type_int: int) -> bytes:
    """Convenience: build a response with exactly one matching FullHash."""
    return _build_search_hashes_response(_build_full_hash(domain, threat_type_int))


# Threat type enum values (matching GSB v5 protobuf)
TT_UNSPECIFIED = 0
TT_MALWARE = 1
TT_SOCIAL_ENGINEERING = 2
TT_UNWANTED_SOFTWARE = 3
TT_POTENTIALLY_HARMFUL = 4


# ---------------------------------------------------------------------------
# aiohttp mocking helpers
# ---------------------------------------------------------------------------


def _make_response(status: int = 200, body: bytes = b""):
    """Build a mocked aiohttp response with raw bytes body."""
    resp = MagicMock()
    resp.status = status
    resp.read = AsyncMock(return_value=body)
    resp.text = AsyncMock(return_value="")
    return resp


def _patch_aiohttp(resp):
    """Return a patch context manager for aiohttp.ClientSession.get."""
    get_ctx = MagicMock()
    get_ctx.__aenter__ = AsyncMock(return_value=resp)
    get_ctx.__aexit__ = AsyncMock(return_value=False)

    session = MagicMock()
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    session.get = MagicMock(return_value=get_ctx)

    return patch("aiohttp.ClientSession", return_value=session)


# ---------------------------------------------------------------------------
# Parser unit tests (test the wire-format parser directly)
# ---------------------------------------------------------------------------


class TestProtobufParser:
    def test_parses_empty_response(self):
        from main import _pb_parse_search_hashes_response

        assert _pb_parse_search_hashes_response(b"") == []

    def test_parses_single_hit(self):
        from main import _pb_parse_search_hashes_response

        body = _hit_response("evil.com", TT_MALWARE)
        result = _pb_parse_search_hashes_response(body)
        assert len(result) == 1
        digest = hashlib.sha256(b"https://evil.com/").digest()
        assert result[0] == (digest, TT_MALWARE)

    def test_parses_multiple_hits(self):
        from main import _pb_parse_search_hashes_response

        body = _build_search_hashes_response(
            _build_full_hash("evil1.com", TT_MALWARE),
            _build_full_hash("evil2.com", TT_SOCIAL_ENGINEERING),
        )
        result = _pb_parse_search_hashes_response(body)
        assert len(result) == 2
        threat_types = sorted(tt for _, tt in result)
        assert threat_types == [TT_MALWARE, TT_SOCIAL_ENGINEERING]


# ---------------------------------------------------------------------------
# _check_url_safety — feature disabled
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestCheckUrlSafetyDisabled:
    async def test_disabled_returns_disabled(self):
        plugin = FakePlugin({"url_safety_check": {"enabled": False}})
        result = await plugin._check_url_safety("evil.com")
        assert result.verdict == "disabled"
        assert result.threat_type == ""


# ---------------------------------------------------------------------------
# _check_url_safety — missing API key
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestCheckUrlSafetyNoKey:
    async def test_missing_api_key_returns_error(self):
        plugin = FakePlugin({"url_safety_check": {"enabled": True, "api_key": ""}})
        result = await plugin._check_url_safety("evil.com")
        assert result.verdict == "error"
        assert "API-Key" in result.detail


# ---------------------------------------------------------------------------
# _check_url_safety — HTTP responses
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestCheckUrlSafetyResponses:
    async def test_safe_empty_protobuf(self):
        plugin = FakePlugin(
            {"url_safety_check": {"enabled": True, "api_key": "FAKE", "timeout": 3}}
        )
        resp = _make_response(200, b"")
        with _patch_aiohttp(resp):
            result = await plugin._check_url_safety("example.com")
        assert result.verdict == "safe"
        assert result.threat_type == ""

    async def test_malicious_social_engineering(self):
        domain = "evil-phishing.com"
        plugin = FakePlugin(
            {"url_safety_check": {"enabled": True, "api_key": "FAKE", "timeout": 3}}
        )
        resp = _make_response(200, _hit_response(domain, TT_SOCIAL_ENGINEERING))
        with _patch_aiohttp(resp):
            result = await plugin._check_url_safety(domain)
        assert result.verdict == "malicious"
        assert result.threat_type == "SOCIAL_ENGINEERING"

    async def test_malicious_malware(self):
        domain = "evil-malware.com"
        plugin = FakePlugin(
            {"url_safety_check": {"enabled": True, "api_key": "FAKE", "timeout": 3}}
        )
        resp = _make_response(200, _hit_response(domain, TT_MALWARE))
        with _patch_aiohttp(resp):
            result = await plugin._check_url_safety(domain)
        assert result.verdict == "malicious"
        assert result.threat_type == "MALWARE"

    async def test_malicious_unwanted_software(self):
        domain = "adware.com"
        plugin = FakePlugin(
            {"url_safety_check": {"enabled": True, "api_key": "FAKE", "timeout": 3}}
        )
        resp = _make_response(200, _hit_response(domain, TT_UNWANTED_SOFTWARE))
        with _patch_aiohttp(resp):
            result = await plugin._check_url_safety(domain)
        assert result.verdict == "malicious"
        assert result.threat_type == "UNWANTED_SOFTWARE"

    async def test_suspicious_unspecified_threat(self):
        domain = "weird-site.com"
        plugin = FakePlugin(
            {"url_safety_check": {"enabled": True, "api_key": "FAKE", "timeout": 3}}
        )
        resp = _make_response(200, _hit_response(domain, TT_UNSPECIFIED))
        with _patch_aiohttp(resp):
            result = await plugin._check_url_safety(domain)
        assert result.verdict == "suspicious"
        assert result.threat_type == "THREAT_TYPE_UNSPECIFIED"

    async def test_no_match_when_fullhash_differs(self):
        """Response contains a full hash for a DIFFERENT domain → safe."""
        plugin = FakePlugin(
            {"url_safety_check": {"enabled": True, "api_key": "FAKE", "timeout": 3}}
        )
        # Build a response for "other-domain.com" but query "example.com"
        resp = _make_response(200, _hit_response("other-domain.com", TT_MALWARE))
        with _patch_aiohttp(resp):
            result = await plugin._check_url_safety("example.com")
        assert result.verdict == "safe"

    async def test_http_403_returns_error(self):
        plugin = FakePlugin(
            {"url_safety_check": {"enabled": True, "api_key": "FAKE", "timeout": 3}}
        )
        resp = _make_response(403)
        with _patch_aiohttp(resp):
            result = await plugin._check_url_safety("example.com")
        assert result.verdict == "error"
        assert "403" in result.detail

    async def test_http_404_returns_error(self):
        plugin = FakePlugin(
            {"url_safety_check": {"enabled": True, "api_key": "FAKE", "timeout": 3}}
        )
        resp = _make_response(404)
        with _patch_aiohttp(resp):
            result = await plugin._check_url_safety("example.com")
        assert result.verdict == "error"
        assert "404" in result.detail

    async def test_timeout_returns_error(self):
        plugin = FakePlugin(
            {"url_safety_check": {"enabled": True, "api_key": "FAKE", "timeout": 3}}
        )
        get_ctx = MagicMock()
        get_ctx.__aenter__ = AsyncMock(side_effect=asyncio.TimeoutError())
        get_ctx.__aexit__ = AsyncMock(return_value=False)
        session = MagicMock()
        session.__aenter__ = AsyncMock(return_value=session)
        session.__aexit__ = AsyncMock(return_value=False)
        session.get = MagicMock(return_value=get_ctx)
        with patch("aiohttp.ClientSession", return_value=session):
            result = await plugin._check_url_safety("example.com")
        assert result.verdict == "error"
        assert "Timeout" in result.detail


# ---------------------------------------------------------------------------
# _validate_gsb_config
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestValidateGsbConfigDisabled:
    async def test_disabled_returns_immediately(self):
        plugin = FakeValidatePlugin({"url_safety_check": {"enabled": False}})
        await plugin._validate_gsb_config()  # must not raise
        plugin.log.critical.assert_not_called()


@pytest.mark.asyncio
class TestValidateGsbConfigNoKey:
    async def test_missing_api_key_raises(self):
        plugin = FakeValidatePlugin(
            {"url_safety_check": {"enabled": True, "api_key": ""}}
        )
        with pytest.raises(ValueError, match="api_key fehlt"):
            await plugin._validate_gsb_config()
        plugin.log.critical.assert_called_once()


@pytest.mark.asyncio
class TestValidateGsbConfigSuccess:
    async def test_valid_key_http_200_allows_start(self):
        plugin = FakeValidatePlugin(
            {"url_safety_check": {"enabled": True, "api_key": "FAKE", "timeout": 3}}
        )
        resp = _make_response(200, b"")
        with _patch_aiohttp(resp):
            await plugin._validate_gsb_config()  # must not raise
        plugin.log.critical.assert_not_called()


@pytest.mark.asyncio
class TestValidateGsbConfigHttpErrors:
    async def test_http_404_raises(self):
        plugin = FakeValidatePlugin(
            {"url_safety_check": {"enabled": True, "api_key": "FAKE", "timeout": 3}}
        )
        resp = _make_response(404)
        resp.text = AsyncMock(return_value="not found")
        with _patch_aiohttp(resp):
            with pytest.raises(ValueError, match="HTTP 404"):
                await plugin._validate_gsb_config()

    async def test_http_400_raises(self):
        plugin = FakeValidatePlugin(
            {"url_safety_check": {"enabled": True, "api_key": "FAKE", "timeout": 3}}
        )
        resp = _make_response(400)
        resp.text = AsyncMock(return_value="bad request")
        with _patch_aiohttp(resp):
            with pytest.raises(ValueError, match="HTTP 400"):
                await plugin._validate_gsb_config()


@pytest.mark.asyncio
class TestValidateGsbConfigTimeout:
    async def test_timeout_raises(self):
        plugin = FakeValidatePlugin(
            {"url_safety_check": {"enabled": True, "api_key": "FAKE", "timeout": 3}}
        )
        get_ctx = MagicMock()
        get_ctx.__aenter__ = AsyncMock(side_effect=asyncio.TimeoutError())
        get_ctx.__aexit__ = AsyncMock(return_value=False)
        session = MagicMock()
        session.__aenter__ = AsyncMock(return_value=session)
        session.__aexit__ = AsyncMock(return_value=False)
        session.get = MagicMock(return_value=get_ctx)
        with patch("aiohttp.ClientSession", return_value=session):
            with pytest.raises(ValueError, match="Timeout"):
                await plugin._validate_gsb_config()
        plugin.log.critical.assert_called_once()


@pytest.mark.asyncio
class TestValidateGsbConfigException:
    async def test_generic_exception_raises(self):
        plugin = FakeValidatePlugin(
            {"url_safety_check": {"enabled": True, "api_key": "FAKE", "timeout": 3}}
        )
        get_ctx = MagicMock()
        get_ctx.__aenter__ = AsyncMock(side_effect=ConnectionError("no route"))
        get_ctx.__aexit__ = AsyncMock(return_value=False)
        session = MagicMock()
        session.__aenter__ = AsyncMock(return_value=session)
        session.__aexit__ = AsyncMock(return_value=False)
        session.get = MagicMock(return_value=get_ctx)
        with patch("aiohttp.ClientSession", return_value=session):
            with pytest.raises(ValueError, match="no route"):
                await plugin._validate_gsb_config()
        plugin.log.critical.assert_called_once()
