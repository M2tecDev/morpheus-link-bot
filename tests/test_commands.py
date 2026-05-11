"""
Unit tests for moderation commands (!block, !allow, !unblock, !unallow, !mute, !unmute).
Uses unittest.mock to avoid real Matrix/DB calls.
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest.mock import AsyncMock, MagicMock

from mautrix.types import RoomID, UserID


class FakePlugin:
    """Minimal stand-in for URLFilterBot so commands can run."""

    def __init__(self, config=None):
        self.config = config or {}
        self.log = MagicMock()
        # In-Memory sets
        self.blacklist_set: set = set()
        self.whitelist_set: set = set()
        self.blacklist_wildcards: set = set()
        self.whitelist_wildcards: set = set()
        self.pending_reviews: dict = {}
        self._pending_domains: set = set()
        self._active_mutes: dict = {}

    async def cmd_block(self, evt, domains_raw):
        from main import URLFilterBot

        return await URLFilterBot.cmd_block.__mb_func__(self, evt, domains_raw)

    async def cmd_allow(self, evt, domains_raw):
        from main import URLFilterBot

        return await URLFilterBot.cmd_allow.__mb_func__(self, evt, domains_raw)

    async def cmd_unblock(self, evt, domains_raw):
        from main import URLFilterBot

        return await URLFilterBot.cmd_unblock.__mb_func__(self, evt, domains_raw)

    async def cmd_unallow(self, evt, domains_raw):
        from main import URLFilterBot

        return await URLFilterBot.cmd_unallow.__mb_func__(self, evt, domains_raw)

    async def cmd_mute(self, evt, args_raw):
        from main import URLFilterBot

        return await URLFilterBot.cmd_mute.__mb_func__(self, evt, args_raw)

    async def cmd_unmute(self, evt, args_raw):
        from main import URLFilterBot

        return await URLFilterBot.cmd_unmute.__mb_func__(self, evt, args_raw)


def _make_evt():
    """Create a minimal mocked MessageEvent."""
    evt = MagicMock()
    evt.room_id = RoomID("!test:example.com")
    evt.sender = UserID("@mod:example.com")
    evt.reply = AsyncMock()
    return evt


# ---------------------------------------------------------------------------
# !block
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestCmdBlock:
    async def test_block_adds_domain(self):
        plugin = FakePlugin()
        plugin._is_allowed_command_room = AsyncMock(return_value=True)
        plugin._is_mod = AsyncMock(return_value=True)
        plugin._db_upsert_domain_rule = AsyncMock()
        plugin._resolve_pending_for_domain = AsyncMock()

        evt = _make_evt()
        await plugin.cmd_block(evt, "evil.com")

        assert "evil.com" in plugin.blacklist_set
        assert "evil.com" not in plugin.whitelist_set
        plugin._db_upsert_domain_rule.assert_awaited_once_with(
            "evil.com", is_blacklisted=True, ignore_preview=False
        )
        evt.reply.assert_awaited_once()
        assert "evil.com" in evt.reply.await_args[0][0]

    async def test_block_wildcard(self):
        plugin = FakePlugin()
        plugin._is_allowed_command_room = AsyncMock(return_value=True)
        plugin._is_mod = AsyncMock(return_value=True)
        plugin._db_upsert_domain_rule = AsyncMock()
        plugin._resolve_pending_for_domain = AsyncMock()

        evt = _make_evt()
        await plugin.cmd_block(evt, "*.evil.com")

        assert "evil.com" in plugin.blacklist_wildcards
        plugin._db_upsert_domain_rule.assert_awaited_once()

    async def test_block_duplicate(self):
        plugin = FakePlugin()
        plugin.blacklist_set.add("evil.com")
        plugin._is_allowed_command_room = AsyncMock(return_value=True)
        plugin._is_mod = AsyncMock(return_value=True)
        plugin._db_upsert_domain_rule = AsyncMock()
        plugin._resolve_pending_for_domain = AsyncMock()

        evt = _make_evt()
        await plugin.cmd_block(evt, "evil.com")

        plugin._db_upsert_domain_rule.assert_not_called()
        assert "bereits auf der Blacklist" in evt.reply.await_args[0][0]

    async def test_block_invalid_domain(self):
        plugin = FakePlugin()
        plugin._is_allowed_command_room = AsyncMock(return_value=True)
        plugin._is_mod = AsyncMock(return_value=True)
        plugin._db_upsert_domain_rule = AsyncMock()

        evt = _make_evt()
        await plugin.cmd_block(evt, "not-a-domain")

        plugin._db_upsert_domain_rule.assert_not_called()
        assert "ungültige Domain" in evt.reply.await_args[0][0]

    async def test_block_not_mod(self):
        plugin = FakePlugin()
        plugin._is_allowed_command_room = AsyncMock(return_value=True)
        plugin._is_mod = AsyncMock(return_value=False)

        evt = _make_evt()
        await plugin.cmd_block(evt, "evil.com")

        assert "keine Berechtigung" in evt.reply.await_args[0][0]

    async def test_block_rejects_matrix_user_id(self):
        plugin = FakePlugin()
        plugin._is_allowed_command_room = AsyncMock(return_value=True)
        plugin._is_mod = AsyncMock(return_value=True)
        plugin._db_upsert_domain_rule = AsyncMock()

        evt = _make_evt()
        await plugin.cmd_block(evt, "@spammer:matrix.org")

        plugin._db_upsert_domain_rule.assert_not_called()
        assert "Matrix-Nutzer/Raum-IDs" in evt.reply.await_args[0][0]
        assert "@spammer:matrix.org" not in plugin.blacklist_set
        assert "matrix.org" not in plugin.blacklist_set

    async def test_block_rejects_matrix_room_id(self):
        plugin = FakePlugin()
        plugin._is_allowed_command_room = AsyncMock(return_value=True)
        plugin._is_mod = AsyncMock(return_value=True)
        plugin._db_upsert_domain_rule = AsyncMock()

        evt = _make_evt()
        await plugin.cmd_block(evt, "!roomid:matrix.org")

        plugin._db_upsert_domain_rule.assert_not_called()
        assert "Matrix-Nutzer/Raum-IDs" in evt.reply.await_args[0][0]
        assert "matrix.org" not in plugin.blacklist_set

    async def test_block_rejects_matrix_alias(self):
        plugin = FakePlugin()
        plugin._is_allowed_command_room = AsyncMock(return_value=True)
        plugin._is_mod = AsyncMock(return_value=True)
        plugin._db_upsert_domain_rule = AsyncMock()

        evt = _make_evt()
        await plugin.cmd_block(evt, "#alias:matrix.org")

        plugin._db_upsert_domain_rule.assert_not_called()
        assert "Matrix-Nutzer/Raum-IDs" in evt.reply.await_args[0][0]

    async def test_block_mixed_domain_and_mxid(self):
        plugin = FakePlugin()
        plugin._is_allowed_command_room = AsyncMock(return_value=True)
        plugin._is_mod = AsyncMock(return_value=True)
        plugin._db_upsert_domain_rule = AsyncMock()
        plugin._resolve_pending_for_domain = AsyncMock()

        evt = _make_evt()
        await plugin.cmd_block(evt, "evil.com @opfer:home.tld")

        # gültige Domain wird geblockt, MXID übersprungen
        assert "evil.com" in plugin.blacklist_set
        assert "home.tld" not in plugin.blacklist_set
        plugin._db_upsert_domain_rule.assert_awaited_once_with(
            "evil.com", is_blacklisted=True, ignore_preview=False
        )
        reply = evt.reply.await_args[0][0]
        assert "Matrix-Nutzer/Raum-IDs" in reply
        assert "evil.com" in reply

    async def test_block_rejects_colon_format(self):
        plugin = FakePlugin()
        plugin._is_allowed_command_room = AsyncMock(return_value=True)
        plugin._is_mod = AsyncMock(return_value=True)
        plugin._db_upsert_domain_rule = AsyncMock()

        evt = _make_evt()
        await plugin.cmd_block(evt, "spammer:matrix.org")

        plugin._db_upsert_domain_rule.assert_not_called()
        assert "ungültige Domain" in evt.reply.await_args[0][0]
        assert "spammer:matrix.org" not in plugin.blacklist_set

    async def test_block_rejects_full_url(self):
        plugin = FakePlugin()
        plugin._is_allowed_command_room = AsyncMock(return_value=True)
        plugin._is_mod = AsyncMock(return_value=True)
        plugin._db_upsert_domain_rule = AsyncMock()

        evt = _make_evt()
        await plugin.cmd_block(evt, "https://evil.com")

        plugin._db_upsert_domain_rule.assert_not_called()
        assert "ungültige Domain" in evt.reply.await_args[0][0]

    async def test_block_multiple_domains(self):
        plugin = FakePlugin()
        plugin._is_allowed_command_room = AsyncMock(return_value=True)
        plugin._is_mod = AsyncMock(return_value=True)
        plugin._db_upsert_domain_rule = AsyncMock()
        plugin._resolve_pending_for_domain = AsyncMock()

        evt = _make_evt()
        await plugin.cmd_block(evt, "evil1.com evil2.com")

        assert "evil1.com" in plugin.blacklist_set
        assert "evil2.com" in plugin.blacklist_set
        assert plugin._db_upsert_domain_rule.await_count == 2


# ---------------------------------------------------------------------------
# !allow
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestCmdAllow:
    async def test_allow_adds_domain(self):
        plugin = FakePlugin()
        plugin._is_allowed_command_room = AsyncMock(return_value=True)
        plugin._is_mod = AsyncMock(return_value=True)
        plugin._db_upsert_domain_rule = AsyncMock()
        plugin._resolve_pending_for_domain = AsyncMock()

        evt = _make_evt()
        await plugin.cmd_allow(evt, "good.com")

        assert "good.com" in plugin.whitelist_set
        assert "good.com" not in plugin.blacklist_set
        plugin._db_upsert_domain_rule.assert_awaited_once_with(
            "good.com", is_blacklisted=False, ignore_preview=False
        )

    async def test_allow_wildcard(self):
        plugin = FakePlugin()
        plugin._is_allowed_command_room = AsyncMock(return_value=True)
        plugin._is_mod = AsyncMock(return_value=True)
        plugin._db_upsert_domain_rule = AsyncMock()
        plugin._resolve_pending_for_domain = AsyncMock()

        evt = _make_evt()
        await plugin.cmd_allow(evt, "*.good.com")

        assert "good.com" in plugin.whitelist_wildcards

    async def test_allow_rejects_matrix_user_id(self):
        plugin = FakePlugin()
        plugin._is_allowed_command_room = AsyncMock(return_value=True)
        plugin._is_mod = AsyncMock(return_value=True)
        plugin._db_upsert_domain_rule = AsyncMock()

        evt = _make_evt()
        await plugin.cmd_allow(evt, "@alice:matrix.org")

        plugin._db_upsert_domain_rule.assert_not_called()
        assert "Matrix-Nutzer/Raum-IDs" in evt.reply.await_args[0][0]
        assert "matrix.org" not in plugin.whitelist_set

    async def test_allow_duplicate(self):
        plugin = FakePlugin()
        plugin.whitelist_set.add("good.com")
        plugin._is_allowed_command_room = AsyncMock(return_value=True)
        plugin._is_mod = AsyncMock(return_value=True)
        plugin._db_upsert_domain_rule = AsyncMock()

        evt = _make_evt()
        await plugin.cmd_allow(evt, "good.com")

        plugin._db_upsert_domain_rule.assert_not_called()
        assert "bereits auf der Whitelist" in evt.reply.await_args[0][0]


# ---------------------------------------------------------------------------
# !unblock
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestCmdUnblock:
    async def test_unblock_removes_domain(self):
        plugin = FakePlugin()
        plugin.blacklist_set.add("evil.com")
        plugin._is_allowed_command_room = AsyncMock(return_value=True)
        plugin._is_mod = AsyncMock(return_value=True)
        plugin._db_delete_domain_rule = AsyncMock()

        evt = _make_evt()
        await plugin.cmd_unblock(evt, "evil.com")

        assert "evil.com" not in plugin.blacklist_set
        plugin._db_delete_domain_rule.assert_awaited_once_with("evil.com")

    async def test_unblock_wildcard(self):
        plugin = FakePlugin()
        plugin.blacklist_wildcards.add("evil.com")
        plugin._is_allowed_command_room = AsyncMock(return_value=True)
        plugin._is_mod = AsyncMock(return_value=True)
        plugin._db_delete_domain_rule = AsyncMock()

        evt = _make_evt()
        await plugin.cmd_unblock(evt, "*.evil.com")

        assert "evil.com" not in plugin.blacklist_wildcards


# ---------------------------------------------------------------------------
# !unallow
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestCmdUnallow:
    async def test_unallow_removes_domain(self):
        plugin = FakePlugin()
        plugin.whitelist_set.add("good.com")
        plugin._is_allowed_command_room = AsyncMock(return_value=True)
        plugin._is_mod = AsyncMock(return_value=True)
        plugin._db_delete_domain_rule = AsyncMock()

        evt = _make_evt()
        await plugin.cmd_unallow(evt, "good.com")

        assert "good.com" not in plugin.whitelist_set
        plugin._db_delete_domain_rule.assert_awaited_once_with("good.com")


# ---------------------------------------------------------------------------
# !mute
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestCmdMute:
    async def test_mute_user(self):
        plugin = FakePlugin(
            {
                "mute_commands_enabled": True,
                "mute_duration_minutes": 60,
            }
        )
        plugin._is_allowed_command_room = AsyncMock(return_value=True)
        plugin._is_mod = AsyncMock(return_value=True)
        plugin._mute_user_global = AsyncMock(return_value=1)

        evt = _make_evt()
        await plugin.cmd_mute(evt, "@spammer:matrix.org")

        plugin._mute_user_global.assert_awaited_once()
        assert "stummgeschaltet" in evt.reply.await_args[0][0]

    async def test_mute_not_mod(self):
        plugin = FakePlugin({"mute_commands_enabled": True})
        plugin._is_allowed_command_room = AsyncMock(return_value=True)
        plugin._is_mod = AsyncMock(return_value=False)

        evt = _make_evt()
        await plugin.cmd_mute(evt, "@spammer:matrix.org")

        assert "keine Berechtigung" in evt.reply.await_args[0][0]

    async def test_mute_disabled(self):
        plugin = FakePlugin({"mute_commands_enabled": False})
        plugin._is_allowed_command_room = AsyncMock(return_value=True)
        plugin._is_mod = AsyncMock(return_value=True)

        evt = _make_evt()
        await plugin.cmd_mute(evt, "@spammer:matrix.org")

        # Wenn mute_commands_enabled=False, wird stillschweigend returned
        evt.reply.assert_not_called()


# ---------------------------------------------------------------------------
# !unmute
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestCmdUnmute:
    async def test_unmute_user(self):
        plugin = FakePlugin({"mute_commands_enabled": True})
        plugin._is_allowed_command_room = AsyncMock(return_value=True)
        plugin._is_mod = AsyncMock(return_value=True)
        plugin._unmute_user_global = AsyncMock(return_value=1)

        evt = _make_evt()
        await plugin.cmd_unmute(evt, "@spammer:matrix.org")

        plugin._unmute_user_global.assert_awaited_once()
        assert "entstummt" in evt.reply.await_args[0][0]

    async def test_unmute_not_mod(self):
        plugin = FakePlugin({"mute_commands_enabled": True})
        plugin._is_allowed_command_room = AsyncMock(return_value=True)
        plugin._is_mod = AsyncMock(return_value=False)

        evt = _make_evt()
        await plugin.cmd_unmute(evt, "@spammer:matrix.org")

        assert "keine Berechtigung" in evt.reply.await_args[0][0]
