"""Integration tests for the `User.bot` Alembic migration
(backend/alembic/versions/24059622568d_add_bot_to_user.py).

Verifies the migration cycle mandated by `docs/data-model.md` (User) and
`docs/features/identity/user-management.md` (Bot Accounts): upgrade from
the previous head adds the non-null `bot` column with a server default of
`false`, so every existing user, local and external alike, reads `false`
with no backfill or inference. Downgrade drops the column.

See `tests/test_migrations/conftest.py` for the shared Alembic test
infrastructure (dedicated database fixture, isolated config helper)
used by every migration test suite in this package.
"""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import create_async_engine

from alembic import command
from app.config import settings
from tests.test_migrations.conftest import isolated_alembic_config, run_sync

_PREVIOUS_HEAD = "6636db334eb1"
_REVISION = "24059622568d"
_LOCAL_USERNAME = "bot-migration-local"
_EXTERNAL_USERNAME = "bot-migration-external"


async def _seed_pre_migration_users(database_url: str) -> None:
    """Insert one local and one external user using only columns valid
    under the pre-migration schema (`chk_user_auth_exclusive` holds)."""
    engine = create_async_engine(database_url)
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    'INSERT INTO "user" (username, email, active, password_hash) '
                    f"VALUES ('{_LOCAL_USERNAME}', "
                    "'bot.migration.local@example.com', true, 'fictional-hash')"
                )
            )
            await conn.execute(
                text(
                    'INSERT INTO "user" (username, email, active, external_id) '
                    f"VALUES ('{_EXTERNAL_USERNAME}', "
                    "'bot.migration.external@example.com', true, "
                    "'00000000-0000-0000-0000-000000000001')"
                )
            )
    finally:
        await engine.dispose()


async def _seed_bot_user(database_url: str) -> None:
    """Insert a bot account — only valid after the migration under test."""
    engine = create_async_engine(database_url)
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    'INSERT INTO "user" (username, email, active, password_hash, '
                    "bot) VALUES ('bot-migration-bot', "
                    "'bot.migration.bot@example.com', true, 'fictional-hash', "
                    "true)"
                )
            )
    finally:
        await engine.dispose()


async def _fetch_bot_values(database_url: str) -> dict[str, bool]:
    """Read `bot` per username — only valid once the column exists."""
    engine = create_async_engine(database_url)
    try:
        async with engine.connect() as conn:
            result = await conn.execute(text('SELECT username, bot FROM "user"'))
            return {row[0]: row[1] for row in result}
    finally:
        await engine.dispose()


async def _inspect_columns(database_url: str) -> dict[str, dict[str, Any]]:
    engine = create_async_engine(database_url)
    try:
        async with engine.connect() as conn:

            def _sync_inspect(sync_conn: Any) -> dict[str, dict[str, Any]]:
                insp = inspect(sync_conn)
                return {col["name"]: col for col in insp.get_columns("user")}

            return await conn.run_sync(_sync_inspect)
    finally:
        await engine.dispose()


def _columns(database_url: str) -> dict[str, dict[str, Any]]:
    return run_sync(_inspect_columns(database_url))


def _bot_values(database_url: str) -> dict[str, bool]:
    return run_sync(_fetch_bot_values(database_url))


@pytest.mark.integration
class TestUserBotMigration:
    def test_upgrade_downgrade_reupgrade_cycle(
        self,
        alembic_test_database_url: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(settings, "database_url", alembic_test_database_url)
        cfg = isolated_alembic_config()

        # 1. Previous head: the column does not exist yet.
        command.upgrade(cfg, _PREVIOUS_HEAD)
        assert "bot" not in _columns(alembic_test_database_url)
        run_sync(_seed_pre_migration_users(alembic_test_database_url))

        # 2. Revision under test: `bot` is NOT NULL with a `false` server
        # default, and every existing user reads `false`.
        command.upgrade(cfg, _REVISION)
        bot_column = _columns(alembic_test_database_url)["bot"]
        assert bot_column["nullable"] is False
        assert bot_column["default"] == "false"
        assert _bot_values(alembic_test_database_url) == {
            _LOCAL_USERNAME: False,
            _EXTERNAL_USERNAME: False,
        }

        # A bot account is now storable.
        run_sync(_seed_bot_user(alembic_test_database_url))
        assert _bot_values(alembic_test_database_url)["bot-migration-bot"] is True

        # 3. Downgrade drops the column and keeps every user row.
        command.downgrade(cfg, _PREVIOUS_HEAD)
        assert "bot" not in _columns(alembic_test_database_url)

        # Re-upgrade restores the column; the previous `true` value is gone
        # with the dropped column.
        command.upgrade(cfg, _REVISION)
        reupgraded = _bot_values(alembic_test_database_url)
        assert reupgraded == {
            _LOCAL_USERNAME: False,
            _EXTERNAL_USERNAME: False,
            "bot-migration-bot": False,
        }
