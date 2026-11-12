"""Integration tests for the `User.avatar_url` Alembic migration
(backend/alembic/versions/24109dcbef28_add_avatar_url_to_user.py).

Verifies the migration cycle mandated by `docs/data-model.md` (User) and
`docs/features/identity/user-avatars.md` (Avatar URL): upgrade from the
previous revision adds the nullable `avatar_url VARCHAR(2048)` column
without a default, so every existing user, active, inactive, or a bot
account, reads `NULL`. Downgrade drops the column and keeps every user row.

See `tests/test_migrations/conftest.py` for the shared Alembic test
infrastructure (dedicated database fixture, isolated config helper)
used by every migration test suite in this package.
"""

from __future__ import annotations

from typing import Any, Final

import pytest
from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import create_async_engine

from alembic import command
from app.config import settings
from tests.test_migrations.conftest import isolated_alembic_config, run_sync

_PREVIOUS_REVISION: Final = "7d1b4ce4cc79"
_REVISION: Final = "24109dcbef28"
_USERS: Final = {
    "avatar-migration-active": ("true", "false"),
    "avatar-migration-inactive": ("false", "false"),
    "avatar-migration-bot": ("true", "true"),
}
"""`username -> (active, bot)` of the users seeded at the previous revision."""
_PICTURE: Final = (
    "https://avatars.slack-edge.com/2026-01-15/"
    "1000000000001_0f1c7e00000000000000_192.jpg"
)


async def _execute(database_url: str, statement: str) -> None:
    engine = create_async_engine(database_url)
    try:
        async with engine.begin() as conn:
            await conn.execute(text(statement))
    finally:
        await engine.dispose()


def _seed_pre_migration_users(database_url: str) -> None:
    """Insert users with only columns valid at the previous revision."""
    for username, (active, bot) in _USERS.items():
        run_sync(
            _execute(
                database_url,
                'INSERT INTO "user" (username, email, active, bot, password_hash) '
                f"VALUES ('{username}', '{username}@example.com', {active}, {bot}, "
                "'fictional-hash')",
            )
        )


async def _fetch(database_url: str, statement: str) -> list[Any]:
    engine = create_async_engine(database_url)
    try:
        async with engine.connect() as conn:
            return list((await conn.execute(text(statement))).all())
    finally:
        await engine.dispose()


def _avatar_urls(database_url: str) -> dict[str, str | None]:
    rows = run_sync(_fetch(database_url, 'SELECT username, avatar_url FROM "user"'))
    return {row[0]: row[1] for row in rows}


def _usernames(database_url: str) -> set[str]:
    rows = run_sync(_fetch(database_url, 'SELECT username FROM "user"'))
    return {row[0] for row in rows}


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


@pytest.mark.integration
class TestUserAvatarUrlMigration:
    def test_upgrade_downgrade_reupgrade_cycle(
        self,
        alembic_test_database_url: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(settings, "database_url", alembic_test_database_url)
        cfg = isolated_alembic_config()

        # 1. Previous revision: the column does not exist yet.
        command.upgrade(cfg, _PREVIOUS_REVISION)
        assert "avatar_url" not in _columns(alembic_test_database_url)
        _seed_pre_migration_users(alembic_test_database_url)

        # 2. Revision under test: a nullable VARCHAR(2048) without a default,
        # and every existing user has no picture.
        command.upgrade(cfg, _REVISION)
        column = _columns(alembic_test_database_url)["avatar_url"]
        assert column["nullable"] is True
        assert column["default"] is None
        assert column["type"].length == 2048
        assert _avatar_urls(alembic_test_database_url) == dict.fromkeys(_USERS)

        # A picture URL of 2048 characters is now storable.
        long_url = _PICTURE + "x" * (2048 - len(_PICTURE))
        run_sync(
            _execute(
                alembic_test_database_url,
                f"UPDATE \"user\" SET avatar_url = '{long_url}' "
                "WHERE username = 'avatar-migration-active'",
            )
        )
        assert (
            _avatar_urls(alembic_test_database_url)["avatar-migration-active"]
            == long_url
        )

        # 3. Downgrade drops the column and keeps every user row.
        command.downgrade(cfg, _PREVIOUS_REVISION)
        assert "avatar_url" not in _columns(alembic_test_database_url)
        assert _usernames(alembic_test_database_url) == set(_USERS)

        # Re-upgrade restores the column; the stored URL is gone with the
        # dropped column.
        command.upgrade(cfg, _REVISION)
        assert _avatar_urls(alembic_test_database_url) == dict.fromkeys(_USERS)
