"""Integration tests for the Ticket Coordinated Release Date CHECK Alembic
migration
(backend/alembic/versions/e1c8a6f82708_constrain_ticket_coordinated_release_.py).

Verifies that upgrading from the previous head adds exactly
`chk_ticket_coordinated_release_not_before_creation` (`docs/data-model.md`,
Ticket, CHECK constraints) with its documented expression, that existing
rows without a CRD, with a CRD equal to `created_at`, and with a later CRD
survive it unchanged, that the constraint then rejects a CRD before
`created_at`, and that an existing violating row makes the upgrade fail.
Downgrade removes only the new constraint, and re-upgrade restores it.

See `tests/test_migrations/conftest.py` for the shared Alembic test
infrastructure (dedicated database fixture, isolated config helper).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import create_async_engine

from alembic import command
from app.config import settings
from tests.test_migrations.conftest import isolated_alembic_config, run_sync

_PREVIOUS_HEAD = "24059622568d"
_REVISION = "e1c8a6f82708"

_CONSTRAINT = "chk_ticket_coordinated_release_not_before_creation"
_EXPECTED_DEFINITION = (
    "CHECK (((coordinated_release_at IS NULL) "
    "OR (coordinated_release_at >= created_at)))"
)
_CREATED_AT = datetime(2026, 3, 10, 14, 37, 21, 123456, tzinfo=UTC)
_ROWS = (
    (_CREATED_AT, None),
    (_CREATED_AT + timedelta(days=1), _CREATED_AT + timedelta(days=1)),
    (_CREATED_AT + timedelta(days=2), _CREATED_AT + timedelta(days=9)),
)
"""(created_at, coordinated_release_at): none, equal, and later."""


async def _execute_async(database_url: str, sql: str, **params: Any) -> None:
    engine = create_async_engine(database_url)
    try:
        async with engine.begin() as conn:
            await conn.execute(text(sql), params)
    finally:
        await engine.dispose()


def _insert_ticket(
    database_url: str, created_at: datetime, coordinated_release_at: datetime | None
) -> None:
    run_sync(
        _execute_async(
            database_url,
            "INSERT INTO ticket (created_at, coordinated_release_at) "
            "VALUES (:created_at, :coordinated_release_at)",
            created_at=created_at,
            coordinated_release_at=coordinated_release_at,
        )
    )


async def _state_async(
    database_url: str,
) -> tuple[dict[str, str], list[tuple[datetime, datetime | None]]]:
    engine = create_async_engine(database_url)
    try:
        async with engine.connect() as conn:
            checks = await conn.execute(
                text(
                    "SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint "
                    "WHERE conrelid = 'ticket'::regclass AND contype = 'c'"
                )
            )
            rows = await conn.execute(
                text(
                    "SELECT created_at, coordinated_release_at FROM ticket "
                    "ORDER BY created_at"
                )
            )
            return (
                {row.conname: row.pg_get_constraintdef for row in checks},
                [(row.created_at, row.coordinated_release_at) for row in rows],
            )
    finally:
        await engine.dispose()


def _state(
    database_url: str,
) -> tuple[dict[str, str], list[tuple[datetime, datetime | None]]]:
    return run_sync(_state_async(database_url))


def _assert_previous_head(database_url: str) -> None:
    checks, rows = _state(database_url)
    assert _CONSTRAINT not in checks
    assert rows == list(_ROWS)


def _assert_upgraded(database_url: str) -> None:
    checks, rows = _state(database_url)
    assert checks[_CONSTRAINT] == _EXPECTED_DEFINITION
    assert rows == list(_ROWS)
    with pytest.raises(IntegrityError, match=_CONSTRAINT):
        _insert_ticket(
            database_url, _CREATED_AT, _CREATED_AT - timedelta(microseconds=1)
        )


@pytest.mark.integration
class TestTicketCoordinatedReleaseCheckMigration:
    def test_upgrade_downgrade_reupgrade_cycle(
        self,
        alembic_test_database_url: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(settings, "database_url", alembic_test_database_url)
        cfg = isolated_alembic_config()

        command.upgrade(cfg, _PREVIOUS_HEAD)
        for created_at, crd in _ROWS:
            _insert_ticket(alembic_test_database_url, created_at, crd)
        _assert_previous_head(alembic_test_database_url)

        command.upgrade(cfg, _REVISION)
        _assert_upgraded(alembic_test_database_url)

        command.downgrade(cfg, _PREVIOUS_HEAD)
        _assert_previous_head(alembic_test_database_url)

        command.upgrade(cfg, _REVISION)
        _assert_upgraded(alembic_test_database_url)

    def test_existing_crd_before_creation_fails_the_upgrade(
        self,
        alembic_test_database_url: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(settings, "database_url", alembic_test_database_url)
        cfg = isolated_alembic_config()

        command.upgrade(cfg, _PREVIOUS_HEAD)
        _insert_ticket(
            alembic_test_database_url,
            _CREATED_AT,
            _CREATED_AT - timedelta(microseconds=1),
        )

        with pytest.raises(IntegrityError, match=_CONSTRAINT):
            command.upgrade(cfg, _REVISION)
        checks, _ = _state(alembic_test_database_url)
        assert _CONSTRAINT not in checks
