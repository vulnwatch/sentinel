"""Integration tests for the Ticket priority override provenance Alembic
migration
(backend/alembic/versions/a522444f26a5_add_ticket_priority_override_provenance.py).

Verifies that upgrading from the previous head adds the nullable
`priority_override_by_id` (FK to `user.id`, ON DELETE RESTRICT) and
`priority_override_at` columns and exactly
`chk_ticket_priority_override_provenance` (`docs/data-model.md`, Ticket),
that existing Tickets without an override survive it unchanged with no
provenance, that the constraint then rejects an override without provenance
(the complete matrix is in `tests/test_models/test_ticket.py`), and that an
existing override makes the upgrade fail and leaves the database at the
previous revision with its rows unchanged
(`docs/features/tickets/ticket-priority.md`, Persistence and Effective
Priority; Testing Requirements, item 11). Downgrade removes exactly what the
revision added, and re-upgrade restores it.

See `tests/test_migrations/conftest.py` for the shared Alembic test
infrastructure (dedicated database fixture, isolated config helper).
"""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import create_async_engine

from alembic import command
from app.config import settings
from tests.test_migrations.conftest import isolated_alembic_config, run_sync

_PREVIOUS_HEAD = "e1c8a6f82708"
_REVISION = "a522444f26a5"

_CONSTRAINT = "chk_ticket_priority_override_provenance"
_EXPECTED_CHECK = (
    "CHECK ((((priority_override IS NULL) AND (priority_override_by_id IS NULL) "
    "AND (priority_override_at IS NULL)) OR ((priority_override IS NOT NULL) "
    "AND (priority_override_by_id IS NOT NULL) "
    "AND (priority_override_at IS NOT NULL))))"
)
_EXPECTED_FOREIGN_KEY = (
    'FOREIGN KEY (priority_override_by_id) REFERENCES "user"(id) ON DELETE RESTRICT'
)
_ROWS = ((1, None), (2, "P2"))
"""(sequence_id, priority_auto) of the Tickets without an override."""

type _Row = tuple[int, str | None, str | None]
"""(sequence_id, priority_auto, priority_override)."""


async def _execute_async(database_url: str, sql: str, **params: Any) -> None:
    engine = create_async_engine(database_url)
    try:
        async with engine.begin() as conn:
            await conn.execute(text(sql), params)
    finally:
        await engine.dispose()


def _execute(database_url: str, sql: str, **params: Any) -> None:
    run_sync(_execute_async(database_url, sql, **params))


def _insert_ticket(
    database_url: str,
    sequence_id: int,
    priority_auto: str | None,
    priority_override: str | None = None,
) -> None:
    _execute(
        database_url,
        "INSERT INTO ticket (sequence_id, priority_auto, priority_override) "
        "VALUES (:sequence_id, :priority_auto, :priority_override)",
        sequence_id=sequence_id,
        priority_auto=priority_auto,
        priority_override=priority_override,
    )


async def _state_async(
    database_url: str,
) -> tuple[str, dict[str, str], dict[str, tuple[str, str]], list[_Row]]:
    engine = create_async_engine(database_url)
    try:
        async with engine.connect() as conn:
            version = (
                await conn.execute(text("SELECT version_num FROM alembic_version"))
            ).scalar_one()
            constraints = await conn.execute(
                text(
                    "SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint "
                    "WHERE conrelid = 'ticket'::regclass AND contype IN ('c', 'f')"
                )
            )
            columns = await conn.execute(
                text(
                    "SELECT column_name, data_type, is_nullable "
                    "FROM information_schema.columns WHERE table_name = 'ticket'"
                )
            )
            rows = await conn.execute(
                text(
                    "SELECT sequence_id, priority_auto, priority_override FROM ticket "
                    "ORDER BY sequence_id"
                )
            )
            return (
                version,
                {row.conname: row.pg_get_constraintdef for row in constraints},
                {row.column_name: (row.data_type, row.is_nullable) for row in columns},
                [
                    (row.sequence_id, row.priority_auto, row.priority_override)
                    for row in rows
                ],
            )
    finally:
        await engine.dispose()


def _state(
    database_url: str,
) -> tuple[str, dict[str, str], dict[str, tuple[str, str]], list[_Row]]:
    return run_sync(_state_async(database_url))


async def _provenance_async(database_url: str) -> list[tuple[Any, Any]]:
    engine = create_async_engine(database_url)
    try:
        async with engine.connect() as conn:
            rows = await conn.execute(
                text(
                    "SELECT priority_override_by_id, priority_override_at "
                    "FROM ticket ORDER BY sequence_id"
                )
            )
            return [tuple(row) for row in rows]
    finally:
        await engine.dispose()


def _assert_previous(
    database_url: str,
    previous_constraints: dict[str, str],
    previous_columns: dict[str, tuple[str, str]],
    rows: list[_Row],
) -> None:
    version, constraints, columns, current_rows = _state(database_url)
    assert version == _PREVIOUS_HEAD
    assert constraints == previous_constraints
    assert columns == previous_columns
    assert current_rows == rows


def _assert_upgraded(
    database_url: str,
    previous_constraints: dict[str, str],
    previous_columns: dict[str, tuple[str, str]],
) -> None:
    version, constraints, columns, rows = _state(database_url)
    assert version == _REVISION
    foreign_keys = {
        name: definition
        for name, definition in constraints.items()
        if name not in previous_constraints
        and definition.startswith("FOREIGN KEY (priority_override_by_id)")
    }
    assert list(foreign_keys.values()) == [_EXPECTED_FOREIGN_KEY]
    assert constraints == {
        **previous_constraints,
        **foreign_keys,
        _CONSTRAINT: _EXPECTED_CHECK,
    }
    assert columns == {
        **previous_columns,
        "priority_override_by_id": ("uuid", "YES"),
        "priority_override_at": ("timestamp with time zone", "YES"),
    }
    assert rows == [(n, auto, None) for n, auto in _ROWS]
    assert run_sync(_provenance_async(database_url)) == [(None, None)] * len(_ROWS)
    with pytest.raises(IntegrityError, match=_CONSTRAINT):
        _insert_ticket(database_url, len(_ROWS) + 1, None, "P1")


@pytest.mark.integration
class TestTicketPriorityOverrideProvenanceMigration:
    def test_upgrade_downgrade_reupgrade_cycle(
        self,
        alembic_test_database_url: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Exactly the columns, their foreign key, and the constraint are
        added and removed; every other Ticket column and constraint keeps
        its definition through the cycle."""
        monkeypatch.setattr(settings, "database_url", alembic_test_database_url)
        cfg = isolated_alembic_config()
        url = alembic_test_database_url

        command.upgrade(cfg, _PREVIOUS_HEAD)
        for sequence_id, priority_auto in _ROWS:
            _insert_ticket(url, sequence_id, priority_auto)
        _, previous_constraints, previous_columns, _ = _state(url)
        assert "chk_ticket_coordinated_release_not_before_creation" in (
            previous_constraints
        )
        expected_rows: list[_Row] = [(n, auto, None) for n, auto in _ROWS]

        command.upgrade(cfg, _REVISION)
        _assert_upgraded(url, previous_constraints, previous_columns)

        command.downgrade(cfg, _PREVIOUS_HEAD)
        _assert_previous(url, previous_constraints, previous_columns, expected_rows)

        command.upgrade(cfg, _REVISION)
        _assert_upgraded(url, previous_constraints, previous_columns)

    def test_existing_override_fails_the_upgrade(
        self,
        alembic_test_database_url: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """No provenance source exists outside audit history, so the upgrade
        fails and leaves the database at the previous revision."""
        monkeypatch.setattr(settings, "database_url", alembic_test_database_url)
        cfg = isolated_alembic_config()
        url = alembic_test_database_url

        command.upgrade(cfg, _PREVIOUS_HEAD)
        _insert_ticket(url, 1, None)
        _insert_ticket(url, 2, "P3", "P1")
        _, previous_constraints, previous_columns, _ = _state(url)

        with pytest.raises(IntegrityError, match=_CONSTRAINT):
            command.upgrade(cfg, _REVISION)

        _assert_previous(
            url,
            previous_constraints,
            previous_columns,
            [(1, None, None), (2, "P3", "P1")],
        )
