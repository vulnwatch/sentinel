"""Integration tests for the Product eligibility override provenance Alembic
migration
(backend/alembic/versions/7d1b4ce4cc79_add_ticket_package_product_eligibility_override_provenance.py).

Verifies that upgrading from the previous head adds the nullable
`eligibility_override_by_id` (FK to `user.id`, ON DELETE RESTRICT) and
`eligibility_override_at` columns and exactly
`chk_ticket_package_product_eligibility_override_provenance`
(`docs/data-model.md`, TicketPackageProduct), that existing occurrences
without an override survive it unchanged with no provenance, that the
constraint then rejects an override without provenance (the complete matrix
is in `tests/test_models/test_ticket_package_product.py`), and that an
existing override makes the upgrade fail and leaves the database at the
previous revision with its rows unchanged
(`docs/features/packages/package-model.md`, Override Model;
`docs/features/packages/package-service.md`, Architectural Test
Requirement, Override provenance). Downgrade removes exactly what the
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

_PREVIOUS_HEAD = "bd5d2327569b"
_REVISION = "7d1b4ce4cc79"

_CONSTRAINT = "chk_ticket_package_product_eligibility_override_provenance"
_EXPECTED_CHECK = (
    "CHECK ((((is_eligible_override = false) "
    "AND (eligibility_override_by_id IS NULL) "
    "AND (eligibility_override_at IS NULL)) "
    "OR ((is_eligible_override = true) "
    "AND (eligibility_override_by_id IS NOT NULL) "
    "AND (eligibility_override_at IS NOT NULL))))"
)
_EXPECTED_FOREIGN_KEY = (
    'FOREIGN KEY (eligibility_override_by_id) REFERENCES "user"(id) ON DELETE RESTRICT'
)
_ROWS = (("cpe:/o:example:alpha:1", True), ("cpe:/o:example:beta:1", False))
"""(Product CPE, eligible) of the occurrences without an override."""

type _Row = tuple[str, bool, bool]
"""(Product CPE, eligible, is_eligible_override), ordered by CPE."""


async def _execute_async(database_url: str, sql: str, **params: Any) -> Any:
    engine = create_async_engine(database_url)
    try:
        async with engine.begin() as conn:
            result = await conn.execute(text(sql), params)
            return result.scalar_one() if result.returns_rows else None
    finally:
        await engine.dispose()


def _execute(database_url: str, sql: str, **params: Any) -> Any:
    return run_sync(_execute_async(database_url, sql, **params))


def _insert_track(database_url: str) -> Any:
    """One Ticket with one package and one IBS track; returns the track id."""
    _execute(database_url, "INSERT INTO ticket (sequence_id) VALUES (1)")
    package_id = _execute(
        database_url,
        "INSERT INTO ticket_package (ticket_id, package_name) "
        "SELECT id, 'example-package' FROM ticket RETURNING id",
    )
    return _execute(
        database_url,
        "INSERT INTO ticket_package_track (ticket_package_id, workflow_type, "
        "reference) VALUES (:package_id, 'ibs', 'EXAMPLE:1:Update') RETURNING id",
        package_id=package_id,
    )


def _insert_occurrence(
    database_url: str,
    track_id: Any,
    cpe: str,
    eligible: bool,
    is_eligible_override: bool = False,
) -> None:
    """A catalog Product and its occurrence below `track_id`, with only the
    columns of the previous revision, in one statement, so that a rejected
    occurrence leaves no Product behind."""
    _execute(
        database_url,
        "WITH product_row AS ("
        "INSERT INTO product (name, version, display_name, cpe, "
        "catalog_last_seen_at) VALUES ('example', '1', :cpe, :cpe, now()) "
        "RETURNING id) "
        "INSERT INTO ticket_package_product (ticket_package_track_id, "
        "product_id, eligible, is_eligible_override) "
        "SELECT :track_id, id, :eligible, :is_eligible_override FROM product_row",
        cpe=cpe,
        track_id=track_id,
        eligible=eligible,
        is_eligible_override=is_eligible_override,
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
                    "WHERE conrelid = 'ticket_package_product'::regclass "
                    "AND contype IN ('c', 'f')"
                )
            )
            columns = await conn.execute(
                text(
                    "SELECT column_name, data_type, is_nullable "
                    "FROM information_schema.columns "
                    "WHERE table_name = 'ticket_package_product'"
                )
            )
            rows = await conn.execute(
                text(
                    "SELECT p.cpe, o.eligible, o.is_eligible_override "
                    "FROM ticket_package_product o "
                    "JOIN product p ON p.id = o.product_id ORDER BY p.cpe"
                )
            )
            return (
                version,
                {row.conname: row.pg_get_constraintdef for row in constraints},
                {row.column_name: (row.data_type, row.is_nullable) for row in columns},
                [(row.cpe, row.eligible, row.is_eligible_override) for row in rows],
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
                    "SELECT o.eligibility_override_by_id, o.eligibility_override_at "
                    "FROM ticket_package_product o "
                    "JOIN product p ON p.id = o.product_id ORDER BY p.cpe"
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
    track_id: Any,
    previous_constraints: dict[str, str],
    previous_columns: dict[str, tuple[str, str]],
) -> None:
    version, constraints, columns, rows = _state(database_url)
    assert version == _REVISION
    foreign_keys = {
        name: definition
        for name, definition in constraints.items()
        if name not in previous_constraints
        and definition.startswith("FOREIGN KEY (eligibility_override_by_id)")
    }
    assert list(foreign_keys.values()) == [_EXPECTED_FOREIGN_KEY]
    assert constraints == {
        **previous_constraints,
        **foreign_keys,
        _CONSTRAINT: _EXPECTED_CHECK,
    }
    assert columns == {
        **previous_columns,
        "eligibility_override_by_id": ("uuid", "YES"),
        "eligibility_override_at": ("timestamp with time zone", "YES"),
    }
    assert rows == [(cpe, eligible, False) for cpe, eligible in _ROWS]
    assert run_sync(_provenance_async(database_url)) == [(None, None)] * len(_ROWS)
    with pytest.raises(IntegrityError, match=_CONSTRAINT):
        _insert_occurrence(
            database_url, track_id, "cpe:/o:example:gamma:1", False, True
        )


@pytest.mark.integration
class TestEligibilityOverrideProvenanceMigration:
    def test_upgrade_downgrade_reupgrade_cycle(
        self,
        alembic_test_database_url: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Exactly the columns, their foreign key, and the constraint are
        added and removed; every other column and constraint of the
        occurrence keeps its definition through the cycle."""
        monkeypatch.setattr(settings, "database_url", alembic_test_database_url)
        cfg = isolated_alembic_config()
        url = alembic_test_database_url

        command.upgrade(cfg, _PREVIOUS_HEAD)
        track_id = _insert_track(url)
        for cpe, eligible in _ROWS:
            _insert_occurrence(url, track_id, cpe, eligible)
        _, previous_constraints, previous_columns, _ = _state(url)
        assert "ticket_package_product_product_id_fkey" in previous_constraints
        expected_rows: list[_Row] = [(cpe, eligible, False) for cpe, eligible in _ROWS]

        command.upgrade(cfg, _REVISION)
        _assert_upgraded(url, track_id, previous_constraints, previous_columns)

        command.downgrade(cfg, _PREVIOUS_HEAD)
        _assert_previous(url, previous_constraints, previous_columns, expected_rows)

        command.upgrade(cfg, _REVISION)
        _assert_upgraded(url, track_id, previous_constraints, previous_columns)

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
        track_id = _insert_track(url)
        _insert_occurrence(url, track_id, "cpe:/o:example:alpha:1", True)
        _insert_occurrence(url, track_id, "cpe:/o:example:beta:1", False, True)
        _, previous_constraints, previous_columns, _ = _state(url)

        with pytest.raises(IntegrityError, match=_CONSTRAINT):
            command.upgrade(cfg, _REVISION)

        _assert_previous(
            url,
            previous_constraints,
            previous_columns,
            [
                ("cpe:/o:example:alpha:1", True, False),
                ("cpe:/o:example:beta:1", False, True),
            ],
        )
