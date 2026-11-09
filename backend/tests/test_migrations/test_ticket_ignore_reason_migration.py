"""Integration tests for the Ticket ignore reason Alembic migration
(backend/alembic/versions/57504b9961b3_add_ticket_ignore_reason.py).

Verifies that upgrading from the previous head adds the nullable
`ignore_reason` column, `chk_ticket_ignore_reason_valid` with exactly the
TicketIgnoreReason values of its time (`not_shipped`, `cve_rejected`, and
`other`; revision bd5d2327569b adds `cna_policy`), and
`chk_ticket_ignore_reason_status_coherence`
(`docs/data-model.md`, Ticket, TicketIgnoreReason Enum). Every Ticket that is
already `Ignored` receives `cve_rejected` when its CVE is `REJECTED` and
`other` otherwise, whether its CVE is `PUBLISHED` or it has none; no other
Ticket receives a reason, no audit event is created, and an earlier
`status_change` into `Ignored` keeps `detail = NULL`
(`docs/features/tickets/tickets.md`, Ignore Reason). Downgrade removes
exactly what the revision added and keeps every status; re-upgrade restores
the reasons.

See `tests/test_migrations/conftest.py` for the shared Alembic test
infrastructure (dedicated database fixture, isolated config helper).
"""

from __future__ import annotations

import re
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import create_async_engine

from alembic import command
from app.config import settings
from tests.test_migrations.conftest import isolated_alembic_config, run_sync

_PREVIOUS_HEAD = "a522444f26a5"
_REVISION = "57504b9961b3"

_VALID = "chk_ticket_ignore_reason_valid"
_REVISION_REASONS = frozenset({"not_shipped", "cve_rejected", "other"})
"""The values that this revision's CHECK admits."""
_COHERENCE = "chk_ticket_ignore_reason_status_coherence"
_EXPECTED_COHERENCE = (
    "CHECK (((((status)::text = 'Ignored'::text) AND (ignore_reason IS NOT NULL)) "
    "OR (((status)::text <> 'Ignored'::text) AND (ignore_reason IS NULL))))"
)

_CVES = (("CVE-2099-0001", "REJECTED"), ("CVE-2099-0002", "PUBLISHED"))
_TICKETS: tuple[tuple[int, str, str | None, str | None], ...] = (
    # (sequence_id, status, CVE, reason after the upgrade)
    (1, "Ignored", "CVE-2099-0001", "cve_rejected"),
    (2, "Ignored", "CVE-2099-0002", "other"),
    (3, "Ignored", None, "other"),
    (4, "New", None, None),
    (5, "Analysis", None, None),
)

type _Row = tuple[int, str, str | None]
"""(sequence_id, status, ignore_reason)."""


async def _execute_async(database_url: str, sql: str, **params: Any) -> None:
    engine = create_async_engine(database_url)
    try:
        async with engine.begin() as conn:
            await conn.execute(text(sql), params)
    finally:
        await engine.dispose()


def _execute(database_url: str, sql: str, **params: Any) -> None:
    run_sync(_execute_async(database_url, sql, **params))


def _seed(database_url: str) -> None:
    """Rows valid at the previous revision: two CVEs, the Tickets, and one
    earlier `status_change` into `Ignored` of the first Ticket."""
    for cve, state in _CVES:
        _execute(
            database_url,
            "INSERT INTO cve (cve_id, cve_state) VALUES (:cve_id, :state)",
            cve_id=cve,
            state=state,
        )
    for sequence_id, status, cve_id, _ in _TICKETS:
        _execute(
            database_url,
            "INSERT INTO ticket (sequence_id, status, cve_id) VALUES "
            "(:sequence_id, :status, (SELECT id FROM cve WHERE cve_id = :cve_id))",
            sequence_id=sequence_id,
            status=status,
            cve_id=cve_id,
        )
    _execute(
        database_url,
        "INSERT INTO ticket_audit_event "
        "(ticket_id, event_type, old_value, new_value, comment) VALUES "
        "((SELECT id FROM ticket WHERE sequence_id = 1), 'status_change', "
        "'New', 'Ignored', 'CVE rejected')",
    )


async def _state_async(
    database_url: str,
) -> tuple[str, dict[str, str], dict[str, tuple[str, str]], list[tuple[Any, ...]]]:
    engine = create_async_engine(database_url)
    try:
        async with engine.connect() as conn:
            version = (
                await conn.execute(text("SELECT version_num FROM alembic_version"))
            ).scalar_one()
            constraints = await conn.execute(
                text(
                    "SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint "
                    "WHERE conrelid = 'ticket'::regclass"
                )
            )
            columns = await conn.execute(
                text(
                    "SELECT column_name, data_type, is_nullable "
                    "FROM information_schema.columns WHERE table_name = 'ticket'"
                )
            )
            events = await conn.execute(
                text(
                    "SELECT event_type, user_id, old_value, new_value, comment, "
                    "detail FROM ticket_audit_event ORDER BY id"
                )
            )
            return (
                version,
                {row.conname: row.pg_get_constraintdef for row in constraints},
                {row.column_name: (row.data_type, row.is_nullable) for row in columns},
                [tuple(row) for row in events],
            )
    finally:
        await engine.dispose()


def _state(
    database_url: str,
) -> tuple[str, dict[str, str], dict[str, tuple[str, str]], list[tuple[Any, ...]]]:
    return run_sync(_state_async(database_url))


_ROWS_WITHOUT_REASON = (
    "SELECT sequence_id, status, NULL AS reason FROM ticket ORDER BY sequence_id"
)
_ROWS_WITH_REASON = (
    "SELECT sequence_id, status, ignore_reason AS reason FROM ticket "
    "ORDER BY sequence_id"
)


async def _rows_async(database_url: str, sql: str) -> list[_Row]:
    engine = create_async_engine(database_url)
    try:
        async with engine.connect() as conn:
            rows = await conn.execute(text(sql))
            return [(row.sequence_id, row.status, row.reason) for row in rows]
    finally:
        await engine.dispose()


def _rows(database_url: str, *, with_reason: bool) -> list[_Row]:
    sql = _ROWS_WITH_REASON if with_reason else _ROWS_WITHOUT_REASON
    return run_sync(_rows_async(database_url, sql))


_EVENTS = [("status_change", None, "New", "Ignored", "CVE rejected", None)]


def _assert_previous(
    database_url: str,
    previous_constraints: dict[str, str],
    previous_columns: dict[str, tuple[str, str]],
) -> None:
    version, constraints, columns, events = _state(database_url)
    assert version == _PREVIOUS_HEAD
    assert constraints == previous_constraints
    assert columns == previous_columns
    assert events == _EVENTS
    assert _rows(database_url, with_reason=False) == [
        (n, status, None) for n, status, _, _ in _TICKETS
    ]


def _assert_upgraded(
    database_url: str,
    previous_constraints: dict[str, str],
    previous_columns: dict[str, tuple[str, str]],
) -> None:
    version, constraints, columns, events = _state(database_url)
    assert version == _REVISION
    added = {
        name: definition
        for name, definition in constraints.items()
        if name not in previous_constraints
    }
    assert set(added) == {_VALID, _COHERENCE}
    assert constraints == {**previous_constraints, **added}
    assert added[_COHERENCE] == _EXPECTED_COHERENCE
    # `alembic check` does not compare CHECK expressions: the literal value
    # list of this revision is the TicketIgnoreReason of its time; the later
    # `cna_policy` is added by its own revision
    # (`test_cna_audit_event_migration.py`).
    assert added[_VALID].startswith("CHECK (((ignore_reason)::text = ANY (")
    assert set(re.findall(r"'([^']*)'", added[_VALID])) == _REVISION_REASONS
    assert columns == {
        **previous_columns,
        "ignore_reason": ("character varying", "YES"),
    }
    assert events == _EVENTS
    assert _rows(database_url, with_reason=True) == [
        (n, status, reason) for n, status, _, reason in _TICKETS
    ]


@pytest.mark.integration
class TestTicketIgnoreReasonMigration:
    def test_upgrade_downgrade_reupgrade_cycle(
        self,
        alembic_test_database_url: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The backfill gives each `Ignored` Ticket its reason and no other
        Ticket one; exactly the column and both constraints are added and
        removed; every other Ticket column and constraint, every status, and
        the earlier audit event keep their values through the cycle."""
        monkeypatch.setattr(settings, "database_url", alembic_test_database_url)
        cfg = isolated_alembic_config()
        url = alembic_test_database_url

        command.upgrade(cfg, _PREVIOUS_HEAD)
        _seed(url)
        _, previous_constraints, previous_columns, _ = _state(url)
        assert "chk_ticket_priority_override_provenance" in previous_constraints

        command.upgrade(cfg, _REVISION)
        _assert_upgraded(url, previous_constraints, previous_columns)

        command.downgrade(cfg, _PREVIOUS_HEAD)
        _assert_previous(url, previous_constraints, previous_columns)

        command.upgrade(cfg, _REVISION)
        _assert_upgraded(url, previous_constraints, previous_columns)

    @pytest.mark.parametrize(
        ("status", "reason", "constraint"),
        [
            ("Ignored", None, _COHERENCE),
            ("New", "other", _COHERENCE),
            ("Ignored", "not_for_us", _VALID),
        ],
    )
    def test_constraints_reject_incoherent_rows_after_upgrade(
        self,
        alembic_test_database_url: str,
        monkeypatch: pytest.MonkeyPatch,
        status: str,
        reason: str | None,
        constraint: str,
    ) -> None:
        """After the upgrade, an `Ignored` Ticket without a reason, a reason
        outside `Ignored`, and an unknown value are rejected (the complete
        matrix is in `tests/test_models/test_ticket.py`)."""
        monkeypatch.setattr(settings, "database_url", alembic_test_database_url)
        cfg = isolated_alembic_config()
        url = alembic_test_database_url
        command.upgrade(cfg, _REVISION)

        with pytest.raises(IntegrityError, match=constraint):
            _execute(
                url,
                "INSERT INTO ticket (sequence_id, status, ignore_reason) "
                "VALUES (1, :status, :reason)",
                status=status,
                reason=reason,
            )
