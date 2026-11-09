"""Integration tests for the CNA audit event and `cna_policy` Alembic
migration
(backend/alembic/versions/bd5d2327569b_add_cna_audit_event_and_cna_policy_reason.py).

Verifies that upgrading from the previous head creates the
`cna_audit_event` table with exactly the columns, primary key, foreign keys
(`cna.id` and `user.id`, both ON DELETE RESTRICT), and indexes of
`docs/data-model.md` (CNAAuditEvent), and recreates
`chk_ticket_ignore_reason_valid` with exactly the TicketIgnoreReason values,
`cna_policy` included (docs/data-model.md, TicketIgnoreReason Enum). Every
existing Ticket keeps its status and reason. Downgrade turns `cna_policy`
into `other`, so the Ticket stays `Ignored` with a reason that the previous
schema accepts, and removes exactly what the revision added; re-upgrade
restores the schema.

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

_PREVIOUS_HEAD = "b169c9f216f2"
_REVISION = "bd5d2327569b"

_VALID = "chk_ticket_ignore_reason_valid"
_ORG_ID = "00000000-0000-4000-8000-0000000000a1"

_EXPECTED_COLUMNS = {
    "id": ("uuid", "NO", "uuidv7()", None),
    "created_at": ("timestamp with time zone", "NO", "now()", None),
    "user_id": ("uuid", "YES", None, None),
    "cna_id": ("uuid", "NO", None, None),
    "event_type": ("character varying", "NO", None, 50),
    "old_value": ("text", "YES", None, None),
    "new_value": ("text", "YES", None, None),
    "detail": ("jsonb", "YES", None, None),
}
_EXPECTED_CONSTRAINTS = {
    "cna_audit_event_pkey": "PRIMARY KEY (id)",
    "cna_audit_event_cna_id_fkey": (
        "FOREIGN KEY (cna_id) REFERENCES cna(id) ON DELETE RESTRICT"
    ),
    "cna_audit_event_user_id_fkey": (
        'FOREIGN KEY (user_id) REFERENCES "user"(id) ON DELETE RESTRICT'
    ),
}
_EXPECTED_INDEXES = {
    "cna_audit_event_pkey": (
        "CREATE UNIQUE INDEX cna_audit_event_pkey ON public.cna_audit_event "
        "USING btree (id)"
    ),
    "ix_cna_audit_event_created_at": (
        "CREATE INDEX ix_cna_audit_event_created_at ON public.cna_audit_event "
        "USING btree (created_at)"
    ),
    "ix_cna_audit_event_user_id": (
        "CREATE INDEX ix_cna_audit_event_user_id ON public.cna_audit_event "
        "USING btree (user_id)"
    ),
    "ix_cna_audit_event_cna_id": (
        "CREATE INDEX ix_cna_audit_event_cna_id ON public.cna_audit_event "
        "USING btree (cna_id)"
    ),
}

_TICKETS_BEFORE: tuple[tuple[int, str, str | None], ...] = (
    # (sequence_id, status, ignore_reason): valid at the previous revision.
    (1, "Ignored", "not_shipped"),
    (2, "Ignored", "cve_rejected"),
    (3, "Ignored", "other"),
    (4, "New", None),
)
_POLICY_TICKET = (5, "Ignored", "cna_policy")
"""Inserted after the upgrade; the downgrade turns its reason into `other`."""


async def _execute_async(database_url: str, sql: str, **params: Any) -> None:
    engine = create_async_engine(database_url)
    try:
        async with engine.begin() as conn:
            await conn.execute(text(sql), params)
    finally:
        await engine.dispose()


def _execute(database_url: str, sql: str, **params: Any) -> None:
    run_sync(_execute_async(database_url, sql, **params))


async def _fetch_async(database_url: str, sql: str) -> list[tuple[Any, ...]]:
    engine = create_async_engine(database_url)
    try:
        async with engine.connect() as conn:
            return [tuple(row) for row in await conn.execute(text(sql))]
    finally:
        await engine.dispose()


def _fetch(database_url: str, sql: str) -> list[tuple[Any, ...]]:
    return run_sync(_fetch_async(database_url, sql))


def _version(url: str) -> str:
    ((version,),) = _fetch(url, "SELECT version_num FROM alembic_version")
    assert isinstance(version, str)
    return version


def _table_exists(url: str) -> bool:
    ((exists,),) = _fetch(
        url, "SELECT to_regclass('public.cna_audit_event') IS NOT NULL"
    )
    return bool(exists)


def _columns(url: str) -> dict[str, tuple[Any, ...]]:
    rows = _fetch(
        url,
        "SELECT column_name, data_type, is_nullable, column_default, "
        "character_maximum_length FROM information_schema.columns "
        "WHERE table_name = 'cna_audit_event'",
    )
    return {row[0]: row[1:] for row in rows}


def _constraints(url: str, table: str) -> dict[str, str]:
    rows = _fetch(
        url,
        "SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint "
        f"WHERE conrelid = '\"{table}\"'::regclass "
        "AND contype IN ('p', 'u', 'f', 'c')",
    )
    return {str(name): str(definition) for name, definition in rows}


def _indexes(url: str) -> dict[str, str]:
    rows = _fetch(
        url,
        "SELECT indexname, indexdef FROM pg_indexes "
        "WHERE tablename = 'cna_audit_event'",
    )
    return {str(name): str(definition) for name, definition in rows}


def _tickets(url: str) -> list[tuple[Any, ...]]:
    return _fetch(
        url,
        "SELECT sequence_id, status, ignore_reason FROM ticket ORDER BY sequence_id",
    )


def _check_values(definition: str) -> set[str]:
    assert definition.startswith("CHECK (((ignore_reason)::text = ANY (")
    return set(re.findall(r"'([^']*)'", definition))


def _insert_ticket(url: str, sequence_id: int, status: str, reason: str | None) -> None:
    _execute(
        url,
        "INSERT INTO ticket (sequence_id, status, ignore_reason) "
        "VALUES (:sequence_id, :status, :reason)",
        sequence_id=sequence_id,
        status=status,
        reason=reason,
    )


def _assert_upgraded(url: str, previous_ticket_constraints: dict[str, str]) -> None:
    assert _version(url) == _REVISION
    assert _columns(url) == _EXPECTED_COLUMNS
    assert _constraints(url, "cna_audit_event") == _EXPECTED_CONSTRAINTS
    assert _indexes(url) == _EXPECTED_INDEXES
    constraints = _constraints(url, "ticket")
    # Only the value list of the enum CHECK changes.
    assert {k: v for k, v in constraints.items() if k != _VALID} == {
        k: v for k, v in previous_ticket_constraints.items() if k != _VALID
    }
    # `alembic check` does not compare CHECK expressions: the literal value
    # list is that of this revision, transcribed so that a later revision
    # adding a reason does not change what this suite proves.
    assert _check_values(constraints[_VALID]) == {
        "not_shipped",
        "cve_rejected",
        "cna_policy",
        "other",
    }


def _assert_previous(url: str, previous_ticket_constraints: dict[str, str]) -> None:
    assert _version(url) == _PREVIOUS_HEAD
    assert not _table_exists(url)
    assert _constraints(url, "ticket") == previous_ticket_constraints
    assert _check_values(previous_ticket_constraints[_VALID]) == {
        "not_shipped",
        "cve_rejected",
        "other",
    }


@pytest.mark.integration
class TestCNAAuditEventMigration:
    def test_upgrade_downgrade_reupgrade_cycle(
        self,
        alembic_test_database_url: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The table and its indexes are added and removed, the enum CHECK
        gains and loses `cna_policy`, the existing Tickets keep their status
        and reason throughout, and the downgrade gives a `cna_policy` Ticket
        the reason `other` while it stays `Ignored`."""
        monkeypatch.setattr(settings, "database_url", alembic_test_database_url)
        cfg = isolated_alembic_config()
        url = alembic_test_database_url

        command.upgrade(cfg, _PREVIOUS_HEAD)
        for sequence_id, status, reason in _TICKETS_BEFORE:
            _insert_ticket(url, sequence_id, status, reason)
        previous_ticket_constraints = _constraints(url, "ticket")
        assert not _table_exists(url)

        command.upgrade(cfg, _REVISION)
        _assert_upgraded(url, previous_ticket_constraints)
        assert _tickets(url) == list(_TICKETS_BEFORE)

        _insert_ticket(url, *_POLICY_TICKET)
        _execute(url, "INSERT INTO cna (org_id) VALUES (:org_id)", org_id=_ORG_ID)
        _execute(
            url,
            "INSERT INTO cna_audit_event (cna_id, event_type, detail) "
            "SELECT id, 'auto_ignore_enabled', '{\"cna_name\": null}'::jsonb "
            "FROM cna",
        )

        command.downgrade(cfg, _PREVIOUS_HEAD)
        _assert_previous(url, previous_ticket_constraints)
        assert _tickets(url) == [*_TICKETS_BEFORE, (5, "Ignored", "other")]
        assert _fetch(url, "SELECT org_id::text, auto_ignore FROM cna") == [
            (_ORG_ID, False)
        ]

        command.upgrade(cfg, _REVISION)
        _assert_upgraded(url, previous_ticket_constraints)
        assert _tickets(url) == [*_TICKETS_BEFORE, (5, "Ignored", "other")]

    def test_foreign_keys_and_check_after_upgrade(
        self,
        alembic_test_database_url: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """After the upgrade, an event without a CNA, an event of an unknown
        CNA, and the deletion of a CNA with an event fail, and an unknown
        ignore reason is still rejected."""
        monkeypatch.setattr(settings, "database_url", alembic_test_database_url)
        cfg = isolated_alembic_config()
        url = alembic_test_database_url
        command.upgrade(cfg, _REVISION)

        with pytest.raises(IntegrityError, match="cna_id"):
            _execute(
                url,
                "INSERT INTO cna_audit_event (event_type) "
                "VALUES ('auto_ignore_enabled')",
            )
        with pytest.raises(IntegrityError, match="cna_audit_event_cna_id_fkey"):
            _execute(
                url,
                "INSERT INTO cna_audit_event (cna_id, event_type) "
                "VALUES (:cna_id, 'auto_ignore_enabled')",
                cna_id=_ORG_ID,
            )
        _execute(url, "INSERT INTO cna (org_id) VALUES (:org_id)", org_id=_ORG_ID)
        _execute(
            url,
            "INSERT INTO cna_audit_event (cna_id, event_type) "
            "SELECT id, 'auto_ignore_enabled' FROM cna",
        )
        with pytest.raises(IntegrityError, match="cna_audit_event_cna_id_fkey"):
            _execute(url, "DELETE FROM cna")
        with pytest.raises(IntegrityError, match=_VALID):
            _insert_ticket(url, 1, "Ignored", "not_for_us")
