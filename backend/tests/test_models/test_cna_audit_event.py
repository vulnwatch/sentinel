"""Tests for the CNAAuditEvent model (backend/app/models/cna_audit_event.py).

See docs/data-model.md (CNAAuditEvent) and docs/features/tickets/cna.md
(CNA Audit Log) for the full specification. These tests exercise the raw
persistence contract (columns, constraints, indexes) by constructing rows
directly, bypassing `CNAAuditLog.log_event()` validation on purpose —
service-layer validation is covered by
tests/test_services/test_cna_policy_service.py.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from typing import cast

import pytest
from sqlalchemy import String, Table, delete, inspect, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cna import CNA
from app.models.cna_audit_event import CNAAuditEvent
from app.models.mixins import AuditEventMixin
from app.models.user import User

_TABLE = cast(Table, CNAAuditEvent.__table__)


@pytest.mark.unit
class TestCNAAuditEventMetadata:
    """Structural assertions over SQLAlchemy metadata, independent of any
    database round-trip."""

    def test_table_and_columns(self) -> None:
        table = _TABLE
        assert table.name == "cna_audit_event"
        assert set(table.columns.keys()) == {
            "id",
            "created_at",
            "user_id",
            "cna_id",
            "event_type",
            "old_value",
            "new_value",
            "detail",
        }

    def test_inherits_audit_event_mixin_without_updated_at(self) -> None:
        """Audit event tables are append-only
        (docs/features/platform/audit-trail-infrastructure.md,
        AuditEventMixin)."""
        assert issubclass(CNAAuditEvent, AuditEventMixin)
        assert CNAAuditEvent in AuditEventMixin.__subclasses__()
        assert not hasattr(CNAAuditEvent, "updated_at")

    @pytest.mark.parametrize("column", ["cna_id", "user_id"])
    def test_foreign_keys_use_ondelete_restrict(self, column: str) -> None:
        fks = [
            fk
            for fk in CNAAuditEvent.__table__.foreign_keys
            if fk.parent.name == column
        ]
        assert len(fks) == 1
        assert fks[0].ondelete == "RESTRICT"

    @pytest.mark.parametrize(
        ("column", "nullable"),
        [
            ("cna_id", False),
            ("event_type", False),
            ("user_id", True),
            ("old_value", True),
            ("new_value", True),
            ("detail", True),
        ],
    )
    def test_nullability(self, column: str, nullable: bool) -> None:
        assert CNAAuditEvent.__table__.columns[column].nullable is nullable

    def test_indexes(self) -> None:
        """`cna_id` for the `cna` filter of the CNA audit log, plus the
        `created_at` and `user_id` indexes inherited from the mixin
        (audit-trail-infrastructure.md, Indexing)."""
        indexes = {
            index.name: [column.name for column in index.columns]
            for index in _TABLE.indexes
        }
        assert indexes == {
            "ix_cna_audit_event_cna_id": ["cna_id"],
            "ix_cna_audit_event_created_at": ["created_at"],
            "ix_cna_audit_event_user_id": ["user_id"],
        }


@pytest.mark.integration
class TestCNAAuditEventPersistence:
    async def test_create_and_relationships(
        self,
        db_session: AsyncSession,
        cna_factory: Callable[..., Awaitable[CNA]],
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        cna = await cna_factory()
        user = await user_factory()
        event = CNAAuditEvent(
            cna_id=cna.id,
            user_id=user.id,
            event_type="auto_ignore_enabled",
            detail={"cna_name": "example"},
        )
        db_session.add(event)
        await db_session.flush()

        assert event.id.version == 7
        assert event.created_at is not None
        assert (event.old_value, event.new_value) == (None, None)
        await db_session.refresh(event, attribute_names=["cna", "actor"])
        assert event.cna is cna
        assert event.actor is user
        await db_session.refresh(cna, attribute_names=["audit_events"])
        assert cna.audit_events == [event]

    async def test_missing_cna_rejected(self, db_session: AsyncSession) -> None:
        db_session.add(CNAAuditEvent(event_type="auto_ignore_enabled"))
        with pytest.raises(IntegrityError, match="cna_id"):
            await db_session.flush()

    async def test_missing_event_type_rejected(
        self,
        db_session: AsyncSession,
        cna_factory: Callable[..., Awaitable[CNA]],
    ) -> None:
        cna = await cna_factory()
        db_session.add(CNAAuditEvent(cna_id=cna.id))
        with pytest.raises(IntegrityError, match="event_type"):
            await db_session.flush()

    async def test_unknown_cna_rejected(self, db_session: AsyncSession) -> None:
        db_session.add(
            CNAAuditEvent(cna_id=uuid.uuid7(), event_type="auto_ignore_enabled")
        )
        with pytest.raises(IntegrityError, match="cna_audit_event_cna_id_fkey"):
            await db_session.flush()

    async def test_unknown_user_rejected(
        self,
        db_session: AsyncSession,
        cna_factory: Callable[..., Awaitable[CNA]],
    ) -> None:
        cna = await cna_factory()
        db_session.add(
            CNAAuditEvent(
                cna_id=cna.id, user_id=uuid.uuid7(), event_type="auto_ignore_enabled"
            )
        )
        with pytest.raises(IntegrityError, match="cna_audit_event_user_id_fkey"):
            await db_session.flush()

    async def test_cna_with_an_event_cannot_be_deleted(
        self,
        db_session: AsyncSession,
        cna_factory: Callable[..., Awaitable[CNA]],
    ) -> None:
        cna = await cna_factory()
        db_session.add(CNAAuditEvent(cna_id=cna.id, event_type="auto_ignore_enabled"))
        await db_session.flush()
        with pytest.raises(IntegrityError, match="cna_audit_event_cna_id_fkey"):
            await db_session.execute(delete(CNA).where(CNA.id == cna.id))

    async def test_event_type_is_not_constrained_in_the_database(
        self,
        db_session: AsyncSession,
        cna_factory: Callable[..., Awaitable[CNA]],
    ) -> None:
        """`CNAAuditEventType` is Category B (docs/data-model.md): the
        service validates it, the database does not."""
        cna = await cna_factory()
        db_session.add(CNAAuditEvent(cna_id=cna.id, event_type="unknown"))
        await db_session.flush()
        stored = await db_session.scalar(
            select(CNAAuditEvent.event_type).where(CNAAuditEvent.cna_id == cna.id)
        )
        assert stored == "unknown"
        column_type = inspect(CNAAuditEvent).columns["event_type"].type
        assert isinstance(column_type, String)
        assert column_type.length == 50
