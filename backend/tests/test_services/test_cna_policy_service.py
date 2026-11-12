"""Single-session tests for the auto-ignore policy operation and the CNA
audit trail of `cna_service` (backend/app/services/cna_service.py):
`CNAAuditLog`, `set_cna_auto_ignore()`, and `list_cna_audit_events()`.

Owning specifications: docs/features/tickets/cna.md (Auto-Ignore Policy,
Flag; `set_cna_auto_ignore()`; `list_cna_audit_events()`; CNA Audit Log:
CNAAuditEvent, CNAAuditEventType, CNAAuditLog Service; Testing
Requirements, items 5 and 6), docs/features/platform/audit-trail-
infrastructure.md (BaseAuditLog, Atomicity, Actor Field, Date Filtering),
and docs/features/platform/testing-strategy.md (Audit Trail Testing). The
independent-session races are in
`tests/test_services/test_cna_policy_atomicity.py`.

Every test runs in the rolled-back `db_session` with fictional
organization UUIDs, names, and users.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, date, datetime
from typing import Any
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import CNAAuditEventType, TicketStatus
from app.models.cna import CNA
from app.models.cna_audit_event import CNAAuditEvent
from app.models.cve import CVE
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.user import User
from app.services import base_audit_log
from app.services.cna_service import (
    CNAAuditEventActor,
    CNAAuditLog,
    CNANotFoundError,
    list_cna_audit_events,
    set_cna_auto_ignore,
)
from app.services.cve_projection import CNASummaryProjection
from tests.support.database import rollback_test_scope
from tests.support.ticket_mutations import StatementRecorder

Factory = Callable[..., Awaitable[Any]]

ENABLED = CNAAuditEventType.AUTO_IGNORE_ENABLED
DISABLED = CNAAuditEventType.AUTO_IGNORE_DISABLED
STALE = datetime(2000, 1, 1, tzinfo=UTC)
"""An `updated_at` far before the transaction's `now()`."""

type EventValues = tuple[str, uuid.UUID, uuid.UUID | None, Any, Any, Any]
"""`(event_type, cna_id, user_id, old_value, new_value, detail)`."""


async def _events(db: AsyncSession, cna_id: uuid.UUID) -> list[EventValues]:
    rows = await db.execute(
        select(
            CNAAuditEvent.event_type,
            CNAAuditEvent.cna_id,
            CNAAuditEvent.user_id,
            CNAAuditEvent.old_value,
            CNAAuditEvent.new_value,
            CNAAuditEvent.detail,
        )
        .where(CNAAuditEvent.cna_id == cna_id)
        .order_by(CNAAuditEvent.id)
    )
    return [(row[0], row[1], row[2], row[3], row[4], row[5]) for row in rows.all()]


async def _stored(db: AsyncSession, cna_id: uuid.UUID) -> tuple[bool, datetime]:
    row = (
        await db.execute(
            select(CNA.auto_ignore, CNA.updated_at).where(CNA.id == cna_id)
        )
    ).one()
    return row[0], row[1]


async def _now(db: AsyncSession) -> datetime:
    """The transaction's `now()`, which `updated_at` takes on UPDATE."""
    instant = await db.scalar(select(func.now()))
    assert isinstance(instant, datetime)
    return instant


# ---------------------------------------------------------------------------
# CNAAuditLog (cna.md, CNAAuditLog Service)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCNAAuditLog:
    def test_registered_with_its_specified_attributes(self) -> None:
        assert base_audit_log.AUDIT_LOG_REGISTRY["cna"] is CNAAuditLog
        assert CNAAuditLog.description == "Auto-ignore policy changes of CNAs"
        assert CNAAuditLog.model_class is CNAAuditEvent

    @pytest.mark.parametrize("name", ["Example Corporation", None])
    async def test_creates_and_flushes_exactly_one_event(
        self,
        db_session: AsyncSession,
        cna_factory: Factory,
        user_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        name: str | None,
    ) -> None:
        cna = await cna_factory()
        admin = await user_factory()
        commit = AsyncMock(side_effect=AssertionError("no commit expected"))
        monkeypatch.setattr(db_session, "commit", commit)

        await CNAAuditLog.log_event(
            db_session,
            event_type=ENABLED,
            cna_id=cna.id,
            user_id=admin.id,
            detail={"cna_name": name},
        )

        assert await _events(db_session, cna.id) == [
            ("auto_ignore_enabled", cna.id, admin.id, None, None, {"cna_name": name})
        ]
        commit.assert_not_awaited()

    @pytest.mark.parametrize(
        ("overrides", "message"),
        [
            ({"event_type": "auto_ignore_enabled"}, "CNAAuditEventType member"),
            ({"event_type": None}, "CNAAuditEventType member"),
            ({"user_id": None}, "user_id is required"),
            ({"detail": None}, "exactly one 'cna_name' key"),
            ({"detail": {}}, "exactly one 'cna_name' key"),
            ({"detail": {"name": "Example"}}, "exactly one 'cna_name' key"),
            (
                {"detail": {"cna_name": "Example", "org_id": "x"}},
                "exactly one 'cna_name' key",
            ),
            ({"detail": {"cna_name": 1}}, "string or None"),
            ({"detail": {"cna_name": ["Example"]}}, "string or None"),
        ],
    )
    async def test_invalid_input_raises_before_any_database_operation(
        self,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
        overrides: dict[str, Any],
        message: str,
    ) -> None:
        kwargs: dict[str, Any] = {
            "event_type": ENABLED,
            "cna_id": uuid.uuid4(),
            "user_id": uuid.uuid4(),
            "detail": {"cna_name": "Example"},
            **overrides,
        }
        flush = AsyncMock(side_effect=AssertionError("no flush expected"))
        monkeypatch.setattr(db_session, "flush", flush)

        with pytest.raises(ValueError, match=message):
            await CNAAuditLog.log_event(db_session, **kwargs)

        flush.assert_not_awaited()
        assert list(db_session.new) == []


# ---------------------------------------------------------------------------
# set_cna_auto_ignore() (cna.md, `set_cna_auto_ignore()`; Flag)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestSetCnaAutoIgnore:
    @pytest.mark.parametrize(
        ("initial", "requested", "event_type"),
        [(False, True, ENABLED), (True, False, DISABLED)],
    )
    async def test_effective_change_writes_the_flag_and_one_event(
        self,
        db_session: AsyncSession,
        cna_factory: Factory,
        user_factory: Factory,
        initial: bool,
        requested: bool,
        event_type: CNAAuditEventType,
    ) -> None:
        cna = await cna_factory(
            auto_ignore=initial,
            organization_name="Example Corporation",
            updated_at=STALE,
        )
        admin = await user_factory()

        result = await set_cna_auto_ignore(
            db_session,
            org_id=str(cna.org_id),
            auto_ignore=requested,
            acting_user_id=admin.id,
        )

        now = await _now(db_session)
        assert result.id == cna.id
        assert result.auto_ignore is requested
        assert result.updated_at == now
        assert await _stored(db_session, cna.id) == (requested, now)
        assert await _events(db_session, cna.id) == [
            (
                event_type.value,
                cna.id,
                admin.id,
                None,
                None,
                {"cna_name": "Example Corporation"},
            )
        ]

    @pytest.mark.parametrize(
        ("organization_name", "short_name", "expected"),
        [
            ("Example Corporation", "example", "Example Corporation"),
            (None, "example", "example"),
            (None, None, None),
        ],
    )
    async def test_event_snapshots_the_display_name(
        self,
        db_session: AsyncSession,
        cna_factory: Factory,
        user_factory: Factory,
        organization_name: str | None,
        short_name: str | None,
        expected: str | None,
    ) -> None:
        """cna.md, CNAAuditEventType: `cna_name` is the display name of the
        locked row, `null` without one."""
        cna = await cna_factory(
            organization_name=organization_name, short_name=short_name
        )
        admin = await user_factory()

        await set_cna_auto_ignore(
            db_session,
            org_id=str(cna.org_id),
            auto_ignore=True,
            acting_user_id=admin.id,
        )

        [event] = await _events(db_session, cna.id)
        assert event[5] == {"cna_name": expected}

    @pytest.mark.parametrize("value", [False, True])
    async def test_unchanged_request_writes_nothing_and_creates_no_event(
        self,
        db_session: AsyncSession,
        cna_factory: Factory,
        user_factory: Factory,
        value: bool,
    ) -> None:
        cna = await cna_factory(auto_ignore=value, updated_at=STALE)
        admin = await user_factory()

        with StatementRecorder(db_session) as recorder:
            result = await set_cna_auto_ignore(
                db_session,
                org_id=str(cna.org_id),
                auto_ignore=value,
                acting_user_id=admin.id,
            )

        assert result.auto_ignore is value
        assert recorder.writes() == []
        assert await _stored(db_session, cna.id) == (value, STALE)
        assert await _events(db_session, cna.id) == []

    async def test_first_database_operation_locks_the_row_for_no_key_update(
        self,
        db_session: AsyncSession,
        cna_factory: Factory,
        user_factory: Factory,
    ) -> None:
        cna = await cna_factory()
        admin = await user_factory()

        with StatementRecorder(db_session) as recorder:
            await set_cna_auto_ignore(
                db_session,
                org_id=str(cna.org_id),
                auto_ignore=True,
                acting_user_id=admin.id,
            )

        first = recorder.statements[0]
        assert first.startswith("SELECT cna.")
        assert first.rstrip().endswith("FOR NO KEY UPDATE")
        assert recorder.row_locks() == [first]

    async def test_reinvocation_creates_one_event(
        self,
        db_session: AsyncSession,
        cna_factory: Factory,
        user_factory: Factory,
    ) -> None:
        cna = await cna_factory()
        admin = await user_factory()

        for _ in range(2):
            await set_cna_auto_ignore(
                db_session,
                org_id=str(cna.org_id),
                auto_ignore=True,
                acting_user_id=admin.id,
            )

        assert [event[0] for event in await _events(db_session, cna.id)] == [
            "auto_ignore_enabled"
        ]

    async def test_org_id_is_compared_case_insensitively(
        self,
        db_session: AsyncSession,
        cna_factory: Factory,
        user_factory: Factory,
    ) -> None:
        cna = await cna_factory(
            org_id=uuid.UUID("00000000-0000-4000-8000-0000000abcde")
        )
        admin = await user_factory()

        result = await set_cna_auto_ignore(
            db_session,
            org_id="00000000-0000-4000-8000-0000000ABCDE",
            auto_ignore=True,
            acting_user_id=admin.id,
        )

        assert result.id == cna.id

    async def test_changes_no_ticket_cve_or_other_cna(
        self,
        db_session: AsyncSession,
        cna_factory: Factory,
        cve_factory: Factory,
        ticket_factory: Factory,
        user_factory: Factory,
    ) -> None:
        """Flag: a change applies to later ingestions only; the `New` Ticket
        of a CVE of the CNA, the CVE, and another CNA keep every value."""
        cna = await cna_factory()
        other = await cna_factory()
        cve: CVE = await cve_factory(cna_id=cna.id)
        ticket: Ticket = await ticket_factory(
            status=TicketStatus.NEW.value, cve_id=cve.id
        )
        admin = await user_factory()

        with StatementRecorder(db_session) as recorder:
            await set_cna_auto_ignore(
                db_session,
                org_id=str(cna.org_id),
                auto_ignore=True,
                acting_user_id=admin.id,
            )

        assert sorted(" ".join(s.split()[:3]) for s in recorder.writes()) == [
            "INSERT INTO cna_audit_event",
            "UPDATE cna SET",
        ]
        assert (
            await db_session.scalar(select(Ticket.status).where(Ticket.id == ticket.id))
            == "New"
        )
        assert (
            await db_session.scalar(
                select(TicketAuditEvent.id).where(
                    TicketAuditEvent.ticket_id == ticket.id
                )
            )
            is None
        )
        assert (await _stored(db_session, other.id))[0] is False

    @pytest.mark.parametrize(
        "org_id",
        [
            "000000000000400080000000000abcde",
            "{00000000-0000-4000-8000-0000000abcde}",
            " 00000000-0000-4000-8000-0000000abcde",
            "example",
            "",
        ],
    )
    async def test_malformed_org_id_raises_not_found_before_any_query(
        self,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
        org_id: str,
    ) -> None:
        """The malformed locator also precedes the `auto_ignore` guard."""
        execute = AsyncMock(side_effect=AssertionError("no query expected"))
        monkeypatch.setattr(db_session, "execute", execute)

        with pytest.raises(CNANotFoundError):
            await set_cna_auto_ignore(
                db_session,
                org_id=org_id,
                auto_ignore="yes",  # type: ignore[arg-type]
                acting_user_id=uuid.uuid4(),
            )

        execute.assert_not_awaited()

    @pytest.mark.parametrize("value", [None, 1, 0, "true", "false"])
    async def test_non_bool_auto_ignore_raises_before_any_query(
        self,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
        value: object,
    ) -> None:
        execute = AsyncMock(side_effect=AssertionError("no query expected"))
        monkeypatch.setattr(db_session, "execute", execute)

        with pytest.raises(ValueError, match="auto_ignore must be a bool"):
            await set_cna_auto_ignore(
                db_session,
                org_id=str(uuid.uuid4()),
                auto_ignore=value,  # type: ignore[arg-type]
                acting_user_id=uuid.uuid4(),
            )

        execute.assert_not_awaited()

    async def test_unknown_org_id_raises_not_found(
        self, db_session: AsyncSession
    ) -> None:
        with pytest.raises(CNANotFoundError):
            await set_cna_auto_ignore(
                db_session,
                org_id=str(uuid.uuid4()),
                auto_ignore=True,
                acting_user_id=uuid.uuid4(),
            )

    @pytest.mark.parametrize("failure", ["audit", "flush"])
    async def test_event_failure_rolls_back_the_change(
        self,
        db_session: AsyncSession,
        cna_factory: Factory,
        user_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        failure: str,
    ) -> None:
        """audit-trail-infrastructure.md, Atomicity: the failure propagates
        and the caller's rollback leaves neither the flag nor the event."""
        cna = await cna_factory(updated_at=STALE)
        admin = await user_factory()
        cna_id, org_id, admin_id = cna.id, str(cna.org_id), admin.id
        original_flush = db_session.flush
        reached = False

        async def failing_log(*args: Any, **kwargs: Any) -> None:
            nonlocal reached
            reached = True
            raise RuntimeError("injected audit failure")

        async def failing_flush(*args: Any, **kwargs: Any) -> None:
            nonlocal reached
            if any(isinstance(o, CNAAuditEvent) for o in db_session.new):
                reached = True
                raise RuntimeError("injected flush failure")
            await original_flush(*args, **kwargs)

        async with rollback_test_scope(db_session):
            if failure == "audit":
                monkeypatch.setattr(CNAAuditLog, "log_event", failing_log)
            else:
                monkeypatch.setattr(db_session, "flush", failing_flush)
            with pytest.raises(RuntimeError, match="injected"):
                await set_cna_auto_ignore(
                    db_session, org_id=org_id, auto_ignore=True, acting_user_id=admin_id
                )
        monkeypatch.undo()

        assert reached
        assert await _stored(db_session, cna_id) == (False, STALE)
        assert await _events(db_session, cna_id) == []

    async def test_never_commits_or_rolls_back(
        self,
        db_session: AsyncSession,
        cna_factory: Factory,
        user_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cna = await cna_factory()
        admin = await user_factory()
        forbidden = AsyncMock(side_effect=AssertionError("no transaction end"))
        monkeypatch.setattr(db_session, "commit", forbidden)
        monkeypatch.setattr(db_session, "rollback", forbidden)

        await set_cna_auto_ignore(
            db_session,
            org_id=str(cna.org_id),
            auto_ignore=True,
            acting_user_id=admin.id,
        )

        forbidden.assert_not_awaited()


# ---------------------------------------------------------------------------
# list_cna_audit_events() (cna.md, `list_cna_audit_events()`; List CNA Audit
# Events)
# ---------------------------------------------------------------------------


async def _event(
    db: AsyncSession,
    cna: CNA,
    user: User | None,
    event_type: CNAAuditEventType = ENABLED,
    *,
    name: str | None = "Example",
    created_at: datetime | None = None,
) -> uuid.UUID:
    """One event row written directly, bypassing `log_event()`, so that a
    test controls `created_at` (and can write a system row)."""
    event = CNAAuditEvent(
        cna_id=cna.id,
        user_id=user.id if user is not None else None,
        event_type=event_type.value,
        detail={"cna_name": name},
    )
    if created_at is not None:
        event.created_at = created_at
    db.add(event)
    await db.flush()
    return event.id


async def _list(db: AsyncSession, **overrides: Any) -> Any:
    values: dict[str, Any] = {
        "event_type": None,
        "cna": None,
        "actor": None,
        "from_date": None,
        "to_date": None,
        "page": 1,
        "per_page": 20,
        **overrides,
    }
    return await list_cna_audit_events(db, **values)


@pytest.mark.integration
class TestListCnaAuditEvents:
    async def test_projects_current_references_newest_first(
        self,
        db_session: AsyncSession,
        cna_factory: Factory,
        user_factory: Factory,
    ) -> None:
        """`cna` is the current reference of the CNA and `actor` the current
        user reference; `detail` keeps the event-time name."""
        cna = await cna_factory(short_name="example")
        admin = await user_factory(full_name="Fictional Admin")
        first = await _event(db_session, cna, admin, name="example")
        second = await _event(db_session, cna, admin, DISABLED, name="example")
        await db_session.execute(
            update(CNA)
            .where(CNA.id == cna.id)
            .values(organization_name="Example Corporation")
        )
        await db_session.execute(
            update(User).where(User.id == admin.id).values(active=False, bot=True)
        )

        with StatementRecorder(db_session) as recorder:
            result = await _list(db_session, cna=cna.org_id)

        assert len(recorder.statements) == 1
        assert (result.total, result.page, result.per_page) == (2, 1, 20)
        assert [item.id for item in result.items] == [second, first]
        newest = result.items[0]
        assert newest.event_type == "auto_ignore_disabled"
        assert newest.cna == CNASummaryProjection(
            org_id=cna.org_id, name="Example Corporation"
        )
        assert newest.detail == {"cna_name": "example"}
        assert newest.actor == CNAAuditEventActor(
            id=admin.id,
            username=admin.username,
            full_name="Fictional Admin",
            active=False,
            bot=True,
            avatar_url=None,
        )
        assert newest.created_at is not None

    async def test_pagination_and_a_page_beyond_the_last(
        self,
        db_session: AsyncSession,
        cna_factory: Factory,
        user_factory: Factory,
    ) -> None:
        cna = await cna_factory()
        admin = await user_factory()
        ids = [await _event(db_session, cna, admin) for _ in range(3)]

        first = await _list(db_session, cna=cna.org_id, per_page=2)
        second = await _list(db_session, cna=cna.org_id, per_page=2, page=2)
        beyond = await _list(db_session, cna=cna.org_id, per_page=2, page=3)

        assert [item.id for item in first.items] == [ids[2], ids[1]]
        assert [item.id for item in second.items] == [ids[0]]
        assert beyond.items == ()
        assert (first.total, second.total, beyond.total) == (3, 3, 3)

    @pytest.mark.parametrize(
        ("event_type", "expected"),
        [
            (["auto_ignore_enabled"], ["enabled"]),
            (["auto_ignore_disabled", "auto_ignore_enabled"], ["disabled", "enabled"]),
            (["auto_ignore_enabled", "unknown"], ["enabled"]),
            (["unknown"], []),
            ([], []),
            (None, ["disabled", "enabled"]),
        ],
    )
    async def test_event_type_filter(
        self,
        db_session: AsyncSession,
        cna_factory: Factory,
        user_factory: Factory,
        event_type: list[str] | None,
        expected: list[str],
    ) -> None:
        """Valid values combine with OR; a supplied filter without a valid
        value matches nothing (`docs/api-spec.md`, Enum Filter Validation)."""
        cna = await cna_factory()
        admin = await user_factory()
        ids = {
            "enabled": await _event(db_session, cna, admin, ENABLED),
            "disabled": await _event(db_session, cna, admin, DISABLED),
        }

        result = await _list(db_session, cna=cna.org_id, event_type=event_type)

        assert [item.id for item in result.items] == [ids[k] for k in expected]
        assert result.total == len(expected)

    async def test_without_filters_every_cna_is_listed(
        self,
        db_session: AsyncSession,
        cna_factory: Factory,
        user_factory: Factory,
    ) -> None:
        """The rolled-back `db_session` holds no other CNA audit event."""
        cna = await cna_factory()
        other = await cna_factory()
        admin = await user_factory()
        first = await _event(db_session, cna, admin)
        second = await _event(db_session, other, admin)

        result = await _list(db_session)

        assert [item.id for item in result.items] == [second, first]
        assert [item.cna.org_id for item in result.items] == [other.org_id, cna.org_id]
        assert result.total == 2

    async def test_cna_filter_and_an_unknown_cna(
        self,
        db_session: AsyncSession,
        cna_factory: Factory,
        user_factory: Factory,
    ) -> None:
        cna = await cna_factory()
        other = await cna_factory()
        admin = await user_factory()
        mine = await _event(db_session, cna, admin)
        await _event(db_session, other, admin)

        selected = await _list(db_session, cna=cna.org_id)
        unknown = await _list(db_session, cna=uuid.uuid4())

        assert [item.id for item in selected.items] == [mine]
        assert (unknown.items, unknown.total) == ((), 0)

    async def test_actor_filter(
        self,
        db_session: AsyncSession,
        cna_factory: Factory,
        user_factory: Factory,
    ) -> None:
        """`BaseAuditLog.filter_by_actor()`: UUID or username; `system`
        matches the events without an actor, which `log_event()` never
        writes; an unknown actor yields an empty page."""
        cna = await cna_factory()
        admin = await user_factory()
        other = await user_factory()
        mine = await _event(db_session, cna, admin)
        theirs = await _event(db_session, cna, other)

        by_name = await _list(db_session, cna=cna.org_id, actor=admin.username)
        by_id = await _list(db_session, cna=cna.org_id, actor=str(other.id))
        system = await _list(db_session, cna=cna.org_id, actor="system")
        unknown = await _list(db_session, cna=cna.org_id, actor="nobody")

        assert [item.id for item in by_name.items] == [mine]
        assert [item.id for item in by_id.items] == [theirs]
        assert (system.total, unknown.total) == (0, 0)

    async def test_inclusive_date_filters(
        self,
        db_session: AsyncSession,
        cna_factory: Factory,
        user_factory: Factory,
    ) -> None:
        cna = await cna_factory()
        admin = await user_factory()
        early = await _event(
            db_session, cna, admin, created_at=datetime(2026, 1, 1, tzinfo=UTC)
        )
        middle = await _event(
            db_session, cna, admin, created_at=datetime(2026, 2, 1, 12, tzinfo=UTC)
        )
        late = await _event(
            db_session, cna, admin, created_at=datetime(2026, 3, 1, tzinfo=UTC)
        )

        from_middle = await _list(
            db_session, cna=cna.org_id, from_date=date(2026, 2, 1)
        )
        to_middle = await _list(db_session, cna=cna.org_id, to_date=date(2026, 2, 1))
        exact = await _list(
            db_session,
            cna=cna.org_id,
            from_date=datetime(2026, 2, 1, 12, tzinfo=UTC),
            to_date=datetime(2026, 2, 1, 12, tzinfo=UTC),
        )

        assert {item.id for item in from_middle.items} == {middle, late}
        assert {item.id for item in to_middle.items} == {early, middle}
        assert [item.id for item in exact.items] == [middle]

    async def test_filters_combine_with_and(
        self,
        db_session: AsyncSession,
        cna_factory: Factory,
        user_factory: Factory,
    ) -> None:
        cna = await cna_factory()
        admin = await user_factory()
        other = await user_factory()
        match = await _event(db_session, cna, admin, DISABLED)
        await _event(db_session, cna, admin, ENABLED)
        await _event(db_session, cna, other, DISABLED)

        result = await _list(
            db_session,
            cna=cna.org_id,
            actor=admin.username,
            event_type=["auto_ignore_disabled"],
        )

        assert [item.id for item in result.items] == [match]

    @pytest.mark.parametrize(("page", "per_page"), [(0, 20), (1, 0), (1, 101)], ids=str)
    async def test_invalid_pagination_raises_before_any_query(
        self,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
        page: int,
        per_page: int,
    ) -> None:
        execute = AsyncMock(side_effect=AssertionError("no query expected"))
        monkeypatch.setattr(db_session, "execute", execute)

        with pytest.raises(ValueError, match="page"):
            await _list(db_session, page=page, per_page=per_page)

        execute.assert_not_awaited()
