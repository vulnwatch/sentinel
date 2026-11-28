"""Tests for `list_own_ticket_events()`
(backend/app/services/ticket_audit_log.py).

See docs/features/tickets/ticket-audit-log.md (API > List My Ticket
Events; Service Contract > `list_own_ticket_events()`; Testing
Requirement 32) for the contract under test, and the Ticket
Accessibility matrix in docs/features/platform/testing-strategy.md for
the visibility, atomicity, and independent-session race cases. The HTTP
contract is covered by tests/test_api/test_my_ticket_audit.py.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, date, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import delete, event, func, select, update
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import Role, Scope, TicketAuditEventType
from app.core.identifiers import format_ticket_id
from app.core.permissions import get_effective_scope
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_maintainer import TicketPackageMaintainer
from app.models.user import User
from app.models.user_role import UserRole
from app.services import user_service
from app.services.ticket_audit_log import (
    TicketEventActor,
    list_own_ticket_events,
)
from app.services.ticket_visibility import TicketCaller
from tests.support.callers import ROLELESS_CALLER

# No module-level `pytestmark`: every class carries its own explicit
# marker (mirrors tests/test_services/test_ticket_audit_log.py).

_Factory = Callable[..., Awaitable[Any]]
_BASE_TIME = datetime(2026, 3, 15, 10, 30, tzinfo=UTC)
_TRACK: dict[str, str] = {
    "track": "SUSE:SLE-15-SP6:Update",
    "package": "fictional-package",
}


def _sntl(ticket: Ticket) -> str:
    return format_ticket_id(ticket.sequence_id)


def _restricted(user: User) -> TicketCaller:
    return TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL)


def _all(user: User) -> TicketCaller:
    return TicketCaller.authenticated(user.id, Scope.ALL)


def _actor(user: User) -> TicketEventActor:
    return TicketEventActor(
        id=user.id,
        username=user.username,
        full_name=user.full_name,
        active=user.active,
        bot=user.bot,
        avatar_url=user.avatar_url,
    )


async def _ids(
    db: AsyncSession, caller: TicketCaller, **kwargs: Any
) -> list[uuid.UUID]:
    result = await list_own_ticket_events(db, caller=caller, **kwargs)
    return [item.id for item in result.items]


@pytest.mark.unit
class TestInputGuards:
    @pytest.mark.parametrize(
        ("page", "per_page"),
        [(0, 20), (-1, 20), (1, 0), (1, 101)],
    )
    async def test_out_of_range_pagination_raises_before_query(
        self, page: int, per_page: int
    ) -> None:
        db = AsyncMock(spec=AsyncSession)

        with pytest.raises(ValueError, match="page"):
            await list_own_ticket_events(
                db, caller=ROLELESS_CALLER, page=page, per_page=per_page
            )

        db.execute.assert_not_awaited()

    async def test_database_error_propagates(self) -> None:
        db = AsyncMock(spec=AsyncSession)
        failure = OperationalError("SELECT 1", {}, Exception("connection lost"))
        db.execute.side_effect = failure

        with pytest.raises(OperationalError) as excinfo:
            await list_own_ticket_events(db, caller=ROLELESS_CALLER)

        assert excinfo.value is failure


@pytest.mark.integration
class TestProjection:
    async def test_returns_own_events_with_their_ticket_fields(
        self,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        cve_factory: _Factory,
        user_factory: _Factory,
        ticket_audit_event_factory: _Factory,
    ) -> None:
        user: User = await user_factory(full_name="Fictional Analyst")
        cve = await cve_factory(cve_id="CVE-2026-1234")
        with_cve: Ticket = await ticket_factory(cve_id=cve.id)
        without_cve: Ticket = await ticket_factory()
        older = await ticket_audit_event_factory(
            ticket_id=without_cve.id,
            event_type="reference_added",
            user_id=user.id,
            new_value="https://example.com/advisory",
            created_at=_BASE_TIME,
        )
        newer = await ticket_audit_event_factory(
            ticket_id=with_cve.id,
            event_type="track_status_changed",
            user_id=user.id,
            old_value="ANALYSIS",
            new_value="AFFECTED",
            detail=_TRACK,
            created_at=_BASE_TIME + timedelta(minutes=5),
        )

        result = await list_own_ticket_events(db_session, caller=_restricted(user))

        assert (result.total, result.page, result.per_page) == (2, 1, 20)
        first, second = result.items
        assert first.id == newer.id
        assert first.ticket_id == _sntl(with_cve)
        assert first.cve_id == "CVE-2026-1234"
        assert first.is_confidential is False
        assert first.event_type == "track_status_changed"
        assert (first.old_value, first.new_value) == ("ANALYSIS", "AFFECTED")
        assert first.comment is None
        assert first.detail == _TRACK
        assert first.created_at == _BASE_TIME + timedelta(minutes=5)
        assert first.actor == _actor(user)
        assert second.id == older.id
        assert second.ticket_id == _sntl(without_cve)
        assert second.cve_id is None
        assert second.new_value == "https://example.com/advisory"
        assert second.actor == _actor(user)
        assert str(with_cve.id) not in {first.ticket_id, second.ticket_id}

    async def test_ticket_fields_and_actor_are_current_state(
        self,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        cve_factory: _Factory,
        user_factory: _Factory,
        ticket_audit_event_factory: _Factory,
    ) -> None:
        """`cve_id`, `is_confidential`, and `actor` follow the current
        Ticket and User rows, not their state when the event was recorded."""
        user: User = await user_factory(username="fictional.before")
        ticket: Ticket = await ticket_factory()
        await ticket_audit_event_factory(ticket_id=ticket.id, user_id=user.id)
        cve = await cve_factory(cve_id="CVE-2026-5678")
        ticket.cve_id = cve.id
        ticket.is_confidential = True
        user.username = "fictional.after"
        user.full_name = None
        await db_session.flush()

        result = await list_own_ticket_events(db_session, caller=_all(user))

        (item,) = result.items
        assert item.cve_id == "CVE-2026-5678"
        assert item.is_confidential is True
        assert item.actor.username == "fictional.after"
        assert item.actor.full_name is None

    async def test_events_of_other_users_and_system_events_are_excluded(
        self,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        user_factory: _Factory,
        ticket_audit_event_factory: _Factory,
    ) -> None:
        """A system event of a workflow the caller initiated, such as the
        promotion after an assignment, is not the caller's event."""
        user: User = await user_factory()
        other: User = await user_factory()
        ticket: Ticket = await ticket_factory()
        own = await ticket_audit_event_factory(
            ticket_id=ticket.id,
            event_type="assignment",
            user_id=user.id,
            new_value=user.username,
            created_at=_BASE_TIME,
        )
        await ticket_audit_event_factory(
            ticket_id=ticket.id,
            event_type="status_change",
            old_value="New",
            new_value="Analysis",
            created_at=_BASE_TIME,
        )
        await ticket_audit_event_factory(
            ticket_id=ticket.id, event_type="assignment", user_id=other.id
        )

        result = await list_own_ticket_events(db_session, caller=_all(user))

        assert [item.id for item in result.items] == [own.id]
        assert result.total == 1

    async def test_caller_without_events_gets_an_empty_page(
        self,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        user_factory: _Factory,
        ticket_audit_event_factory: _Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        await ticket_audit_event_factory(ticket_id=ticket.id)
        await ticket_audit_event_factory(
            ticket_id=ticket.id, user_id=(await user_factory()).id
        )

        result = await list_own_ticket_events(
            db_session, caller=_all(await user_factory())
        )

        assert (result.items, result.total, result.page) == ((), 0, 1)

    async def test_read_creates_no_event_and_adds_nothing_to_the_session(
        self,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        user_factory: _Factory,
        ticket_audit_event_factory: _Factory,
    ) -> None:
        user: User = await user_factory()
        ticket: Ticket = await ticket_factory()
        await ticket_audit_event_factory(ticket_id=ticket.id, user_id=user.id)

        await list_own_ticket_events(db_session, caller=_all(user))

        assert not db_session.new
        assert not db_session.dirty
        count = await db_session.scalar(
            select(func.count())
            .select_from(TicketAuditEvent)
            .where(TicketAuditEvent.ticket_id == ticket.id)
        )
        assert count == 1

    async def test_read_is_one_statement(
        self,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        user_factory: _Factory,
        ticket_audit_event_factory: _Factory,
    ) -> None:
        """Candidate set, Ticket fields, actor, total, and page come from one
        statement, hence one PostgreSQL snapshot."""
        user: User = await user_factory()
        for _ in range(3):
            ticket = await ticket_factory()
            await ticket_audit_event_factory(ticket_id=ticket.id, user_id=user.id)
        statements: list[str] = []

        def _record(*args: Any) -> None:
            statements.append(args[2])

        sync_engine = db_session.get_bind().engine
        event.listen(sync_engine, "before_cursor_execute", _record)
        try:
            await list_own_ticket_events(
                db_session,
                caller=_restricted(user),
                event_types=[TicketAuditEventType.ASSIGNMENT],
                search="x",
                from_date=date(2020, 1, 1),
            )
        finally:
            event.remove(sync_engine, "before_cursor_execute", _record)

        assert len(statements) == 1
        (statement,) = statements
        for cte in ("filtered AS", "total AS", "page AS"):
            assert cte in statement
        assert '"user" AS actor_user' in statement

    async def test_actor_scope_can_use_the_inherited_user_id_index(
        self,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        user_factory: _Factory,
        ticket_audit_event_factory: _Factory,
    ) -> None:
        """docs/data-model.md (TicketAuditEvent, Indexes): the inherited
        `user_id` index serves the mandatory actor scope."""
        user: User = await user_factory()
        ticket: Ticket = await ticket_factory()
        await ticket_audit_event_factory(ticket_id=ticket.id, user_id=user.id)
        captured: list[tuple[str, Any]] = []

        def _record(*args: Any) -> None:
            captured.append((args[2], args[3]))

        sync_engine = db_session.get_bind().engine
        event.listen(sync_engine, "before_cursor_execute", _record)
        try:
            await list_own_ticket_events(db_session, caller=_all(user))
        finally:
            event.remove(sync_engine, "before_cursor_execute", _record)
        statement, parameters = captured[0]

        connection = await db_session.connection()
        await connection.exec_driver_sql("SET LOCAL enable_seqscan = off")
        plan = await connection.exec_driver_sql(f"EXPLAIN {statement}", parameters)

        assert "ix_ticket_audit_event_user_id" in "\n".join(
            row[0] for row in plan.all()
        )


@pytest.mark.integration
class TestPagination:
    async def test_equal_timestamps_are_ordered_by_id_desc_across_pages(
        self,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        user_factory: _Factory,
        ticket_audit_event_factory: _Factory,
    ) -> None:
        user: User = await user_factory()
        events = []
        for _ in range(5):
            ticket = await ticket_factory()
            events.append(
                await ticket_audit_event_factory(
                    ticket_id=ticket.id, user_id=user.id, created_at=_BASE_TIME
                )
            )
        expected = sorted((e.id for e in events), reverse=True)

        pages = [
            await _ids(db_session, _all(user), page=page, per_page=2)
            for page in (1, 2, 3)
        ]

        assert [len(page) for page in pages] == [2, 2, 1]
        assert [event_id for page in pages for event_id in page] == expected

    async def test_created_at_orders_before_id(
        self,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        user_factory: _Factory,
        ticket_audit_event_factory: _Factory,
    ) -> None:
        user: User = await user_factory()
        ticket: Ticket = await ticket_factory()
        # The later-created (higher UUIDv7) event carries the older timestamp.
        newest = await ticket_audit_event_factory(
            ticket_id=ticket.id,
            user_id=user.id,
            created_at=_BASE_TIME + timedelta(hours=1),
        )
        oldest = await ticket_audit_event_factory(
            ticket_id=ticket.id, user_id=user.id, created_at=_BASE_TIME
        )

        assert await _ids(db_session, _all(user)) == [newest.id, oldest.id]

    async def test_page_beyond_the_last_is_empty_with_the_total(
        self,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        user_factory: _Factory,
        ticket_audit_event_factory: _Factory,
    ) -> None:
        user: User = await user_factory()
        ticket: Ticket = await ticket_factory()
        for _ in range(3):
            await ticket_audit_event_factory(ticket_id=ticket.id, user_id=user.id)

        result = await list_own_ticket_events(
            db_session, caller=_all(user), page=3, per_page=2
        )

        assert result.items == ()
        assert (result.total, result.page, result.per_page) == (3, 3, 2)


@pytest.mark.integration
class TestFilters:
    async def test_event_type_filter_uses_or_semantics(
        self,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        user_factory: _Factory,
        ticket_audit_event_factory: _Factory,
    ) -> None:
        user: User = await user_factory()
        ticket: Ticket = await ticket_factory()
        status = await ticket_audit_event_factory(
            ticket_id=ticket.id, user_id=user.id, event_type="status_change"
        )
        assignment = await ticket_audit_event_factory(
            ticket_id=ticket.id, user_id=user.id, event_type="assignment"
        )
        await ticket_audit_event_factory(
            ticket_id=ticket.id, user_id=user.id, event_type="ticket_created"
        )

        ids = await _ids(
            db_session,
            _all(user),
            event_types=[
                TicketAuditEventType.STATUS_CHANGE,
                TicketAuditEventType.ASSIGNMENT,
            ],
        )

        assert set(ids) == {status.id, assignment.id}
        assert len(await _ids(db_session, _all(user), event_types=None)) == 3

    async def test_supplied_but_empty_event_type_filter_returns_empty_page(
        self,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        user_factory: _Factory,
        ticket_audit_event_factory: _Factory,
    ) -> None:
        user: User = await user_factory()
        ticket: Ticket = await ticket_factory()
        await ticket_audit_event_factory(ticket_id=ticket.id, user_id=user.id)

        result = await list_own_ticket_events(
            db_session, caller=_all(user), event_types=[]
        )

        assert (result.items, result.total) == ((), 0)

    @pytest.mark.parametrize("field", ["comment", "old_value", "new_value", "detail"])
    async def test_search_matches_each_declared_field_case_insensitively(
        self,
        field: str,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        user_factory: _Factory,
        ticket_audit_event_factory: _Factory,
    ) -> None:
        user: User = await user_factory()
        ticket: Ticket = await ticket_factory()
        text = "Fictional Linux"
        value: Any = {"product_name": text} if field == "detail" else text
        match = await ticket_audit_event_factory(
            ticket_id=ticket.id, user_id=user.id, **{field: value}
        )
        await ticket_audit_event_factory(
            ticket_id=ticket.id, user_id=user.id, **{field: None}
        )

        assert await _ids(db_session, _all(user), search="  fictional LINUX ") == [
            match.id
        ]

    @pytest.mark.parametrize("search", [None, "", "   \t "])
    async def test_absent_or_blank_search_applies_no_filter(
        self,
        search: str | None,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        user_factory: _Factory,
        ticket_audit_event_factory: _Factory,
    ) -> None:
        user: User = await user_factory()
        ticket: Ticket = await ticket_factory()
        await ticket_audit_event_factory(
            ticket_id=ticket.id, user_id=user.id, new_value="a"
        )
        await ticket_audit_event_factory(ticket_id=ticket.id, user_id=user.id)

        assert len(await _ids(db_session, _all(user), search=search)) == 2

    @pytest.mark.parametrize(
        ("literal", "decoy"),
        [("100%", "1000"), ("a_b", "axb"), ("C:\\tmp", "C:tmp")],
    )
    async def test_search_metacharacters_are_literal(
        self,
        literal: str,
        decoy: str,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        user_factory: _Factory,
        ticket_audit_event_factory: _Factory,
    ) -> None:
        user: User = await user_factory()
        ticket: Ticket = await ticket_factory()
        match = await ticket_audit_event_factory(
            ticket_id=ticket.id, user_id=user.id, new_value=literal
        )
        await ticket_audit_event_factory(
            ticket_id=ticket.id, user_id=user.id, new_value=decoy
        )

        assert await _ids(db_session, _all(user), search=literal) == [match.id]

    async def test_date_bounds_are_inclusive_utc(
        self,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        user_factory: _Factory,
        ticket_audit_event_factory: _Factory,
    ) -> None:
        user: User = await user_factory()
        ticket: Ticket = await ticket_factory()

        async def _at(moment: datetime) -> Any:
            return await ticket_audit_event_factory(
                ticket_id=ticket.id, user_id=user.id, created_at=moment
            )

        before = await _at(datetime(2026, 3, 14, 23, 59, 59, tzinfo=UTC))
        start = await _at(datetime(2026, 3, 15, 0, 0, tzinfo=UTC))
        end = await _at(datetime(2026, 3, 16, 23, 59, 59, 999999, tzinfo=UTC))
        after = await _at(datetime(2026, 3, 17, 0, 0, tzinfo=UTC))
        caller = _all(user)

        assert await _ids(
            db_session, caller, from_date=date(2026, 3, 15), to_date=date(2026, 3, 16)
        ) == [end.id, start.id]
        assert await _ids(db_session, caller, to_date=date(2026, 3, 14)) == [before.id]
        assert await _ids(
            db_session,
            caller,
            from_date=datetime.fromisoformat("2026-03-17T02:00:00+02:00"),
        ) == [after.id]

    async def test_different_filters_compose_with_and(
        self,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        user_factory: _Factory,
        ticket_audit_event_factory: _Factory,
    ) -> None:
        user: User = await user_factory()
        ticket: Ticket = await ticket_factory()
        base: dict[str, Any] = {
            "event_type": "status_change",
            "user_id": user.id,
            "new_value": "Analysis",
            "created_at": _BASE_TIME,
        }
        target = await ticket_audit_event_factory(ticket_id=ticket.id, **base)
        for overrides in (
            {"event_type": "assignment"},
            {"user_id": None},
            {"new_value": "Resolved"},
            {"created_at": _BASE_TIME - timedelta(days=30)},
        ):
            await ticket_audit_event_factory(
                ticket_id=ticket.id, **{**base, **overrides}
            )

        result = await list_own_ticket_events(
            db_session,
            caller=_all(user),
            event_types=[TicketAuditEventType.STATUS_CHANGE],
            search="analysis",
            from_date=date(2026, 3, 1),
            per_page=1,
        )

        # The decoys sort first by `id DESC`, so page 1 holds `target` only
        # when every filter applies before pagination.
        assert [item.id for item in result.items] == [target.id]
        assert result.total == 1


@pytest.mark.integration
class TestAccessibility:
    async def test_events_of_invisible_tickets_are_neither_listed_nor_counted(
        self,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        user_factory: _Factory,
        ticket_access_grant_factory: _Factory,
        ticket_audit_event_factory: _Factory,
    ) -> None:
        user: User = await user_factory()
        public: Ticket = await ticket_factory()
        granted: Ticket = await ticket_factory(is_confidential=True)
        hidden: Ticket = await ticket_factory(is_confidential=True)
        await ticket_access_grant_factory(ticket_id=granted.id, user_id=user.id)
        older = await ticket_audit_event_factory(
            ticket_id=public.id, user_id=user.id, created_at=_BASE_TIME
        )
        newer = await ticket_audit_event_factory(
            ticket_id=granted.id,
            user_id=user.id,
            created_at=_BASE_TIME + timedelta(minutes=1),
        )
        # The invisible event is the newest, so a page sliced before the
        # visibility predicate would start with it.
        await ticket_audit_event_factory(
            ticket_id=hidden.id,
            user_id=user.id,
            created_at=_BASE_TIME + timedelta(minutes=2),
        )
        caller = _restricted(user)

        restricted = await list_own_ticket_events(db_session, caller=caller)
        first = await list_own_ticket_events(db_session, caller=caller, per_page=1)
        second = await list_own_ticket_events(
            db_session, caller=caller, page=2, per_page=1
        )
        unrestricted = await list_own_ticket_events(db_session, caller=_all(user))

        assert [item.id for item in restricted.items] == [newer.id, older.id]
        assert restricted.total == 2
        assert ([item.id for item in first.items], first.total) == ([newer.id], 2)
        assert ([item.id for item in second.items], second.total) == ([older.id], 2)
        assert unrestricted.total == 3

    @pytest.mark.parametrize("branch", ["scope_all", "grant", "maintainer"])
    async def test_each_visibility_branch_lists_the_confidential_ticket(
        self,
        branch: str,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        user_factory: _Factory,
        ticket_access_grant_factory: _Factory,
        ticket_package_factory: _Factory,
        ticket_package_maintainer_factory: _Factory,
        ticket_audit_event_factory: _Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory(is_confidential=True)
        user: User = await user_factory()
        caller = _restricted(user)
        if branch == "scope_all":
            caller = _all(user)
        elif branch == "grant":
            await ticket_access_grant_factory(ticket_id=ticket.id, user_id=user.id)
        else:
            package = await ticket_package_factory(ticket_id=ticket.id)
            await ticket_package_maintainer_factory(
                ticket_package_id=package.id, user_id=user.id
            )
        await ticket_audit_event_factory(ticket_id=ticket.id, user_id=user.id)

        result = await list_own_ticket_events(db_session, caller=caller)

        assert result.total == 1
        assert result.items[0].is_confidential is True

    async def test_losing_and_regaining_the_last_visibility_path(
        self,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        user_factory: _Factory,
        ticket_package_factory: _Factory,
        ticket_package_maintainer_factory: _Factory,
        ticket_audit_event_factory: _Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory(is_confidential=True)
        user: User = await user_factory()
        package: TicketPackage = await ticket_package_factory(ticket_id=ticket.id)
        await ticket_package_maintainer_factory(
            ticket_package_id=package.id, user_id=user.id
        )
        own = await ticket_audit_event_factory(
            ticket_id=ticket.id, event_type="package_excluded", user_id=user.id
        )
        caller = _restricted(user)

        package.deleted_at = datetime.now(UTC)
        await db_session.flush()
        lost = await list_own_ticket_events(db_session, caller=caller)
        package.deleted_at = None
        await db_session.flush()
        regained = await list_own_ticket_events(db_session, caller=caller)

        assert (lost.items, lost.total) == ((), 0)
        assert [item.id for item in regained.items] == [own.id]
        assert regained.total == 1

    async def test_roleless_caller_lists_events_recorded_under_former_roles(
        self,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        user_factory: _Factory,
        ticket_audit_event_factory: _Factory,
    ) -> None:
        user: User = await user_factory()
        public: Ticket = await ticket_factory()
        confidential: Ticket = await ticket_factory(is_confidential=True)
        own = await ticket_audit_event_factory(
            ticket_id=public.id, event_type="assignment", user_id=user.id
        )
        await ticket_audit_event_factory(ticket_id=confidential.id, user_id=user.id)
        roles = await user_service.get_user_roles(db_session, user.id)
        caller = TicketCaller.authenticated(user.id, get_effective_scope(roles))

        result = await list_own_ticket_events(db_session, caller=caller)

        assert caller.scope is Scope.NON_CONFIDENTIAL
        assert [item.id for item in result.items] == [own.id]
        assert result.items[0].actor == _actor(user)

    async def test_several_visibility_paths_do_not_duplicate_events(
        self,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        user_factory: _Factory,
        ticket_access_grant_factory: _Factory,
        ticket_package_factory: _Factory,
        ticket_package_maintainer_factory: _Factory,
        ticket_audit_event_factory: _Factory,
    ) -> None:
        """A grant and two included maintained packages of one Ticket never
        multiply the caller's events or inflate the total."""
        ticket: Ticket = await ticket_factory(is_confidential=True)
        user: User = await user_factory()
        await ticket_access_grant_factory(ticket_id=ticket.id, user_id=user.id)
        for _ in range(2):
            package = await ticket_package_factory(ticket_id=ticket.id)
            await ticket_package_maintainer_factory(
                ticket_package_id=package.id, user_id=user.id
            )
            await ticket_package_maintainer_factory(ticket_package_id=package.id)
        for _ in range(4):
            await ticket_audit_event_factory(ticket_id=ticket.id, user_id=user.id)

        result = await list_own_ticket_events(db_session, caller=_restricted(user))

        assert result.total == 4
        assert len({item.id for item in result.items}) == 4
        assert len(result.items) == 4


# ---------------------------------------------------------------------------
# Independent-session races
# ---------------------------------------------------------------------------


class _CommittedWorld:
    """Commits fixture rows through an independent session and deletes
    them at teardown in FK-safe order (testing-strategy.md, Concurrency
    Testing: committed data is not rolled back by the fixture)."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.ticket_ids: list[uuid.UUID] = []
        self.user_ids: list[uuid.UUID] = []

    async def user(self, *, role: Role | None = None) -> User:
        n = len(self.user_ids) + 1
        user = User(
            username=f"fictional.ownrace{n}.{uuid.uuid4().hex[:8]}",
            email=f"ownrace{n}.{uuid.uuid4().hex[:8]}@example.com",
            password_hash="$2b$12$" + "a" * 53,
        )
        self.session.add(user)
        await self.session.flush()
        self.user_ids.append(user.id)
        if role is not None:
            self.session.add(UserRole(user_id=user.id, role=role.value))
        await self.session.commit()
        return user

    async def ticket(
        self, *, is_confidential: bool, actor: User, events: int = 2
    ) -> Ticket:
        ticket = Ticket(is_confidential=is_confidential)
        self.session.add(ticket)
        await self.session.flush()
        self.ticket_ids.append(ticket.id)
        for _ in range(events):
            self.session.add(
                TicketAuditEvent(
                    ticket_id=ticket.id, event_type="assignment", user_id=actor.id
                )
            )
        await self.session.commit()
        return ticket

    async def cleanup(self) -> None:
        await self.session.rollback()
        packages = select(TicketPackage.id).where(
            TicketPackage.ticket_id.in_(self.ticket_ids)
        )
        for statement in (
            delete(TicketAuditEvent).where(
                TicketAuditEvent.ticket_id.in_(self.ticket_ids)
            ),
            delete(TicketAccessGrant).where(
                TicketAccessGrant.ticket_id.in_(self.ticket_ids)
            ),
            delete(TicketPackageMaintainer).where(
                TicketPackageMaintainer.ticket_package_id.in_(packages)
            ),
            delete(TicketPackage).where(TicketPackage.ticket_id.in_(self.ticket_ids)),
            delete(Ticket).where(Ticket.id.in_(self.ticket_ids)),
            delete(UserRole).where(UserRole.user_id.in_(self.user_ids)),
            delete(User).where(User.id.in_(self.user_ids)),
        ):
            await self.session.execute(statement)
        await self.session.commit()


@pytest.fixture
async def committed_world(
    db_session_factory: Callable[[], Awaitable[AsyncSession]],
) -> AsyncIterator[_CommittedWorld]:
    world = _CommittedWorld(await db_session_factory())
    try:
        yield world
    finally:
        await world.cleanup()


async def _commit(session: AsyncSession, *statements: Any) -> None:
    for statement in statements:
        await session.execute(statement)
    await session.commit()


async def _resolve_caller(db: AsyncSession, user: User) -> TicketCaller:
    """Resolve the caller once, as the API dependency does at the start of
    the request (rbac.md, Principal to Caller Context)."""
    roles = await user_service.get_user_roles(db, user.id)
    return TicketCaller.authenticated(user.id, get_effective_scope(roles))


@pytest.mark.integration
class TestRaces:
    """Session R resolves the caller information, session W then commits a
    visibility change, and R performs the protected selection. The steps
    run in a fixed order on independent connections, so the interleaving
    is deterministic. An implementation that selected the caller's events
    from a visibility decision taken before the service call would return
    the now-invisible Ticket's events and fail these tests; a visibility
    decision split from the event selection inside the service is ruled
    out by `TestProjection.test_read_is_one_statement`."""

    async def test_confidentiality_set_after_the_caller_is_resolved(
        self,
        committed_world: _CommittedWorld,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        user = await committed_world.user()
        ticket = await committed_world.ticket(is_confidential=False, actor=user)
        reader = await db_session_factory()
        writer = await db_session_factory()

        caller = await _resolve_caller(reader, user)
        before = await list_own_ticket_events(reader, caller=caller)
        await _commit(
            writer,
            update(Ticket).where(Ticket.id == ticket.id).values(is_confidential=True),
        )
        after = await list_own_ticket_events(reader, caller=caller)

        assert (before.total, len(before.items)) == (2, 2)
        assert (after.total, after.items) == (0, ())

    async def test_grant_revoked_after_the_caller_is_resolved(
        self,
        committed_world: _CommittedWorld,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        user = await committed_world.user()
        granter = await committed_world.user()
        ticket = await committed_world.ticket(is_confidential=True, actor=user)
        committed_world.session.add(
            TicketAccessGrant(
                ticket_id=ticket.id, user_id=user.id, granted_by_id=granter.id
            )
        )
        await committed_world.session.commit()
        reader = await db_session_factory()
        writer = await db_session_factory()

        caller = await _resolve_caller(reader, user)
        await _commit(
            writer,
            delete(TicketAccessGrant).where(
                TicketAccessGrant.ticket_id == ticket.id,
                TicketAccessGrant.user_id == user.id,
            ),
        )
        result = await list_own_ticket_events(reader, caller=caller)

        assert (result.total, result.items) == (0, ())

    async def test_last_maintained_package_excluded_after_the_caller_is_resolved(
        self,
        committed_world: _CommittedWorld,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        user = await committed_world.user()
        ticket = await committed_world.ticket(is_confidential=True, actor=user)
        package = TicketPackage(ticket_id=ticket.id, package_name="fictional-own-pkg")
        committed_world.session.add(package)
        await committed_world.session.flush()
        committed_world.session.add(
            TicketPackageMaintainer(ticket_package_id=package.id, user_id=user.id)
        )
        await committed_world.session.commit()
        reader = await db_session_factory()
        writer = await db_session_factory()

        caller = await _resolve_caller(reader, user)
        await _commit(
            writer,
            update(TicketPackage)
            .where(TicketPackage.id == package.id)
            .values(deleted_at=datetime.now(UTC)),
        )
        result = await list_own_ticket_events(reader, caller=caller)

        assert (result.total, result.items) == (0, ())

    async def test_visibility_acquired_after_the_caller_is_resolved(
        self,
        committed_world: _CommittedWorld,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        user = await committed_world.user()
        granter = await committed_world.user()
        await committed_world.ticket(is_confidential=False, actor=user, events=1)
        ticket = await committed_world.ticket(
            is_confidential=True, actor=user, events=3
        )
        reader = await db_session_factory()
        writer = await db_session_factory()

        caller = await _resolve_caller(reader, user)
        before = await list_own_ticket_events(reader, caller=caller)
        writer.add(
            TicketAccessGrant(
                ticket_id=ticket.id, user_id=user.id, granted_by_id=granter.id
            )
        )
        await writer.commit()
        after = await list_own_ticket_events(reader, caller=caller, per_page=100)

        assert (before.total, len(before.items)) == (1, 1)
        assert (after.total, len(after.items)) == (4, 4)

    async def test_concurrent_role_change_does_not_alter_the_resolved_caller(
        self,
        committed_world: _CommittedWorld,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        """A committed role removal applies to the next resolution, not to
        the in-flight request (rbac.md, Principal to Caller Context)."""
        user = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        await committed_world.ticket(is_confidential=True, actor=user)
        reader = await db_session_factory()
        writer = await db_session_factory()

        in_flight = await _resolve_caller(reader, user)
        await _commit(writer, delete(UserRole).where(UserRole.user_id == user.id))
        result = await list_own_ticket_events(reader, caller=in_flight)
        next_request = await _resolve_caller(reader, user)
        later = await list_own_ticket_events(reader, caller=next_request)

        assert in_flight.scope is Scope.ALL
        assert result.total == 2
        assert next_request.scope is Scope.NON_CONFIDENTIAL
        assert later.total == 0
