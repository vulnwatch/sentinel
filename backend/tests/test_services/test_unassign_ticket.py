"""Single-session service integration tests for `unassign_ticket()`
(backend/app/services/ticket_service.py).

Owning specifications:

- docs/features/tickets/ticket-service.md (Caller category and Ticket
  accessibility; Operability guard; Concurrency control;
  `unassign_ticket`; Architectural Test Requirement 21, single-session
  part).
- docs/features/tickets/tickets.md (Self-Unassignment; Architectural
  Invariant).
- docs/features/tickets/ticket-audit-log.md (Event Type Contract:
  `assignment`; Canonical Mutation and No-Event Matrix: Self-unassignment;
  Cross-Event Ordering, Locking, and Rollback; Testing Requirements 1-7).
- docs/conventions.md (Cross-Domain Root Lock Order: a path that only
  clears the caller's own assignment acquires no User root).
- docs/features/platform/testing-strategy.md (Tier Responsibility and
  Proportionality; Service Functions; Ticket Accessibility).

The independent-session tests (Ticket lock serialization, the absence of a
User lock, the races with a reassignment and with the real deactivation,
and the locked-current accessibility races) live in
`tests/test_services/test_unassign_ticket_atomicity.py`.

Expected values are transcribed from the specifications, never computed
with the module under test.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from typing import Any

import pytest
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import Role, Scope, TicketAuditEventType, TicketStatus
from app.core.exceptions import TicketNotFoundError, TicketNotMutableError
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.user import User
from app.services import ticket_service
from app.services.ticket_audit_log import TicketAuditLog
from app.services.ticket_convergence_registry import (
    pending_ticket_convergence_effects,
)
from app.services.ticket_service import AssigneeNotCallerError, unassign_ticket
from app.services.ticket_visibility import TicketCaller
from tests.support.database import rollback_test_scope
from tests.support.ticket_mutations import (
    EventRow,
    StatementRecorder,
    TicketFactory,
    TreeBuilder,
    VAUser,
    cveless,
    ticket_events_by_id,
    tree_for,
)

pytest_plugins = ["tests.support.ticket_mutation_fixtures"]
"""Provides the shared `va_user` and `tree` fixtures."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _self_unassignment(actor: User) -> EventRow:
    """The acting-user `assignment` event of a self-unassignment
    (ticket-audit-log.md, Event Type Contract): the caller's username as
    `old_value`, `new_value`, `comment`, and `detail` `NULL`."""
    return EventRow("assignment", actor.id, actor.username, None, None, None)


async def _unassign(
    db: AsyncSession,
    ticket_id: uuid.UUID,
    actor: User,
    *,
    scope: Scope = Scope.ALL,
) -> Ticket:
    """Call the service as the API handler does for `user_id: null`."""
    return await unassign_ticket(
        db,
        ticket_id=ticket_id,
        acting_user_id=actor.id,
        caller=TicketCaller.authenticated(actor.id, scope),
    )


async def _state(
    db: AsyncSession, ticket_id: uuid.UUID
) -> tuple[str, uuid.UUID | None] | None:
    """The persisted `(status, assignee_id)` of a Ticket, `None` if absent."""
    row = (
        await db.execute(
            select(Ticket.status, Ticket.assignee_id).where(Ticket.id == ticket_id)
        )
    ).one_or_none()
    return (row.status, row.assignee_id) if row is not None else None


class _Spy:
    """Wraps an async `ticket_service` attribute (the name imported from
    `ticket_mutations`), recording each call."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, name: str) -> None:
        self.calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        original = getattr(ticket_service, name)

        async def _wrapper(*args: Any, **kwargs: Any) -> Any:
            self.calls.append((args, kwargs))
            return await original(*args, **kwargs)

        monkeypatch.setattr(ticket_service, name, _wrapper)


async def _assert_no_effect(
    db: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    *,
    ticket_id: uuid.UUID,
    actor: User,
    error_type: type[Exception] | None,
    scope: Scope = Scope.ALL,
) -> None:
    """Call the service and assert the zero-side-effect contract of a
    rejected call (`error_type`) or of the idempotent no-op (`None`): no
    write, no reconciliation or auto-assignment, no registered convergence
    effect, the Ticket unchanged, and no new event."""
    reconcile = _Spy(monkeypatch, "reconcile_ticket_status")
    assign = _Spy(monkeypatch, "auto_assign_actor")
    before = await _state(db, ticket_id)
    events = await ticket_events_by_id(db, ticket_id)

    with StatementRecorder(db) as recorder:
        if error_type is None:
            result = await _unassign(db, ticket_id, actor, scope=scope)
            assert result.id == ticket_id
        else:
            with pytest.raises(error_type):
                await _unassign(db, ticket_id, actor, scope=scope)

    assert recorder.writes() == []
    assert (reconcile.calls, assign.calls) == ([], [])
    assert pending_ticket_convergence_effects(db) == ()
    assert await _state(db, ticket_id) == before
    assert await ticket_events_by_id(db, ticket_id) == events


# ---------------------------------------------------------------------------
# Effective self-unassignment
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestSelfUnassignment:
    @pytest.mark.parametrize(
        ("current", "gates"),
        [
            # Gates met above the current status: a reconciliation would
            # promote the Ticket, so an unchanged status proves none ran.
            pytest.param(TicketStatus.ANALYSIS, TicketStatus.ANALYZED, id="analysis"),
            pytest.param(TicketStatus.ANALYZED, TicketStatus.RESOLVED, id="analyzed"),
            pytest.param(TicketStatus.RESOLVED, TicketStatus.ANALYSIS, id="resolved"),
        ],
    )
    async def test_caller_clears_their_own_assignment_and_keeps_the_status(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        current: TicketStatus,
        gates: TicketStatus,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=current, assignee_id=actor.id)
        await tree_for(gates, ticket, tree)
        reconcile = _Spy(monkeypatch, "reconcile_ticket_status")
        assign = _Spy(monkeypatch, "auto_assign_actor")

        result = await _unassign(db_session, ticket.id, actor)

        assert result.id == ticket.id
        assert (result.status, result.assignee_id) == (current, None)
        assert await _state(db_session, ticket.id) == (current, None)
        assert await ticket_events_by_id(db_session, ticket.id) == [
            _self_unassignment(actor)
        ]
        assert (reconcile.calls, assign.calls) == ([], [])
        assert pending_ticket_convergence_effects(db_session) == ()

    async def test_anomalous_new_assignment_to_the_caller_is_cleared_in_new(
        self, db_session: AsyncSession, ticket_factory: TicketFactory, va_user: VAUser
    ) -> None:
        """Every assigning path promotes `New` to `Analysis`; an anomalous
        `New` assignment to the caller is still cleared by steps 6-8 without
        a status change (ticket-service.md, `unassign_ticket`)."""
        actor = await va_user()
        ticket = await cveless(
            ticket_factory, status=TicketStatus.NEW, assignee_id=actor.id
        )

        await _unassign(db_session, ticket.id, actor)

        assert await _state(db_session, ticket.id) == (TicketStatus.NEW, None)
        assert await ticket_events_by_id(db_session, ticket.id) == [
            _self_unassignment(actor)
        ]

    async def test_event_records_the_event_time_username(
        self, db_session: AsyncSession, ticket_factory: TicketFactory, va_user: VAUser
    ) -> None:
        """`old_value` is the username observed under the Ticket lock, not a
        stale in-memory value of the caller."""
        actor = await va_user()
        ticket = await cveless(ticket_factory, assignee_id=actor.id)
        renamed = f"renamed.va.{uuid.uuid4().hex[:8]}"
        # A Core UPDATE leaves the identity-map copy of the caller stale.
        await db_session.execute(
            update(User)
            .where(User.id == actor.id)
            .values(username=renamed)
            .execution_options(synchronize_session=False)
        )
        assert actor.username != renamed

        await _unassign(db_session, ticket.id, actor)

        [event] = await ticket_events_by_id(db_session, ticket.id)
        assert event.old_value == renamed


# ---------------------------------------------------------------------------
# Idempotency (Q5)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestIdempotency:
    @pytest.mark.parametrize(
        "status",
        [TicketStatus.NEW, TicketStatus.ANALYSIS, TicketStatus.RESOLVED],
    )
    async def test_ticket_without_an_assignee_is_a_no_op(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
    ) -> None:
        """A no-op is not a modifying operation: it neither auto-assigns the
        caller nor reconciles, even with gates met above the status."""
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=status)
        await tree_for(TicketStatus.ANALYZED, ticket, tree)

        await _assert_no_effect(
            db_session, monkeypatch, ticket_id=ticket.id, actor=actor, error_type=None
        )

    async def test_repeated_self_unassignment_creates_one_event(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(ticket_factory, assignee_id=actor.id)
        await _unassign(db_session, ticket.id, actor)

        await _assert_no_effect(
            db_session, monkeypatch, ticket_id=ticket.id, actor=actor, error_type=None
        )
        assert await ticket_events_by_id(db_session, ticket.id) == [
            _self_unassignment(actor)
        ]


# ---------------------------------------------------------------------------
# Guard precedence with zero side effects
# ---------------------------------------------------------------------------


ASSIGNEES = ["none", "other", "caller"]
"""The locked-current assignee: absent, another active VA, or the caller."""


async def _assignee_id(kind: str, actor: User, va_user: VAUser) -> uuid.UUID | None:
    if kind == "none":
        return None
    if kind == "caller":
        return actor.id
    return (await va_user()).id


@pytest.mark.integration
class TestGuardPrecedence:
    @pytest.mark.parametrize(
        "status", [TicketStatus.ANALYSIS, TicketStatus.ANALYZED, TicketStatus.RESOLVED]
    )
    async def test_another_assignee_raises_not_caller(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
    ) -> None:
        actor = await va_user()
        other = await va_user()
        ticket = await cveless(ticket_factory, status=status, assignee_id=other.id)

        await _assert_no_effect(
            db_session,
            monkeypatch,
            ticket_id=ticket.id,
            actor=actor,
            error_type=AssigneeNotCallerError,
        )
        assert await _state(db_session, ticket.id) == (status, other.id)

    async def test_missing_ticket_is_not_found(
        self,
        db_session: AsyncSession,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        actor = await va_user()

        await _assert_no_effect(
            db_session,
            monkeypatch,
            ticket_id=uuid.uuid7(),
            actor=actor,
            error_type=TicketNotFoundError,
        )

    @pytest.mark.parametrize(
        ("status", "assignee"),
        [
            *[(TicketStatus.ANALYSIS, kind) for kind in ASSIGNEES],
            (TicketStatus.IGNORED, "caller"),
        ],
    )
    async def test_inaccessible_ticket_is_not_found_before_any_other_decision(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
        assignee: str,
    ) -> None:
        """A `non_confidential`-scope caller without a grant or maintainership
        cannot see a confidential Ticket: `TicketNotFoundError` precedes
        operability, the no-op, and both assignee results."""
        actor = await va_user(roles=(Role.RESTRICTED_ANALYST,))
        ticket = await cveless(
            ticket_factory,
            status=status,
            is_confidential=True,
            assignee_id=await _assignee_id(assignee, actor, va_user),
        )

        await _assert_no_effect(
            db_session,
            monkeypatch,
            ticket_id=ticket.id,
            actor=actor,
            error_type=TicketNotFoundError,
            scope=Scope.NON_CONFIDENTIAL,
        )

    @pytest.mark.parametrize("assignee", ASSIGNEES)
    @pytest.mark.parametrize("status", [TicketStatus.IGNORED, TicketStatus.DUPLICATED])
    async def test_manual_zone_is_not_mutable_before_any_assignee_result(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
        assignee: str,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(
            ticket_factory,
            status=status,
            assignee_id=await _assignee_id(assignee, actor, va_user),
        )

        await _assert_no_effect(
            db_session,
            monkeypatch,
            ticket_id=ticket.id,
            actor=actor,
            error_type=TicketNotMutableError,
        )

    async def test_caller_mismatch_raises_before_any_statement(
        self, db_session: AsyncSession, ticket_factory: TicketFactory, va_user: VAUser
    ) -> None:
        actor = await va_user()
        other = await va_user()
        ticket = await cveless(ticket_factory, assignee_id=actor.id)

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ValueError, match="acting user"),
        ):
            await unassign_ticket(
                db_session,
                ticket_id=ticket.id,
                acting_user_id=actor.id,
                caller=TicketCaller.authenticated(other.id, Scope.ALL),
            )

        assert recorder.statements == []
        assert await _state(db_session, ticket.id) == (TicketStatus.ANALYSIS, actor.id)
        assert await ticket_events_by_id(db_session, ticket.id) == []


# ---------------------------------------------------------------------------
# Locked-current accessibility (single session)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestAccessibility:
    async def test_explicit_grant_holder_reaches_the_assignee_check(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_access_grant_factory: Callable[..., Awaitable[TicketAccessGrant]],
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A grant makes the confidential Ticket accessible, so the caller
        gets the assignee result rather than `TicketNotFoundError`."""
        actor = await va_user(roles=(Role.RESTRICTED_ANALYST,))
        other = await va_user()
        ticket = await cveless(
            ticket_factory, is_confidential=True, assignee_id=other.id
        )
        await ticket_access_grant_factory(ticket_id=ticket.id, user_id=actor.id)

        await _assert_no_effect(
            db_session,
            monkeypatch,
            ticket_id=ticket.id,
            actor=actor,
            error_type=AssigneeNotCallerError,
            scope=Scope.NON_CONFIDENTIAL,
        )


# ---------------------------------------------------------------------------
# Lock order and the unlocked username observation
# ---------------------------------------------------------------------------


def _bound(params: Any) -> list[Any]:
    """The bound values of one recorded statement."""
    return list(params.values() if isinstance(params, dict) else params)


@pytest.mark.integration
class TestLockOrder:
    async def test_ticket_update_is_the_only_lock_and_precedes_one_username_read(
        self, db_session: AsyncSession, ticket_factory: TicketFactory, va_user: VAUser
    ) -> None:
        """The Ticket `FOR UPDATE` is the first statement and the only row
        lock; no User root, role load, or audit-history read occurs; the one
        User read under the Ticket lock is the unlocked username of the
        caller."""
        actor = await va_user()
        ticket = await cveless(ticket_factory, assignee_id=actor.id)

        with StatementRecorder(db_session) as recorder:
            await _unassign(db_session, ticket.id, actor)

        statements = recorder.statements
        assert "FROM ticket" in statements[0]
        assert statements[0].rstrip().endswith("FOR UPDATE")
        assert recorder.row_locks() == [statements[0]]
        user_reads = [i for i, s in enumerate(statements) if 'FROM "user"' in s]
        assert len(user_reads) == 1
        assert _bound(recorder.parameters[user_reads[0]]) == [actor.id]
        assert recorder.selects_from("user_role") == []
        assert recorder.selects_from("ticket_audit_event") == []
        assert not any('"user"' in w for w in recorder.writes())


# ---------------------------------------------------------------------------
# Whole-operation rollback (audit Testing Requirement 7) and no commit
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRollback:
    async def test_audit_failure_rolls_back_the_clear_and_the_event(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        actor = await va_user()
        actor_id = actor.id  # The rollback expires the instance.
        ticket = await cveless(ticket_factory, assignee_id=actor_id)

        async with rollback_test_scope(db_session):

            async def failing_log(*args: Any, **kwargs: Any) -> None:
                assert kwargs["event_type"] is TicketAuditEventType.ASSIGNMENT
                raise RuntimeError("injected audit failure")

            monkeypatch.setattr(TicketAuditLog, "log_event", failing_log)
            with pytest.raises(RuntimeError, match="injected"):
                await _unassign(db_session, ticket.id, actor)
        monkeypatch.undo()

        await db_session.refresh(ticket)
        assert await _state(db_session, ticket.id) == (TicketStatus.ANALYSIS, actor_id)
        assert await ticket_events_by_id(db_session, ticket.id) == []

    async def test_never_commits(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(ticket_factory, assignee_id=actor.id)

        async def forbidden() -> None:
            raise AssertionError("unassign_ticket() must not commit")

        monkeypatch.setattr(db_session, "commit", forbidden)
        monkeypatch.setattr(db_session, "rollback", forbidden)

        await _unassign(db_session, ticket.id, actor)

        assert await _state(db_session, ticket.id) == (TicketStatus.ANALYSIS, None)
