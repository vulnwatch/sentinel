"""Single-session service integration tests for `ignore_ticket()`
(backend/app/services/ticket_service.py).

Owning specifications:

- docs/features/tickets/ticket-service.md (Transaction ownership; Caller
  category and Ticket accessibility; Operability guard, including the
  ordering constraint for `ignore_ticket`; `ignore_ticket`; Service
  Exceptions; Architectural Test Requirement 4 (`ignore_ticket()` path,
  in `tests/test_services/test_new_to_analysis_promotion.py`), 15
  (single-session part), and 24 (single-session part)).
- docs/features/tickets/tickets.md (Ignore Reason; Ignore Ticket).
- docs/features/tickets/tickets.md (Status Transitions, including the
  VA/non-VA note after the matrix; Auto-Assignment on Unassigned
  Tickets).
- docs/features/tickets/ticket-audit-log.md (Event Type Contract:
  `status_change`, `assignment`; `detail` JSONB Schema Contract:
  `status_change`; Canonical Mutation and No-Event Matrix: Ignore, mark
  duplicate, reopen, or revert duplicate; Cross-Event Ordering, Locking,
  and Rollback; Testing Requirements 1-7 and 30).
- docs/features/platform/testing-strategy.md (Tier Responsibility and
  Proportionality; Audit Trail Testing, What to Assert).

The independent-session tests (lock serialization, the winner/loser old
value of audit Testing Requirement 23, and the locked-current
accessibility races of Architectural Test Requirement 15) are owned by
`tests/test_services/test_manual_zone_entry_atomicity.py`; the
`cve_rejected` races with ingestion and the CVE lock-freedom of
Architectural Test Requirement 24 by
`tests/test_services/test_upsert_cve_atomicity.py`.

Not reachable, hence not tested: the converse self-loss case of
Architectural Test Requirement 15 (an authorized mutation that itself
removes the caller's last visibility path). The canonical predicate
(docs/features/identity/rbac.md, Scope and Confidential Ticket Visibility)
depends only on the Ticket's confidentiality, the caller's scope, explicit
grants, and included-package maintainership; `ignore_ticket()` changes
only the status and, through auto-assignment, `assignee_id`, so it cannot
remove any visibility path.

Expected values are transcribed from the specifications, never computed
with the module under test.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from typing import Any, cast

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    CveState,
    Role,
    Scope,
    TicketAuditEventType,
    TicketIgnoreReason,
    TicketStatus,
)
from app.core.exceptions import (
    InvalidTransitionError,
    TicketNotFoundError,
    TicketNotMutableError,
)
from app.models.cve import CVE
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.user import User
from app.services import ticket_service
from app.services.ticket_audit_log import TicketAuditLog
from app.services.ticket_convergence_registry import (
    pending_ticket_convergence_effects,
)
from app.services.ticket_service import TicketCVENotRejectedError, ignore_ticket
from app.services.ticket_visibility import TicketCaller
from tests.support.database import rollback_test_scope
from tests.support.ticket_mutations import (
    EventRow,
    StatementRecorder,
    TicketFactory,
    VAUser,
    status_event,
    ticket_events,
    ticket_events_by_id,
)

pytest_plugins = ["tests.support.ticket_mutation_fixtures"]
"""Provides the shared `va_user` fixture."""

PROMOTION = status_event(TicketStatus.NEW.value, TicketStatus.ANALYSIS.value)
"""The system `New -> Analysis` event of the auto-assignment."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


OTHER = TicketIgnoreReason.OTHER


def _ignored(
    actor: User, old: TicketStatus, reason: TicketIgnoreReason = OTHER
) -> EventRow:
    """The acting-user manual-zone entry (ticket-audit-log.md, Event Type
    Contract: `status_change` of a direct manual transition, `comment`
    `NULL` for every reason, `detail` the reason)."""
    return EventRow(
        "status_change",
        actor.id,
        old.value,
        TicketStatus.IGNORED.value,
        None,
        {"ignore_reason": reason.value},
    )


def _assignment(actor: User) -> EventRow:
    """The acting-user auto-assignment of an unassigned Ticket."""
    return EventRow("assignment", actor.id, None, actor.username, None, None)


async def _ignore(
    db: AsyncSession,
    ticket_id: uuid.UUID,
    actor: User,
    *,
    scope: Scope = Scope.ALL,
    reason: TicketIgnoreReason = OTHER,
) -> Ticket:
    """Call the service as an API handler would."""
    return await ignore_ticket(
        db,
        ticket_id=ticket_id,
        acting_user_id=actor.id,
        caller=TicketCaller.authenticated(actor.id, scope),
        reason=reason,
    )


async def _state(
    db: AsyncSession, ticket_id: uuid.UUID
) -> tuple[str, uuid.UUID | None, str | None] | None:
    """The persisted `(status, assignee_id, ignore_reason)` of a Ticket,
    `None` if absent."""
    row = (
        await db.execute(
            select(Ticket.status, Ticket.assignee_id, Ticket.ignore_reason).where(
                Ticket.id == ticket_id
            )
        )
    ).one_or_none()
    return (row.status, row.assignee_id, row.ignore_reason) if row is not None else None


class _Spy:
    """Wraps an async `ticket_service` attribute (the name imported from
    `ticket_mutations`), recording each call's arguments."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, name: str) -> None:
        self.calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        original = getattr(ticket_service, name)

        async def _wrapper(*args: Any, **kwargs: Any) -> Any:
            self.calls.append((args, kwargs))
            return await original(*args, **kwargs)

        monkeypatch.setattr(ticket_service, name, _wrapper)


async def _assert_rejected(
    db: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    error_type: type[Exception],
    *,
    ticket_id: uuid.UUID,
    actor: User,
    scope: Scope = Scope.ALL,
    reason: TicketIgnoreReason = OTHER,
) -> None:
    """Call the service and assert the zero-side-effect contract of a
    rejected call: the expected error, no write, no assignment, no
    reconciliation, no registered convergence effect, the Ticket
    unchanged, and no event."""
    assign = _Spy(monkeypatch, "auto_assign_actor")
    reconcile = _Spy(monkeypatch, "reconcile_ticket_status")
    before = await _state(db, ticket_id)

    with StatementRecorder(db) as recorder, pytest.raises(error_type):
        await _ignore(db, ticket_id, actor, scope=scope, reason=reason)

    assert recorder.writes() == []
    assert (assign.calls, reconcile.calls) == ([], [])
    assert pending_ticket_convergence_effects(db) == ()
    assert await _state(db, ticket_id) == before
    assert await ticket_events_by_id(db, ticket_id) == []


# ---------------------------------------------------------------------------
# Effective manual-zone entry
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestIgnore:
    async def test_va_actor_claims_an_unassigned_new_ticket_before_ignoring(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """tickets.md, Auto-Assignment on Unassigned Tickets: the audit
        trail records `assignment`, the system `New -> Analysis`, then the
        acting-user `Analysis -> Ignored`. The entry never reconciles,
        registers convergence, or reads audit history."""
        actor = await va_user()
        ticket = await ticket_factory(status=TicketStatus.NEW.value)
        reconcile = _Spy(monkeypatch, "reconcile_ticket_status")

        with StatementRecorder(db_session) as recorder:
            result = await _ignore(db_session, ticket.id, actor)

        assert result.id == ticket.id
        assert (result.status, result.assignee_id) == (TicketStatus.IGNORED, actor.id)
        assert await _state(db_session, ticket.id) == (
            TicketStatus.IGNORED,
            actor.id,
            OTHER,
        )
        assert await ticket_events(db_session, ticket) == [
            _assignment(actor),
            PROMOTION,
            _ignored(actor, TicketStatus.ANALYSIS),
        ]
        assert reconcile.calls == []
        assert pending_ticket_convergence_effects(db_session) == ()
        assert recorder.selects_from("ticket_audit_event") == []

    @pytest.mark.parametrize(
        ("active", "roles", "bot", "scope"),
        [
            pytest.param(
                True, (Role.VULNERABILITY_ANALYST,), True, Scope.ALL, id="bot-va"
            ),
            pytest.param(
                False, (Role.VULNERABILITY_ANALYST,), False, Scope.ALL, id="inactive-va"
            ),
        ],
    )
    async def test_ineligible_actor_ignores_a_new_ticket_directly(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        active: bool,
        roles: tuple[Role, ...],
        bot: bool,
        scope: Scope,
    ) -> None:
        """tickets.md, Status Transitions (note after the matrix): an actor
        that is not eligible to be the assignee (rbac.md, Business Rule 10)
        cannot be assigned and records the direct `New -> Ignored`; the
        Ticket stays unassigned."""
        actor = await va_user(active=active, roles=roles, bot=bot)
        ticket = await ticket_factory(status=TicketStatus.NEW.value)

        await _ignore(db_session, ticket.id, actor, scope=scope)

        assert await _state(db_session, ticket.id) == (
            TicketStatus.IGNORED,
            None,
            OTHER,
        )
        assert await ticket_events(db_session, ticket) == [
            _ignored(actor, TicketStatus.NEW)
        ]

    @pytest.mark.parametrize(
        "preassigned", [False, True], ids=["unassigned", "assigned"]
    )
    async def test_analysis_ticket_is_ignored_with_auto_assignment_only_if_unassigned(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        preassigned: bool,
    ) -> None:
        """An `Analysis` Ticket has no promotion; an already-assigned
        Ticket keeps its assignee and records no `assignment`
        (rbac.md, Business Rule 12: ignore applies only the auto-assignment
        of an unassigned Ticket)."""
        actor = await va_user()
        owner = await va_user()
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value,
            assignee_id=owner.id if preassigned else None,
        )

        await _ignore(db_session, ticket.id, actor)

        expected_assignee = owner.id if preassigned else actor.id
        claim = [] if preassigned else [_assignment(actor)]
        assert await _state(db_session, ticket.id) == (
            TicketStatus.IGNORED,
            expected_assignee,
            OTHER,
        )
        assert await ticket_events(db_session, ticket) == [
            *claim,
            _ignored(actor, TicketStatus.ANALYSIS),
        ]


# ---------------------------------------------------------------------------
# Ignore reason (ticket-service.md, Architectural Test Requirement 24;
# ticket-audit-log.md, Testing Requirement 30)
# ---------------------------------------------------------------------------

CVEFactory = Callable[..., Awaitable[CVE]]


@pytest.mark.integration
class TestReason:
    @pytest.mark.parametrize("reason", list(TicketIgnoreReason), ids=lambda r: r.value)
    @pytest.mark.parametrize(
        "source", [TicketStatus.NEW, TicketStatus.ANALYSIS], ids=lambda s: s.value
    )
    async def test_each_reason_is_stored_and_recorded_from_each_source(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_factory: CVEFactory,
        va_user: VAUser,
        reason: TicketIgnoreReason,
        source: TicketStatus,
    ) -> None:
        """The reason is written together with `Ignored` and recorded in the
        `detail` of the acting-user `status_change`, with `comment = NULL`
        also for `cve_rejected`; the optional `assignment` and system
        `New -> Analysis` keep `detail = NULL`. Every Ticket has a rejected
        CVE, so `cve_rejected` is admissible."""
        actor = await va_user()
        cve = await cve_factory(cve_state=CveState.REJECTED.value)
        ticket = await ticket_factory(status=source.value, cve_id=cve.id)

        result = await _ignore(db_session, ticket.id, actor, reason=reason)

        assert result.ignore_reason == reason
        assert await _state(db_session, ticket.id) == (
            TicketStatus.IGNORED,
            actor.id,
            reason,
        )
        promotion = [PROMOTION] if source is TicketStatus.NEW else []
        assert await ticket_events(db_session, ticket) == [
            _assignment(actor),
            *promotion,
            _ignored(actor, TicketStatus.ANALYSIS, reason),
        ]

    @pytest.mark.parametrize(
        "source", [TicketStatus.NEW, TicketStatus.ANALYSIS], ids=lambda s: s.value
    )
    @pytest.mark.parametrize(
        "cve_state", [None, CveState.PUBLISHED], ids=["cve-less", "published"]
    )
    async def test_cve_rejected_without_a_rejected_cve_is_rejected(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_factory: CVEFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        source: TicketStatus,
        cve_state: CveState | None,
    ) -> None:
        """A CVE-less Ticket and a `PUBLISHED` CVE raise
        `TicketCVENotRejectedError` with no assignment, status change, or
        event: an unassigned `New` Ticket and an eligible actor make an
        assignment before the check observable, and the `New` Ticket stays
        `New`."""
        actor = await va_user()
        cve = None if cve_state is None else await cve_factory(cve_state=cve_state)
        ticket = await ticket_factory(
            status=source.value, cve_id=cve.id if cve is not None else None
        )

        await _assert_rejected(
            db_session,
            monkeypatch,
            TicketCVENotRejectedError,
            ticket_id=ticket.id,
            actor=actor,
            reason=TicketIgnoreReason.CVE_REJECTED,
        )
        assert await _state(db_session, ticket.id) == (source, None, None)

    async def test_cve_state_is_read_after_the_lock_without_a_cve_lock(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_factory: CVEFactory,
        va_user: VAUser,
    ) -> None:
        """ticket-service.md, `ignore_ticket` step 6: one column statement
        on `cve` issued after the Ticket `FOR UPDATE`, which takes no row
        lock; the root locks stay the acting User and the Ticket."""
        actor = await va_user()
        cve = await cve_factory(cve_state=CveState.REJECTED.value)
        ticket = await ticket_factory(status=TicketStatus.ANALYSIS.value, cve_id=cve.id)

        with StatementRecorder(db_session) as recorder:
            await _ignore(
                db_session, ticket.id, actor, reason=TicketIgnoreReason.CVE_REJECTED
            )

        statements = recorder.statements
        ticket_lock = next(
            i
            for i, s in enumerate(statements)
            if "FROM ticket" in s and "FOR UPDATE" in s
        )
        cve_reads = [
            i
            for i, s in enumerate(statements)
            if s.lstrip().startswith("SELECT cve.cve_state")
        ]
        assert len(cve_reads) == 1
        assert cve_reads[0] > ticket_lock
        assert "FOR " not in statements[cve_reads[0]]
        assert len(recorder.row_locks()) == 2

    @pytest.mark.parametrize(
        ("status", "confidential", "error"),
        [
            pytest.param(
                TicketStatus.NEW, True, TicketNotFoundError, id="inaccessible"
            ),
            pytest.param(
                TicketStatus.IGNORED, False, TicketNotMutableError, id="not-mutable"
            ),
            pytest.param(
                TicketStatus.DUPLICATED, False, TicketNotMutableError, id="duplicated"
            ),
            pytest.param(
                TicketStatus.ANALYZED,
                False,
                InvalidTransitionError,
                id="invalid-transition",
            ),
        ],
    )
    async def test_earlier_guards_precede_the_cve_rejected_check(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
        confidential: bool,
        error: type[Exception],
    ) -> None:
        """tickets.md, Ignore Ticket: accessibility, then operability, then
        the transition guard decide before `TICKET_CVE_NOT_REJECTED`; each
        CVE-less Ticket would also fail the reason check."""
        actor = await va_user()
        ticket = await ticket_factory(status=status.value, is_confidential=confidential)

        await _assert_rejected(
            db_session,
            monkeypatch,
            error,
            ticket_id=ticket.id,
            actor=actor,
            scope=Scope.NON_CONFIDENTIAL,
            reason=TicketIgnoreReason.CVE_REJECTED,
        )

    @pytest.mark.parametrize(
        "reason",
        [
            pytest.param("not_for_us", id="unknown"),
            pytest.param("other", id="plain-string"),
            pytest.param(None, id="none"),
        ],
    )
    async def test_value_outside_the_user_reasons_raises_before_any_statement(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        reason: object,
    ) -> None:
        """Only a `TicketIgnoreReason` member that a user may choose is
        accepted; anything else raises `ValueError` before any database
        access."""
        actor = await va_user()
        ticket = await ticket_factory(status=TicketStatus.NEW.value)

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ValueError, match="reason"),
        ):
            await _ignore(db_session, ticket.id, actor, reason=cast(Any, reason))

        assert recorder.statements == []
        assert await _state(db_session, ticket.id) == (TicketStatus.NEW, None, None)
        assert await ticket_events(db_session, ticket) == []


# ---------------------------------------------------------------------------
# Guards and their order, with zero side effects
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestGuards:
    @pytest.mark.parametrize("status", [TicketStatus.ANALYZED, TicketStatus.RESOLVED])
    async def test_gate_zone_beyond_analysis_is_an_invalid_transition(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
    ) -> None:
        """An unassigned Ticket and a VA actor: a guard after the
        auto-assignment would be observable."""
        actor = await va_user()
        ticket = await ticket_factory(status=status.value)

        await _assert_rejected(
            db_session,
            monkeypatch,
            InvalidTransitionError,
            ticket_id=ticket.id,
            actor=actor,
        )

    @pytest.mark.parametrize("status", [TicketStatus.IGNORED, TicketStatus.DUPLICATED])
    async def test_manual_zone_is_not_mutable_before_the_status_check(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
    ) -> None:
        """ticket-service.md, Operability guard (ordering constraint for
        `ignore_ticket`): neither status is a valid source state, yet the
        operability guard fires first with `TicketNotMutableError`."""
        actor = await va_user()
        ticket = await ticket_factory(status=status.value)

        await _assert_rejected(
            db_session,
            monkeypatch,
            TicketNotMutableError,
            ticket_id=ticket.id,
            actor=actor,
        )

    async def test_missing_ticket_is_not_found(
        self,
        db_session: AsyncSession,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        actor = await va_user()

        await _assert_rejected(
            db_session,
            monkeypatch,
            TicketNotFoundError,
            ticket_id=uuid.uuid7(),
            actor=actor,
        )

    @pytest.mark.parametrize(
        "status",
        [
            pytest.param(TicketStatus.NEW, id="ignorable"),
            pytest.param(TicketStatus.ANALYZED, id="also-invalid-transition"),
            pytest.param(TicketStatus.IGNORED, id="also-not-mutable"),
        ],
    )
    async def test_inaccessible_ticket_is_not_found_before_any_other_decision(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_access_grant_factory: Callable[..., Awaitable[TicketAccessGrant]],
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
    ) -> None:
        """A VA origin with a request-resolved `non_confidential` scope: an
        auto-assignment before the denial would be observable. The only
        grant belongs to another user."""
        actor = await va_user()
        ticket = await ticket_factory(status=status.value, is_confidential=True)
        await ticket_access_grant_factory(ticket_id=ticket.id)

        await _assert_rejected(
            db_session,
            monkeypatch,
            TicketNotFoundError,
            ticket_id=ticket.id,
            actor=actor,
            scope=Scope.NON_CONFIDENTIAL,
        )

    async def test_caller_mismatch_raises_before_any_statement(
        self, db_session: AsyncSession, ticket_factory: TicketFactory, va_user: VAUser
    ) -> None:
        actor = await va_user()
        other = await va_user()
        ticket = await ticket_factory(status=TicketStatus.NEW.value)

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ValueError, match="acting user"),
        ):
            await ignore_ticket(
                db_session,
                ticket_id=ticket.id,
                acting_user_id=actor.id,
                caller=TicketCaller.authenticated(other.id, Scope.ALL),
                reason=OTHER,
            )

        assert recorder.statements == []
        assert await _state(db_session, ticket.id) == (TicketStatus.NEW, None, None)
        assert await ticket_events(db_session, ticket) == []


# ---------------------------------------------------------------------------
# Lock order and locked-current revalidation statement
# ---------------------------------------------------------------------------


def _bound(params: Any) -> list[Any]:
    """The bound values of one recorded statement."""
    return list(params.values() if isinstance(params, dict) else params)


@pytest.mark.integration
class TestLockOrder:
    async def test_acting_user_share_then_ticket_update_then_visibility(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_access_grant_factory: Callable[..., Awaitable[TicketAccessGrant]],
        va_user: VAUser,
    ) -> None:
        """A confidential Ticket reached through an explicit grant: the
        acting User `FOR SHARE` precedes the Ticket `FOR UPDATE`, which
        precedes the separate visibility statement."""
        actor = await va_user(roles=(Role.RESTRICTED_ANALYST,))
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, is_confidential=True
        )
        await ticket_access_grant_factory(ticket_id=ticket.id, user_id=actor.id)

        with StatementRecorder(db_session) as recorder:
            await _ignore(db_session, ticket.id, actor, scope=Scope.NON_CONFIDENTIAL)

        statements = recorder.statements

        def first(predicate: Callable[[str], bool]) -> int:
            return next(i for i, s in enumerate(statements) if predicate(s))

        user_share = first(lambda s: 'FROM "user"' in s and "FOR SHARE" in s)
        ticket_lock = first(lambda s: "FROM ticket" in s and "FOR UPDATE" in s)
        visibility = first(lambda s: "ticket_access_grant" in s)
        assert user_share < ticket_lock < visibility
        assert _bound(recorder.parameters[user_share]) == [actor.id]
        assert _bound(recorder.parameters[ticket_lock]) == [ticket.id]
        assert "ticket_access_grant" not in statements[ticket_lock]
        assert len(recorder.row_locks()) == 2
        assert await _state(db_session, ticket.id) == (
            TicketStatus.IGNORED,
            None,
            OTHER,
        )
        assert await ticket_events(db_session, ticket) == [
            _ignored(actor, TicketStatus.ANALYSIS)
        ]


# ---------------------------------------------------------------------------
# Whole-operation rollback (audit Testing Requirement 7) and no commit
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRollback:
    @pytest.mark.parametrize("failure", ["audit", "flush"])
    async def test_entry_write_failure_rolls_back_assignment_status_and_events(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        failure: str,
    ) -> None:
        """The failure is injected into the last write (the acting-user
        `Analysis -> Ignored`), after the assignment and promotion: either
        its audit validation or the flush that inserts it."""
        actor = await va_user()
        ticket = await ticket_factory(status=TicketStatus.NEW.value)
        ticket_id = ticket.id
        original_log = TicketAuditLog.log_event

        original_flush = db_session.flush
        reached = False

        async def failing_log(*args: Any, **kwargs: Any) -> None:
            nonlocal reached
            if (
                kwargs["event_type"] is TicketAuditEventType.STATUS_CHANGE
                and kwargs["new_value"] == TicketStatus.IGNORED
            ):
                reached = True
                raise RuntimeError("injected audit failure")
            await original_log(*args, **kwargs)

        async def failing_flush(*args: Any, **kwargs: Any) -> None:
            nonlocal reached
            if any(
                isinstance(o, TicketAuditEvent) and o.new_value == TicketStatus.IGNORED
                for o in db_session.new
            ):
                reached = True
                raise RuntimeError("injected flush failure")
            await original_flush(*args, **kwargs)

        async with rollback_test_scope(db_session):
            if failure == "audit":
                monkeypatch.setattr(TicketAuditLog, "log_event", failing_log)
            else:
                monkeypatch.setattr(db_session, "flush", failing_flush)
            with pytest.raises(RuntimeError, match="injected"):
                await _ignore(db_session, ticket_id, actor)
        monkeypatch.undo()

        assert reached

        assert await _state(db_session, ticket_id) == (TicketStatus.NEW, None, None)
        assert await ticket_events_by_id(db_session, ticket_id) == []

    async def test_never_commits(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        actor = await va_user()
        ticket = await ticket_factory(status=TicketStatus.NEW.value)

        async def forbidden() -> None:
            raise AssertionError("ignore_ticket() must not commit")

        monkeypatch.setattr(db_session, "commit", forbidden)
        monkeypatch.setattr(db_session, "rollback", forbidden)

        await _ignore(db_session, ticket.id, actor)
