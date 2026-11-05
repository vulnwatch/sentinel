"""Single-session service integration tests for `assign_ticket()`
(backend/app/services/ticket_service.py).

Owning specifications:

- docs/features/tickets/ticket-service.md (Transaction ownership; Caller
  category and Ticket accessibility; Operability guard; Concurrency
  control; `assign_ticket`; Architectural Test Requirement 2, 3, 4
  (`assign_ticket()` path), 15 (single-session part), and 23
  (`assign_ticket()` single-session part)).
- docs/features/tickets/tickets.md (Reassignment, including Expected
  assignee; Architectural Invariant).
- docs/features/tickets/ticket-audit-log.md (Event Type Contract:
  `assignment`, `status_change`; Canonical Mutation and No-Event Matrix:
  Direct assignment or reassignment; Cross-Event Ordering, Locking, and
  Rollback; Testing Requirements 1-7).
- docs/features/platform/testing-strategy.md (Tier Responsibility and
  Proportionality; Service Functions; User Identifier Resolution; Ticket
  Accessibility: Locked mutations).

The independent-session tests (Ticket and target-User lock serialization,
the winner/loser old value of audit Testing Requirement 23, the
expected-assignee races, and the locked-current accessibility races) live
in `tests/test_services/test_assign_ticket_atomicity.py`.

Not reachable, hence not tested: the converse self-loss case of
Architectural Test Requirement 15 (an authorized mutation that itself
removes the caller's last visibility path). The canonical predicate
(docs/features/identity/rbac.md, Scope and Confidential Ticket Visibility)
depends only on the Ticket's confidentiality, the caller's scope, explicit
grants, and included-package maintainership; `assign_ticket()` changes only
`assignee_id` and the status, so it cannot remove any visibility path.

Expected values are transcribed from the specifications, never computed
with the module under test.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, date, datetime, timedelta, timezone
from typing import Any

import pytest
from pydantic import MISSING
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    PackageStatus,
    Role,
    Scope,
    TicketAuditEventType,
    TicketStatus,
)
from app.core.exceptions import (
    TicketNotFoundError,
    TicketNotMutableError,
    UserNotFoundError,
)
from app.models.product import Product
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.ticket_package_product import TicketPackageProduct
from app.models.user import User
from app.services import ticket_mutations, ticket_service
from app.services.assignment_eligibility import AssigneeIneligibility
from app.services.ticket_audit_log import TicketAuditLog
from app.services.ticket_convergence_registry import (
    pending_ticket_convergence_effects,
)
from app.services.ticket_service import (
    AssigneeChangedError,
    AssigneeInactiveError,
    AssigneeNotEligibleError,
    assign_ticket,
)
from app.services.ticket_visibility import TicketCaller
from tests.support.database import rollback_test_scope
from tests.support.ticket_mutations import (
    EVAL,
    EventRow,
    StatementRecorder,
    TicketFactory,
    TreeBuilder,
    VAUser,
    cveless,
    status_event,
    ticket_events,
    ticket_events_by_id,
    tree_for,
)

pytest_plugins = ["tests.support.ticket_mutation_fixtures"]
"""Provides the shared `va_user` and `tree` fixtures."""

PROMOTION = status_event(TicketStatus.NEW.value, TicketStatus.ANALYSIS.value)
"""The explicit system `New -> Analysis` event of step 10."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _assignment(actor: User, old: User | None, new: User) -> EventRow:
    """The acting-user `assignment` event (ticket-audit-log.md, Event Type
    Contract): previous and new assignee usernames, `comment` and `detail`
    `NULL`."""
    return EventRow(
        "assignment",
        actor.id,
        old.username if old is not None else None,
        new.username,
        None,
        None,
    )


async def _assign(
    db: AsyncSession,
    ticket_id: uuid.UUID,
    target: str,
    actor: User,
    *,
    scope: Scope = Scope.ALL,
    expected: uuid.UUID | MISSING | None = MISSING,
    evaluation_date: date | None = EVAL,
) -> Ticket:
    """Call the service as an API handler would (fixed `EVAL` by default;
    `None` omits the date). `expected` is the expected assignee, omitted
    (`MISSING`) by default."""
    return await assign_ticket(
        db,
        ticket_id=ticket_id,
        assignee=target,
        acting_user_id=actor.id,
        caller=TicketCaller.authenticated(actor.id, scope),
        expected_assignee_id=expected,
        evaluation_date=evaluation_date,
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
    `ticket_mutations`), recording each call's arguments."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, name: str) -> None:
        self.calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        original = getattr(ticket_service, name)

        async def _wrapper(*args: Any, **kwargs: Any) -> Any:
            self.calls.append((args, kwargs))
            return await original(*args, **kwargs)

        monkeypatch.setattr(ticket_service, name, _wrapper)


TARGET_KINDS = ["absent", "inactive", "bot"]
"""One target per rejected result of step 5 (the condition precedence is
proven once, by `test_ineligible_target_is_rejected_inactive_first`)."""


async def _target(kind: str, va_user: VAUser) -> str:
    """The raw UUID identifier of a target of the given kind: an active VA
    (`eligible`), no User (`absent`), an inactive VA, or an active VA that is
    a bot account (`bot`, not eligible: rbac.md, Business Rule 10)."""
    if kind == "absent":
        return str(uuid.uuid7())
    user = await va_user(active=kind != "inactive", bot=kind == "bot")
    return str(user.id)


async def _assert_rejected(
    db: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    error_type: type[Exception],
    *,
    ticket_id: uuid.UUID,
    target: str,
    actor: User,
    scope: Scope = Scope.ALL,
    expected: uuid.UUID | MISSING | None = MISSING,
) -> BaseException:
    """Call the service and assert the zero-side-effect contract of a
    rejected call: the expected error, no write, no reconciliation, no
    registered convergence effect, the Ticket unchanged, and no event.
    Returns the raised exception."""
    reconcile = _Spy(monkeypatch, "reconcile_ticket_status")
    before = await _state(db, ticket_id)

    with StatementRecorder(db) as recorder, pytest.raises(error_type) as raised:
        await _assign(db, ticket_id, target, actor, scope=scope, expected=expected)

    assert recorder.writes() == []
    assert reconcile.calls == []
    assert pending_ticket_convergence_effects(db) == ()
    assert await _state(db, ticket_id) == before
    assert await ticket_events_by_id(db, ticket_id) == []
    return raised.value


# ---------------------------------------------------------------------------
# ATR 2 and 4: explicit New -> Analysis promotion
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestExplicitPromotion:
    async def test_new_ticket_is_promoted_by_the_assignment_not_by_reconciliation(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Step 10 creates the system `New -> Analysis` event before the one
        reconciliation, which finds the Ticket already in `Analysis` and
        (no gate being met) adds nothing. The acting user is an eligible
        VA on an unassigned Ticket: `auto_assign_actor()` is never used."""
        actor = await va_user()
        target = await va_user()
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW, severity=None)
        assign = _Spy(monkeypatch, "auto_assign_actor")
        observed: list[tuple[str, list[EventRow]]] = []
        original = ticket_mutations.reconcile_ticket_status

        async def observing_reconcile(
            locked: Ticket, db: AsyncSession, **kwargs: Any
        ) -> None:
            observed.append((locked.status, await ticket_events(db, locked)))
            await original(locked, db, **kwargs)

        monkeypatch.setattr(
            ticket_service, "reconcile_ticket_status", observing_reconcile
        )

        result = await _assign(db_session, ticket.id, str(target.id), actor)

        expected = [_assignment(actor, None, target), PROMOTION]
        assert observed == [(TicketStatus.ANALYSIS, expected)]
        assert assign.calls == []
        assert result.id == ticket.id
        assert (result.status, result.assignee_id) == (
            TicketStatus.ANALYSIS,
            target.id,
        )
        assert await _state(db_session, ticket.id) == (TicketStatus.ANALYSIS, target.id)
        assert await ticket_events(db_session, ticket) == expected
        assert pending_ticket_convergence_effects(db_session) == ()

    async def test_reconciliation_promotes_further_after_the_explicit_step(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
    ) -> None:
        actor = await va_user()
        target = await va_user()
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW)
        await tree_for(TicketStatus.ANALYZED, ticket, tree)

        await _assign(db_session, ticket.id, str(target.id), actor)

        assert await _state(db_session, ticket.id) == (TicketStatus.ANALYZED, target.id)
        assert await ticket_events(db_session, ticket) == [
            _assignment(actor, None, target),
            PROMOTION,
            status_event(TicketStatus.ANALYSIS.value, TicketStatus.ANALYZED.value),
        ]


# ---------------------------------------------------------------------------
# Reassignment
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestReassignment:
    @pytest.mark.parametrize(
        ("current", "gates", "expected"),
        [
            pytest.param(
                TicketStatus.ANALYSIS,
                TicketStatus.ANALYSIS,
                TicketStatus.ANALYSIS,
                id="analysis-kept",
            ),
            pytest.param(
                TicketStatus.ANALYZED,
                TicketStatus.ANALYZED,
                TicketStatus.ANALYZED,
                id="analyzed-kept",
            ),
            pytest.param(
                TicketStatus.RESOLVED,
                TicketStatus.RESOLVED,
                TicketStatus.RESOLVED,
                id="resolved-kept",
            ),
            pytest.param(
                TicketStatus.ANALYSIS,
                TicketStatus.ANALYZED,
                TicketStatus.ANALYZED,
                id="analysis-gates-met",
            ),
        ],
    )
    async def test_reassignment_records_the_previous_username_and_keeps_status(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        current: TicketStatus,
        gates: TicketStatus,
        expected: TicketStatus,
    ) -> None:
        actor = await va_user()
        previous = await va_user()
        target = await va_user()
        ticket = await cveless(ticket_factory, status=current, assignee_id=previous.id)
        await tree_for(gates, ticket, tree)

        await _assign(db_session, ticket.id, str(target.id), actor)

        final = (
            [status_event(current.value, expected.value)]
            if expected is not current
            else []
        )
        assert await _state(db_session, ticket.id) == (expected, target.id)
        assert await ticket_events(db_session, ticket) == [
            _assignment(actor, previous, target),
            *final,
        ]


# ---------------------------------------------------------------------------
# ATR 3: idempotency
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestIdempotency:
    async def test_assigning_the_current_assignee_again_has_no_effect(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        actor = await va_user()
        target = await va_user()
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW)
        await _assign(db_session, ticket.id, str(target.id), actor)
        first = [_assignment(actor, None, target), PROMOTION]
        assert await ticket_events(db_session, ticket) == first
        # Gates met after the first call: a reconciliation on the second
        # call would move the Ticket to `Analyzed`.
        await tree_for(TicketStatus.ANALYZED, ticket, tree)
        reconcile = _Spy(monkeypatch, "reconcile_ticket_status")

        with StatementRecorder(db_session) as recorder:
            result = await _assign(db_session, ticket.id, target.username, actor)

        assert result.id == ticket.id
        assert reconcile.calls == []
        assert recorder.writes() == []
        assert await _state(db_session, ticket.id) == (TicketStatus.ANALYSIS, target.id)
        assert await ticket_events(db_session, ticket) == first
        assert pending_ticket_convergence_effects(db_session) == ()


# ---------------------------------------------------------------------------
# ATR 23: expected assignee
# ---------------------------------------------------------------------------


async def _expectation(kind: str, va_user: VAUser) -> uuid.UUID | None:
    """An expected assignee that is not the target: none (`None`), another
    active VA's UUID, or a UUID that identifies no user."""
    if kind == "none":
        return None
    if kind == "other":
        return (await va_user()).id
    return uuid.uuid7()


@pytest.mark.integration
class TestExpectedAssignee:
    @pytest.mark.parametrize("current", ["none", "assigned"])
    async def test_matching_expectation_assigns_as_an_omitted_one(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        current: str,
    ) -> None:
        """`None` for an unassigned `New` Ticket, the assignee's UUID for an
        assigned one: the request assigns exactly as without an
        expectation, including the `New -> Analysis` promotion."""
        actor = await va_user()
        target = await va_user()
        previous = await va_user() if current == "assigned" else None
        ticket = await cveless(
            ticket_factory,
            status=TicketStatus.NEW if previous is None else TicketStatus.ANALYSIS,
            severity=None,
            assignee_id=previous.id if previous is not None else None,
        )

        await _assign(
            db_session,
            ticket.id,
            str(target.id),
            actor,
            expected=previous.id if previous is not None else None,
        )

        assert await _state(db_session, ticket.id) == (TicketStatus.ANALYSIS, target.id)
        assert await ticket_events(db_session, ticket) == [
            _assignment(actor, previous, target),
            *([PROMOTION] if previous is None else []),
        ]

    @pytest.mark.parametrize(
        ("current", "expected"),
        [
            pytest.param("none", "other", id="unassigned-expects-a-user"),
            pytest.param("none", "unknown", id="unassigned-expects-an-unknown-uuid"),
            pytest.param("assigned", "none", id="assigned-expects-none"),
            pytest.param("assigned", "other", id="assigned-expects-another-user"),
            pytest.param("assigned", "unknown", id="assigned-expects-an-unknown-uuid"),
        ],
    )
    async def test_mismatch_raises_assignee_changed_with_no_effect(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        current: str,
        expected: str,
    ) -> None:
        """No write, event, reconciliation, or convergence registration; an
        unassigned `New` Ticket stays `New`, and an assigned Ticket whose
        gates are met above its status is not promoted."""
        actor = await va_user()
        target = await va_user()
        if current == "none":
            ticket = await cveless(
                ticket_factory, status=TicketStatus.NEW, severity=None
            )
        else:
            ticket = await cveless(ticket_factory, assignee_id=(await va_user()).id)
            await tree_for(TicketStatus.ANALYZED, ticket, tree)

        await _assert_rejected(
            db_session,
            monkeypatch,
            AssigneeChangedError,
            ticket_id=ticket.id,
            target=str(target.id),
            actor=actor,
            expected=await _expectation(expected, va_user),
        )

    async def test_rejection_adds_no_statement_under_the_ticket_lock(
        self, db_session: AsyncSession, ticket_factory: TicketFactory, va_user: VAUser
    ) -> None:
        """The expectation is compared with the row that the lock returned:
        after the Ticket `FOR UPDATE`, the only statement is the visibility
        decision, and no previous-assignee username is read."""
        actor = await va_user()
        target = await va_user()
        ticket = await cveless(ticket_factory, assignee_id=(await va_user()).id)

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(AssigneeChangedError),
        ):
            await _assign(db_session, ticket.id, str(target.id), actor, expected=None)

        statements = recorder.statements
        ticket_lock = next(
            i
            for i, s in enumerate(statements)
            if "FROM ticket" in s and "FOR UPDATE" in s
        )
        assert len(recorder.row_locks()) == 2
        assert len(statements) == ticket_lock + 2
        assert 'FROM "user"' not in statements[-1]

    @pytest.mark.parametrize("expected", ["none", "other", "unknown"])
    async def test_target_already_the_assignee_is_the_no_op_whatever_the_expectation(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        expected: str,
    ) -> None:
        """The step-6 no-op precedes the expectation, so a retry of an
        applied request succeeds: no write, event, or reconciliation, even
        with gates met above the status."""
        actor = await va_user()
        target = await va_user()
        ticket = await cveless(ticket_factory, assignee_id=target.id)
        await tree_for(TicketStatus.ANALYZED, ticket, tree)
        stale = await _expectation(expected, va_user)
        reconcile = _Spy(monkeypatch, "reconcile_ticket_status")

        with StatementRecorder(db_session) as recorder:
            result = await _assign(
                db_session, ticket.id, str(target.id), actor, expected=stale
            )

        assert result.assignee_id == target.id
        assert recorder.writes() == []
        assert reconcile.calls == []
        assert await _state(db_session, ticket.id) == (TicketStatus.ANALYSIS, target.id)
        assert await ticket_events(db_session, ticket) == []
        assert pending_ticket_convergence_effects(db_session) == ()

    @pytest.mark.parametrize(
        ("case", "error_type"),
        [
            pytest.param("inaccessible", TicketNotFoundError, id="not-found"),
            pytest.param("ignored", TicketNotMutableError, id="not-mutable"),
            pytest.param("absent", UserNotFoundError, id="user-not-found"),
            pytest.param("inactive", AssigneeInactiveError, id="inactive"),
            pytest.param("bot", AssigneeNotEligibleError, id="not-eligible"),
        ],
    )
    async def test_every_other_error_precedes_assignee_changed(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        case: str,
        error_type: type[Exception],
    ) -> None:
        """An assigned Ticket and the stale expectation `None`: accessibility,
        operability, and each target error keep their outcome."""
        restricted = case == "inaccessible"
        actor = await va_user(
            roles=(Role.RESTRICTED_ANALYST,)
            if restricted
            else (Role.VULNERABILITY_ANALYST,)
        )
        target = await _target(case if case in TARGET_KINDS else "eligible", va_user)
        ticket = await cveless(
            ticket_factory,
            status=TicketStatus.IGNORED if case == "ignored" else TicketStatus.ANALYSIS,
            severity=None,
            is_confidential=restricted,
            assignee_id=(await va_user()).id,
        )

        await _assert_rejected(
            db_session,
            monkeypatch,
            error_type,
            ticket_id=ticket.id,
            target=target,
            actor=actor,
            scope=Scope.NON_CONFIDENTIAL if restricted else Scope.ALL,
            expected=None,
        )


# ---------------------------------------------------------------------------
# Target identifier forms (testing-strategy.md, User Identifier Resolution)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestTargetIdentifier:
    @pytest.mark.parametrize("form", ["uuid", "username"])
    async def test_uuid_and_username_select_the_same_target(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        form: str,
    ) -> None:
        actor = await va_user()
        target = await va_user()
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW, severity=None)
        identifier = str(target.id) if form == "uuid" else target.username

        await _assign(db_session, ticket.id, identifier, actor)

        assert await _state(db_session, ticket.id) == (TicketStatus.ANALYSIS, target.id)
        assert await ticket_events(db_session, ticket) == [
            _assignment(actor, None, target),
            PROMOTION,
        ]

    @pytest.mark.parametrize("form", ["uuid", "username"])
    async def test_nonexistent_target_raises_user_not_found(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        form: str,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW, severity=None)
        identifier = (
            str(uuid.uuid7()) if form == "uuid" else f"nobody.va.{uuid.uuid4().hex[:8]}"
        )

        await _assert_rejected(
            db_session,
            monkeypatch,
            UserNotFoundError,
            ticket_id=ticket.id,
            target=identifier,
            actor=actor,
        )


# ---------------------------------------------------------------------------
# Guard precedence with zero side effects
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestGuardPrecedence:
    @pytest.mark.parametrize("kind", ["eligible", *TARGET_KINDS])
    async def test_missing_ticket_is_not_found_whatever_the_target(
        self,
        db_session: AsyncSession,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        kind: str,
    ) -> None:
        actor = await va_user()
        target = await _target(kind, va_user)

        await _assert_rejected(
            db_session,
            monkeypatch,
            TicketNotFoundError,
            ticket_id=uuid.uuid7(),
            target=target,
            actor=actor,
        )

    @pytest.mark.parametrize(
        ("status", "kind", "preassigned"),
        [
            pytest.param(TicketStatus.NEW, "eligible", False, id="eligible"),
            *[
                pytest.param(TicketStatus.NEW, kind, False, id=kind)
                for kind in TARGET_KINDS
            ],
            pytest.param(TicketStatus.IGNORED, "absent", False, id="also-ignored"),
            pytest.param(TicketStatus.ANALYSIS, "eligible", True, id="also-unchanged"),
        ],
    )
    async def test_inaccessible_ticket_is_not_found_before_any_other_decision(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
        kind: str,
        preassigned: bool,
    ) -> None:
        actor = await va_user(roles=(Role.RESTRICTED_ANALYST,))
        target = await _target(kind, va_user)
        ticket = await cveless(
            ticket_factory,
            status=status,
            severity=None,
            is_confidential=True,
            assignee_id=uuid.UUID(target) if preassigned else None,
        )

        await _assert_rejected(
            db_session,
            monkeypatch,
            TicketNotFoundError,
            ticket_id=ticket.id,
            target=target,
            actor=actor,
            scope=Scope.NON_CONFIDENTIAL,
        )

    @pytest.mark.parametrize("kind", TARGET_KINDS)
    @pytest.mark.parametrize("status", [TicketStatus.IGNORED, TicketStatus.DUPLICATED])
    async def test_manual_zone_is_not_mutable_before_any_target_result(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
        kind: str,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=status, severity=None)

        await _assert_rejected(
            db_session,
            monkeypatch,
            TicketNotMutableError,
            ticket_id=ticket.id,
            target=await _target(kind, va_user),
            actor=actor,
        )

    @pytest.mark.parametrize(
        ("active", "roles", "bot", "confidential", "condition"),
        [
            pytest.param(
                False,
                (Role.VULNERABILITY_ANALYST,),
                False,
                False,
                None,
                id="inactive-va",
            ),
            pytest.param(
                False,
                (Role.RESTRICTED_ANALYST,),
                True,
                True,
                None,
                id="inactive-precedes-every-other-condition",
            ),
            pytest.param(False, (), False, False, None, id="inactive-no-roles"),
            pytest.param(
                True,
                (Role.VULNERABILITY_ANALYST,),
                True,
                False,
                AssigneeIneligibility.BOT,
                id="bot-va",
            ),
            pytest.param(
                True,
                (),
                True,
                True,
                AssigneeIneligibility.BOT,
                id="bot-precedes-triage-and-confidentiality",
            ),
            pytest.param(
                True,
                (),
                False,
                False,
                AssigneeIneligibility.NO_TRIAGE_TICKET,
                id="no-roles",
            ),
            pytest.param(
                True,
                (Role.ADMIN,),
                False,
                True,
                AssigneeIneligibility.NO_TRIAGE_TICKET,
                id="admin-only-precedes-confidentiality",
            ),
            pytest.param(
                True,
                (Role.RESTRICTED_ANALYST,),
                False,
                True,
                AssigneeIneligibility.CONFIDENTIAL,
                id="restricted-on-confidential",
            ),
        ],
    )
    async def test_ineligible_target_is_rejected_inactive_first(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        active: bool,
        roles: tuple[Role, ...],
        bot: bool,
        confidential: bool,
        condition: AssigneeIneligibility | None,
    ) -> None:
        """Step 5 (rbac.md, Business Rule 10): an inactive target raises
        `AssigneeInactiveError` before any other condition; every other
        ineligible target raises `AssigneeNotEligibleError` carrying the
        first failing condition in the order bot account, no
        `triage_ticket`, confidential without scope `all`."""
        actor = await va_user()
        target = await va_user(active=active, roles=roles, bot=bot)
        ticket = await cveless(
            ticket_factory,
            status=TicketStatus.NEW,
            severity=None,
            is_confidential=confidential,
        )

        error = await _assert_rejected(
            db_session,
            monkeypatch,
            AssigneeInactiveError if condition is None else AssigneeNotEligibleError,
            ticket_id=ticket.id,
            target=str(target.id),
            actor=actor,
        )

        if condition is not None:
            assert isinstance(error, AssigneeNotEligibleError)
            assert error.condition is condition

    async def test_grant_does_not_make_a_restricted_target_eligible(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_access_grant_factory: Callable[..., Awaitable[TicketAccessGrant]],
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """rbac.md, Business Rule 10: a restricted analyst that sees the
        confidential Ticket through an explicit grant is still not
        eligible to be its assignee."""
        actor = await va_user()
        target = await va_user(roles=(Role.RESTRICTED_ANALYST,))
        ticket = await cveless(
            ticket_factory, status=TicketStatus.NEW, severity=None, is_confidential=True
        )
        await ticket_access_grant_factory(ticket_id=ticket.id, user_id=target.id)

        error = await _assert_rejected(
            db_session,
            monkeypatch,
            AssigneeNotEligibleError,
            ticket_id=ticket.id,
            target=target.username,
            actor=actor,
        )

        assert isinstance(error, AssigneeNotEligibleError)
        assert error.condition is AssigneeIneligibility.CONFIDENTIAL

    @pytest.mark.parametrize(
        ("roles", "confidential"),
        [
            pytest.param((Role.RESTRICTED_ANALYST,), False, id="restricted-on-public"),
            pytest.param(
                (Role.ADMIN, Role.RESTRICTED_ANALYST),
                True,
                id="admin-and-restricted-on-confidential",
            ),
            pytest.param((Role.VULNERABILITY_ANALYST,), True, id="va-on-confidential"),
        ],
    )
    async def test_eligibility_comes_from_capability_and_scope(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        roles: tuple[Role, ...],
        confidential: bool,
    ) -> None:
        """rbac.md, Business Rule 10: a non-bot restricted analyst is
        assigned to a non-confidential Ticket exactly as a vulnerability
        analyst is, including `New -> Analysis`; a role whose scope is
        `all` makes a restricted analyst eligible for a confidential
        Ticket."""
        actor = await va_user()
        target = await va_user(roles=roles)
        ticket = await cveless(
            ticket_factory,
            status=TicketStatus.NEW,
            severity=None,
            is_confidential=confidential,
        )

        await _assign(db_session, ticket.id, str(target.id), actor)

        assert await _state(db_session, ticket.id) == (TicketStatus.ANALYSIS, target.id)
        assert await ticket_events(db_session, ticket) == [
            _assignment(actor, None, target),
            PROMOTION,
        ]

    async def test_caller_mismatch_raises_before_any_statement(
        self, db_session: AsyncSession, ticket_factory: TicketFactory, va_user: VAUser
    ) -> None:
        actor = await va_user()
        other = await va_user()
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW, severity=None)

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ValueError, match="acting user"),
        ):
            await assign_ticket(
                db_session,
                ticket_id=ticket.id,
                assignee=str(actor.id),
                acting_user_id=actor.id,
                caller=TicketCaller.authenticated(other.id, Scope.ALL),
                evaluation_date=EVAL,
            )

        assert recorder.statements == []
        assert await _state(db_session, ticket.id) == (TicketStatus.NEW, None)
        assert await ticket_events(db_session, ticket) == []


# ---------------------------------------------------------------------------
# Locked-current accessibility (single session)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestAccessibility:
    async def test_explicit_grant_holder_assigns_a_confidential_ticket(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_access_grant_factory: Callable[..., Awaitable[TicketAccessGrant]],
        va_user: VAUser,
    ) -> None:
        actor = await va_user(roles=(Role.RESTRICTED_ANALYST,))
        target = await va_user()
        ticket = await cveless(
            ticket_factory, status=TicketStatus.NEW, severity=None, is_confidential=True
        )
        await ticket_access_grant_factory(ticket_id=ticket.id, user_id=actor.id)

        await _assign(
            db_session, ticket.id, str(target.id), actor, scope=Scope.NON_CONFIDENTIAL
        )

        assert await _state(db_session, ticket.id) == (TicketStatus.ANALYSIS, target.id)
        assert await ticket_events(db_session, ticket) == [
            _assignment(actor, None, target),
            PROMOTION,
        ]


# ---------------------------------------------------------------------------
# Lock order and unlocked observations
# ---------------------------------------------------------------------------


def _bound(params: Any) -> list[Any]:
    """The bound values of one recorded statement."""
    return list(params.values() if isinstance(params, dict) else params)


@pytest.mark.integration
class TestLockOrder:
    async def test_target_share_then_ticket_update_then_visibility(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_access_grant_factory: Callable[..., Awaitable[TicketAccessGrant]],
        va_user: VAUser,
    ) -> None:
        """A reassignment through an explicit grant: the target User `FOR
        SHARE` and its role load precede the Ticket `FOR UPDATE`, which
        precedes the separate visibility statement. Under the Ticket lock,
        the only User reads are the unlocked previous-assignee username and
        the reconciliation's sanitation observation of the new assignee."""
        actor = await va_user(roles=(Role.RESTRICTED_ANALYST,))
        previous = await va_user()
        target = await va_user()
        ticket = await cveless(
            ticket_factory,
            severity=None,
            is_confidential=True,
            assignee_id=previous.id,
        )
        await ticket_access_grant_factory(ticket_id=ticket.id, user_id=actor.id)

        with StatementRecorder(db_session) as recorder:
            await _assign(
                db_session,
                ticket.id,
                str(target.id),
                actor,
                scope=Scope.NON_CONFIDENTIAL,
            )

        statements = recorder.statements

        def first(predicate: Callable[[str], bool]) -> int:
            return next(i for i, s in enumerate(statements) if predicate(s))

        user_share = first(lambda s: 'FROM "user"' in s and "FOR SHARE" in s)
        roles = first(lambda s: "FROM user_role" in s)
        ticket_lock = first(lambda s: "FROM ticket" in s and "FOR UPDATE" in s)
        visibility = first(lambda s: "ticket_access_grant" in s)
        assert user_share < roles < ticket_lock < visibility
        assert target.id in _bound(recorder.parameters[user_share])
        assert "ticket_access_grant" not in statements[ticket_lock]
        assert len(recorder.row_locks()) == 2

        user_reads = [
            i
            for i in range(ticket_lock + 1, len(statements))
            if 'FROM "user"' in statements[i]
        ]
        assert [i for i in user_reads if "FOR " in statements[i]] == []
        bound = [_bound(recorder.parameters[i]) for i in user_reads]
        assert len(bound) == 2
        assert bound[0] == [previous.id]
        assert target.id in bound[1]
        assert not any('"user"' in w for w in recorder.writes())
        assert recorder.selects_from("ticket_audit_event") == []
        assert await ticket_events(db_session, ticket) == [
            _assignment(actor, previous, target)
        ]


# ---------------------------------------------------------------------------
# One evaluation date
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestEvaluationDate:
    async def test_supplied_date_reaches_reconciliation_without_the_clock(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def clock() -> datetime:
            raise AssertionError("the supplied date must be reused")

        monkeypatch.setattr(ticket_service, "_utc_now", clock)
        monkeypatch.setattr(ticket_mutations, "_utc_now", clock)
        reconcile = _Spy(monkeypatch, "reconcile_ticket_status")
        actor = await va_user()
        target = await va_user()
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW, severity=None)
        supplied = date(2026, 1, 2)

        await _assign(
            db_session, ticket.id, str(target.id), actor, evaluation_date=supplied
        )

        assert [(args[0].id, kwargs) for args, kwargs in reconcile.calls] == [
            (ticket.id, {"evaluation_date": supplied})
        ]

    async def test_omitted_date_is_captured_once_at_entry_in_utc(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        product_factory: Callable[..., Awaitable[Product]],
        ticket_package_product_factory: Callable[..., Awaitable[TicketPackageProduct]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        day = date(2026, 12, 31)
        instants = iter(
            [
                # 22:30 UTC on `day`, expressed with a `+02:00` offset.
                datetime(2027, 1, 1, 0, 30, tzinfo=timezone(timedelta(hours=2))),
                datetime(2027, 1, 1, 0, 0, 0, tzinfo=UTC),
            ]
        )
        calls = 0

        def clock() -> datetime:
            nonlocal calls
            calls += 1
            return next(instants)

        def forbidden_clock() -> datetime:
            raise AssertionError("the date is captured once by the service")

        actor = await va_user()
        previous = await va_user()
        target = await va_user()
        ticket = await cveless(ticket_factory, assignee_id=previous.id)
        # General Support ends on `day`: the AFFECTED track is actionable on
        # `day` (Analyzed) and all-EOL the next day (Resolved).
        track = await tree(ticket, status=PackageStatus.AFFECTED, products=())
        product = await product_factory(general_support_end_date=day)
        await ticket_package_product_factory(
            ticket_package_track_id=track.id, product_id=product.id
        )
        monkeypatch.setattr(ticket_service, "_utc_now", clock)
        monkeypatch.setattr(ticket_mutations, "_utc_now", forbidden_clock)
        reconcile = _Spy(monkeypatch, "reconcile_ticket_status")

        await _assign(
            db_session, ticket.id, str(target.id), actor, evaluation_date=None
        )

        assert calls == 1
        assert [kwargs for _, kwargs in reconcile.calls] == [{"evaluation_date": day}]
        assert await _state(db_session, ticket.id) == (TicketStatus.ANALYZED, target.id)


# ---------------------------------------------------------------------------
# Whole-operation rollback (audit Testing Requirement 7) and no commit
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRollback:
    @pytest.mark.parametrize(
        "failure", ["assignment-audit", "status-audit", "reconciliation"]
    )
    async def test_failure_rolls_back_every_effect(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        failure: str,
    ) -> None:
        actor = await va_user()
        target = await va_user()
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW)
        await tree_for(TicketStatus.ANALYZED, ticket, tree)
        failing_type = {
            "assignment-audit": TicketAuditEventType.ASSIGNMENT,
            "status-audit": TicketAuditEventType.STATUS_CHANGE,
        }.get(failure)

        async with rollback_test_scope(db_session):
            if failing_type is not None:
                original_log = TicketAuditLog.log_event

                async def failing_log(*args: Any, **kwargs: Any) -> None:
                    if kwargs["event_type"] is failing_type:
                        raise RuntimeError("injected audit failure")
                    await original_log(*args, **kwargs)

                monkeypatch.setattr(TicketAuditLog, "log_event", failing_log)
            else:
                original_reconcile = ticket_mutations.reconcile_ticket_status

                async def failing_reconcile(*args: Any, **kwargs: Any) -> None:
                    await original_reconcile(*args, **kwargs)
                    raise RuntimeError("injected reconciliation failure")

                monkeypatch.setattr(
                    ticket_service, "reconcile_ticket_status", failing_reconcile
                )

            with pytest.raises(RuntimeError, match="injected"):
                await _assign(db_session, ticket.id, str(target.id), actor)
        monkeypatch.undo()

        await db_session.refresh(ticket)
        assert await _state(db_session, ticket.id) == (TicketStatus.NEW, None)
        assert await ticket_events(db_session, ticket) == []
        assert pending_ticket_convergence_effects(db_session) == ()

    async def test_never_commits(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        actor = await va_user()
        target = await va_user()
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW, severity=None)

        async def forbidden() -> None:
            raise AssertionError("assign_ticket() must not commit")

        monkeypatch.setattr(db_session, "commit", forbidden)
        monkeypatch.setattr(db_session, "rollback", forbidden)

        await _assign(db_session, ticket.id, str(target.id), actor)
