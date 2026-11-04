"""Independent-session races between `set_confidentiality(true)`
(backend/app/services/ticket_service.py) and every change that the
assignment eligibility of the Ticket's assignee depends on: explicit
assignment, auto-assignment, role-origin removal, bot marking, and
self-unassignment.

Owning specifications:

- docs/features/tickets/ticket-service.md (`set_confidentiality` step 7,
  Locking, Concurrency and result; `unassign_ticket`, Concurrency;
  Architectural Test Requirements 21 and 22).
- docs/features/identity/user-service.md (Concurrency Considerations:
  Assignment concurrent with eligibility loss, both commit orders of
  `set_confidentiality()` against an identity batch).
- docs/features/identity/rbac.md (Business Rule 10).
- docs/conventions.md (Cross-Domain Root Lock Order: the confidentiality
  exception).
- docs/features/platform/testing-strategy.md (User Lifecycle and
  Management: `set_confidentiality(true)` races with role removal and bot
  marking in both commit orders; Concurrency Testing, Lock-Wait
  Observation).

In every race the winner holds its locks in an open transaction and the
waiter is proven blocked by it in PostgreSQL's lock manager
(`assert_lock_wait`). `set_confidentiality()` locks only the Ticket, so it
serializes with assignment, self-unassignment, and the identity batches on
the Ticket row; an identity batch selects the assigned Tickets without a
confidentiality filter and decides from the locked-current Ticket. Each
test asserts the committed outcome, and with it the invariant that no
committed active-status confidential Ticket keeps an assignee whose
effective scope is `non_confidential` or a bot assignee.

Committed state is read through a fresh independent session; committed
rows are deleted explicitly at teardown (testing-strategy.md, Concurrency
Testing). Expected values are transcribed from the specifications, never
computed with the module under test.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator, Awaitable
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import Role, Scope, TicketPriority, TicketStatus
from app.core.exceptions import TicketNotFoundError
from app.models.ticket import Ticket
from app.models.user import User
from app.services.assignment_eligibility import AssigneeIneligibility
from app.services.ticket_service import (
    AssigneeNotEligibleError,
    assign_ticket,
    set_confidentiality,
    set_priority_override,
    unassign_ticket,
)
from app.services.ticket_visibility import TicketCaller
from tests.support.assignment_lifecycle_races import (
    PROMOTION,
    WAIT,
    Factory,
    RaceWorld,
    assignment_event,
    race_world,
)
from tests.support.database import assert_lock_wait
from tests.support.identity_lifecycle_races import (
    BOT_ACCOUNT,
    ROLE_REMOVED,
    mark_bot,
    remove_roles,
)
from tests.support.ticket_mutations import (
    EVAL,
    EventRow,
    ticket_events_by_id,
    unassigned_event,
)

CONFIDENTIAL_TICKET = "confidential ticket"
"""The reason of the confidentiality transition (ticket-audit-log.md,
Canonical Automatic Comment Vocabulary)."""


@pytest.fixture
async def world(db_session_factory: Factory) -> AsyncIterator[RaceWorld]:
    async with race_world(db_session_factory) as created:
        yield created


async def _va(world: RaceWorld, prefix: str) -> User:
    return await world.identity_user(manual=[Role.VULNERABILITY_ANALYST], prefix=prefix)


async def _restricted(world: RaceWorld, prefix: str = "carol.ra") -> User:
    return await world.identity_user(manual=[Role.RESTRICTED_ANALYST], prefix=prefix)


def _classify(session: AsyncSession, ticket: Ticket, actor: User) -> Awaitable[Ticket]:
    """The real `set_confidentiality(true)` by a vulnerability analyst."""
    return set_confidentiality(
        session,
        ticket_id=ticket.id,
        is_confidential=True,
        acting_user_id=actor.id,
        caller=TicketCaller.authenticated(actor.id, Scope.ALL),
    )


def _classified(actor: User) -> EventRow:
    return EventRow("confidentiality_changed", actor.id, "false", "true", None, None)


def _restricted_caller(user: User) -> TicketCaller:
    return TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL)


async def _committed(
    world: RaceWorld, ticket: Ticket
) -> tuple[tuple[str, uuid.UUID | None, bool], list[EventRow]]:
    """The committed `(status, assignee_id, is_confidential)` and audit
    events of the Ticket."""
    probe = await world.open_session()
    row = (
        await probe.execute(
            select(Ticket.status, Ticket.assignee_id, Ticket.is_confidential).where(
                Ticket.id == ticket.id
            )
        )
    ).one()
    events = await ticket_events_by_id(probe, ticket.id)
    await probe.rollback()
    return (row.status, row.assignee_id, row.is_confidential), events


async def _serialize(
    world: RaceWorld,
    first: Any,
    then: Any,
    *,
    error: type[Exception] | None = None,
) -> tuple[Any, Any]:
    """Run `first(a)` uncommitted, start `then(b)` and prove it blocked by
    A, commit A, then finish and commit B (or, with `error`, expect it and
    roll B back). Returns both results (B's is the raised exception)."""
    a = await world.open_session()
    b = await world.open_session()
    first_result = await first(a)
    task = world.start(b, then(b))
    await assert_lock_wait(task, waiter=b, blocked_by=a)
    await a.commit()
    if error is not None:
        with pytest.raises(error) as raised:
            await asyncio.wait_for(task, timeout=WAIT)
        await b.rollback()
        return first_result, raised.value
    then_result = await asyncio.wait_for(task, timeout=WAIT)
    await b.commit()
    return first_result, then_result


# ---------------------------------------------------------------------------
# Explicit assignment (ticket-service.md, Architectural Test Requirement 22)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestExplicitAssignment:
    async def test_confidentiality_first_rejects_the_restricted_target(
        self, world: RaceWorld
    ) -> None:
        """The assignment waits on the Ticket lock after its target
        `FOR SHARE` and evaluates the committed confidential Ticket: the
        restricted analyst target is rejected with the `CONFIDENTIAL`
        condition and no write."""
        admin = await _va(world, "alice.va")
        assigner = await _va(world, "dave.va")
        target = await _restricted(world)
        ticket = await world.ticket(cve_id=None, status=TicketStatus.NEW)

        def assign(session: AsyncSession) -> Awaitable[Ticket]:
            return assign_ticket(
                session,
                ticket_id=ticket.id,
                assignee=str(target.id),
                acting_user_id=assigner.id,
                caller=TicketCaller.authenticated(assigner.id, Scope.ALL),
                evaluation_date=EVAL,
            )

        _, error = await _serialize(
            world,
            lambda a: _classify(a, ticket, admin),
            assign,
            error=AssigneeNotEligibleError,
        )

        assert isinstance(error, AssigneeNotEligibleError)
        assert error.condition is AssigneeIneligibility.CONFIDENTIAL
        assert await _committed(world, ticket) == (
            (TicketStatus.NEW.value, None, True),
            [_classified(admin)],
        )

    async def test_assignment_first_is_cleared_by_the_confidentiality_change(
        self, world: RaceWorld
    ) -> None:
        """Step 7 observes the committed assignment after waiting on the
        Ticket lock and clears the restricted analyst."""
        admin = await _va(world, "alice.va")
        assigner = await _va(world, "dave.va")
        target = await _restricted(world)
        ticket = await world.ticket(cve_id=None, status=TicketStatus.NEW)

        def assign(session: AsyncSession) -> Awaitable[Ticket]:
            return assign_ticket(
                session,
                ticket_id=ticket.id,
                assignee=str(target.id),
                acting_user_id=assigner.id,
                caller=TicketCaller.authenticated(assigner.id, Scope.ALL),
                evaluation_date=EVAL,
            )

        await _serialize(world, assign, lambda b: _classify(b, ticket, admin))

        assert await _committed(world, ticket) == (
            (TicketStatus.ANALYSIS.value, None, True),
            [
                assignment_event(assigner, None, target),
                PROMOTION,
                _classified(admin),
                unassigned_event(target.username, CONFIDENTIAL_TICKET),
            ],
        )


# ---------------------------------------------------------------------------
# Auto-assignment by a restricted analyst holding a grant
# ---------------------------------------------------------------------------


def _override(ticket: Ticket, actor: User) -> Any:
    def run(session: AsyncSession) -> Awaitable[Ticket]:
        return set_priority_override(
            session,
            ticket_id=ticket.id,
            priority=TicketPriority.P1,
            acting_user_id=actor.id,
            caller=_restricted_caller(actor),
            evaluation_date=EVAL,
        )

    return run


def _override_set(actor: User) -> EventRow:
    return EventRow(
        "priority_changed", actor.id, None, "P1", None, {"override_action": "set"}
    )


@pytest.mark.integration
class TestAutoAssignment:
    async def test_confidentiality_first_skips_the_auto_assignment(
        self, world: RaceWorld
    ) -> None:
        """The restricted analyst keeps working on the now-confidential
        Ticket through its grant but is not auto-assigned, so the `New`
        Ticket stays `New` (tickets.md, Architectural Invariant)."""
        admin = await _va(world, "alice.va")
        actor = await _restricted(world)
        ticket = await world.ticket(cve_id=None, status=TicketStatus.NEW)
        await world.grant(ticket, actor, admin)

        await _serialize(
            world, lambda a: _classify(a, ticket, admin), _override(ticket, actor)
        )

        assert await _committed(world, ticket) == (
            (TicketStatus.NEW.value, None, True),
            [_classified(admin), _override_set(actor)],
        )

    async def test_auto_assignment_first_is_cleared_by_the_confidentiality_change(
        self, world: RaceWorld
    ) -> None:
        admin = await _va(world, "alice.va")
        actor = await _restricted(world)
        ticket = await world.ticket(cve_id=None, status=TicketStatus.NEW)
        await world.grant(ticket, actor, admin)

        await _serialize(
            world, _override(ticket, actor), lambda b: _classify(b, ticket, admin)
        )

        assert await _committed(world, ticket) == (
            (TicketStatus.ANALYSIS.value, None, True),
            [
                assignment_event(actor, None, actor),
                PROMOTION,
                _override_set(actor),
                _classified(admin),
                unassigned_event(actor.username, CONFIDENTIAL_TICKET),
            ],
        )


# ---------------------------------------------------------------------------
# Identity batches (user-service.md, Assignment concurrent with eligibility
# loss)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRoleRemoval:
    """The assignee holds `vulnerability_analyst` and `restricted_analyst`;
    the removal of the VA origin keeps `triage_ticket` but leaves scope
    `non_confidential`."""

    async def test_confidentiality_first_lets_the_removal_clear_the_ticket(
        self, world: RaceWorld
    ) -> None:
        """The confidentiality change still observes an eligible VA and
        keeps it; the removal then waits on the Ticket lock, observes the
        committed confidential Ticket, and clears it with its own reason."""
        admin = await _va(world, "alice.va")
        assignee = await world.identity_user(
            manual=[Role.VULNERABILITY_ANALYST, Role.RESTRICTED_ANALYST],
            prefix="bob.va",
        )
        ticket = await world.ticket(cve_id=None, assignee_id=assignee.id)

        def removal(session: AsyncSession) -> Awaitable[Any]:
            return remove_roles(session, assignee, [Role.VULNERABILITY_ANALYST], admin)

        await _serialize(world, lambda a: _classify(a, ticket, admin), removal)

        assert await _committed(world, ticket) == (
            (TicketStatus.ANALYSIS.value, None, True),
            [_classified(admin), unassigned_event(assignee.username, ROLE_REMOVED)],
        )

    async def test_removal_first_lets_the_confidentiality_change_clear_the_ticket(
        self, world: RaceWorld
    ) -> None:
        """The removal locks the still non-confidential Ticket and keeps
        it; the confidentiality change waits on it, then observes the
        committed restricted-only assignee and clears it."""
        admin = await _va(world, "alice.va")
        assignee = await world.identity_user(
            manual=[Role.VULNERABILITY_ANALYST, Role.RESTRICTED_ANALYST],
            prefix="bob.va",
        )
        ticket = await world.ticket(cve_id=None, assignee_id=assignee.id)

        def removal(session: AsyncSession) -> Awaitable[Any]:
            return remove_roles(session, assignee, [Role.VULNERABILITY_ANALYST], admin)

        await _serialize(world, removal, lambda b: _classify(b, ticket, admin))

        assert await _committed(world, ticket) == (
            (TicketStatus.ANALYSIS.value, None, True),
            [
                _classified(admin),
                unassigned_event(assignee.username, CONFIDENTIAL_TICKET),
            ],
        )


@pytest.mark.integration
class TestBotMarking:
    async def test_confidentiality_first_lets_the_marking_clear_the_ticket(
        self, world: RaceWorld
    ) -> None:
        admin = await _va(world, "alice.va")
        assignee = await _va(world, "bob.va")
        ticket = await world.ticket(cve_id=None, assignee_id=assignee.id)

        await _serialize(
            world,
            lambda a: _classify(a, ticket, admin),
            lambda b: mark_bot(b, assignee, admin),
        )

        assert await _committed(world, ticket) == (
            (TicketStatus.ANALYSIS.value, None, True),
            [_classified(admin), unassigned_event(assignee.username, BOT_ACCOUNT)],
        )

    async def test_marking_first_leaves_the_confidentiality_change_no_assignee(
        self, world: RaceWorld
    ) -> None:
        admin = await _va(world, "alice.va")
        assignee = await _va(world, "bob.va")
        ticket = await world.ticket(cve_id=None, assignee_id=assignee.id)

        await _serialize(
            world,
            lambda a: mark_bot(a, assignee, admin),
            lambda b: _classify(b, ticket, admin),
        )

        assert await _committed(world, ticket) == (
            (TicketStatus.ANALYSIS.value, None, True),
            [unassigned_event(assignee.username, BOT_ACCOUNT), _classified(admin)],
        )


# ---------------------------------------------------------------------------
# Self-unassignment (ticket-service.md, Architectural Test Requirement 21)
# ---------------------------------------------------------------------------


def _self_unassign(ticket: Ticket, user: User) -> Any:
    def run(session: AsyncSession) -> Awaitable[Ticket]:
        return unassign_ticket(
            session,
            ticket_id=ticket.id,
            acting_user_id=user.id,
            caller=_restricted_caller(user),
        )

    return run


@pytest.mark.integration
class TestSelfUnassignment:
    @pytest.mark.parametrize(
        "status", [TicketStatus.ANALYSIS, TicketStatus.RESOLVED], ids=str
    )
    async def test_confidentiality_first_with_a_grant(
        self, world: RaceWorld, status: TicketStatus
    ) -> None:
        """A waiting self-unassignment of a restricted analyst that still
        sees the Ticket through its grant is a no-op for `Analysis`, whose
        assignment step 7 already cleared, and clears a `Resolved`
        assignment, which step 7 retained."""
        admin = await _va(world, "alice.va")
        assignee = await _restricted(world)
        ticket = await world.ticket(cve_id=None, status=status, assignee_id=assignee.id)
        await world.grant(ticket, assignee, admin)

        await _serialize(
            world,
            lambda a: _classify(a, ticket, admin),
            _self_unassign(ticket, assignee),
        )

        cleared_by_step_7 = status is TicketStatus.ANALYSIS
        own_clear = EventRow(
            "assignment", assignee.id, assignee.username, None, None, None
        )
        assert await _committed(world, ticket) == (
            (status.value, None, True),
            [
                _classified(admin),
                unassigned_event(assignee.username, CONFIDENTIAL_TICKET)
                if cleared_by_step_7
                else own_clear,
            ],
        )

    async def test_confidentiality_first_without_a_grant_is_not_found(
        self, world: RaceWorld
    ) -> None:
        admin = await _va(world, "alice.va")
        assignee = await _restricted(world)
        ticket = await world.ticket(cve_id=None, assignee_id=assignee.id)

        await _serialize(
            world,
            lambda a: _classify(a, ticket, admin),
            _self_unassign(ticket, assignee),
            error=TicketNotFoundError,
        )

        assert await _committed(world, ticket) == (
            (TicketStatus.ANALYSIS.value, None, True),
            [
                _classified(admin),
                unassigned_event(assignee.username, CONFIDENTIAL_TICKET),
            ],
        )

    async def test_self_unassignment_first_leaves_no_assignment_event(
        self, world: RaceWorld
    ) -> None:
        admin = await _va(world, "alice.va")
        assignee = await _restricted(world)
        ticket = await world.ticket(cve_id=None, assignee_id=assignee.id)

        await _serialize(
            world,
            _self_unassign(ticket, assignee),
            lambda b: _classify(b, ticket, admin),
        )

        assert await _committed(world, ticket) == (
            (TicketStatus.ANALYSIS.value, None, True),
            [
                EventRow(
                    "assignment", assignee.id, assignee.username, None, None, None
                ),
                _classified(admin),
            ],
        )
