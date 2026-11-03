"""Independent-session tests for `unassign_ticket()`
(backend/app/services/ticket_service.py).

Owning specifications:

- docs/features/tickets/ticket-service.md (Caller category and Ticket
  accessibility; Concurrency control; `unassign_ticket` Locking and
  Concurrency; Architectural Test Requirement 21, independent-session part).
- docs/features/identity/user-service.md (`_unassign_active_tickets()`:
  every assigned Ticket is locked whatever its status, and the
  locked-current assignee is revalidated).
- docs/conventions.md (Transaction and Locking: Cross-Domain Root Lock
  Order; a path that only clears the caller's own assignment acquires no
  User root, while the foreign-key `FOR KEY SHARE` of its audit insert is
  compatible with `FOR NO KEY UPDATE`).
- docs/features/tickets/ticket-audit-log.md (Canonical Automatic Comment
  Vocabulary: `user deactivated`; Testing Requirements 19 and 23).
- docs/features/platform/testing-strategy.md (Concurrency Testing,
  Lock-Wait Observation; Service Functions: lock serialization; Ticket
  Accessibility: Locked mutations).

The single-session behavior is covered by
`tests/test_services/test_unassign_ticket.py`; this module adds only what
needs independent sessions. The deactivation races use the real
`deactivate_user()` of the caller by an administrator.

Committed rows are deleted explicitly at teardown (testing-strategy.md,
Concurrency Testing). Expected values are transcribed from the
specifications, never computed with the module under test.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator
from typing import Any

import pytest
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import Role, Scope, TicketStatus
from app.core.exceptions import TicketNotFoundError
from app.core.identifiers import format_ticket_id
from app.models.ticket import Ticket
from app.models.user import User
from app.services import ticket_mutations, ticket_service
from app.services.ticket_service import (
    AssigneeNotCallerError,
    assign_ticket,
    resolve_ticket_locator,
    unassign_ticket,
)
from app.services.ticket_visibility import TicketCaller
from tests.support.assignment_lifecycle_races import (
    WAIT,
    Factory,
    RaceWorld,
    assignment_event,
    race_actors,
    race_world,
    read_committed,
)
from tests.support.database import assert_lock_wait
from tests.support.identity_lifecycle_races import (
    USER_DEACTIVATED,
    deactivate,
    user_deactivated,
)
from tests.support.suse_cvss_races import SessionStatementRecorder, prepare_loss
from tests.support.ticket_mutations import (
    EVAL,
    EventRow,
    ticket_events_by_id,
    unassigned_event,
)

REASON = "fictional offboarding"
"""The caller-supplied deactivation reason (Identity context only)."""


@pytest.fixture
async def world(db_session_factory: Factory) -> AsyncIterator[RaceWorld]:
    async with race_world(db_session_factory) as created:
        yield created


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _self_unassignment(actor: User) -> EventRow:
    """The acting-user `assignment` event of a self-unassignment."""
    return EventRow("assignment", actor.id, actor.username, None, None, None)


async def _unassign(
    session: AsyncSession, ticket: Ticket, actor: User, *, scope: Scope = Scope.ALL
) -> Ticket:
    return await unassign_ticket(
        session,
        ticket_id=ticket.id,
        acting_user_id=actor.id,
        caller=TicketCaller.authenticated(actor.id, scope),
    )


async def _committed(
    world: RaceWorld, ticket: Ticket
) -> tuple[tuple[str, uuid.UUID | None], list[EventRow]]:
    """The committed `(status, assignee_id)` and events of a Ticket, read
    through a fresh independent session."""
    probe = await world.open_session()
    row = (
        await probe.execute(
            select(Ticket.status, Ticket.assignee_id).where(Ticket.id == ticket.id)
        )
    ).one()
    events = await ticket_events_by_id(probe, ticket.id)
    await probe.rollback()
    return (row.status, row.assignee_id), events


def _is_ticket_lock(statement: str) -> bool:
    return "FROM ticket" in statement and statement.rstrip().endswith("FOR UPDATE")


# ---------------------------------------------------------------------------
# Ticket lock serialization (Service Functions; audit Testing Requirement 23)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestTicketLockSerialization:
    async def test_waiting_self_unassignment_loses_to_a_committed_reassignment(
        self, world: RaceWorld
    ) -> None:
        """B reassigns the caller's Ticket to X and holds the Ticket lock
        uncommitted; A's self-unassignment blocks on it. After B commits, A
        observes X as the locked-current assignee and raises
        `AssigneeNotCallerError` without a write."""
        caller = await world.user(role=Role.VULNERABILITY_ANALYST)
        assigner = await world.user(role=Role.VULNERABILITY_ANALYST)
        x = await world.user(role=Role.VULNERABILITY_ANALYST)
        ticket = await world.ticket(cve_id=None, assignee_id=caller.id)
        a = await world.open_session()
        b = await world.open_session()

        await assign_ticket(
            b,
            ticket_id=ticket.id,
            assignee=str(x.id),
            acting_user_id=assigner.id,
            caller=TicketCaller.authenticated(assigner.id, Scope.ALL),
            evaluation_date=EVAL,
        )
        with SessionStatementRecorder(a) as recorder:
            task = world.start(a, _unassign(a, ticket, caller))
            await assert_lock_wait(task, waiter=a, blocked_by=b)
            assert _is_ticket_lock(recorder.statements[0])
            await b.commit()
            with pytest.raises(AssigneeNotCallerError):
                await asyncio.wait_for(task, timeout=WAIT)

        assert recorder.writes() == []
        await a.rollback()
        assert await _committed(world, ticket) == (
            (TicketStatus.ANALYSIS, x.id),
            [assignment_event(assigner, caller, x)],
        )

    async def test_concurrent_self_unassignments_create_one_event(
        self, world: RaceWorld
    ) -> None:
        """The waiter observes the winner's committed clear and is the
        idempotent no-op."""
        caller = await world.user(role=Role.VULNERABILITY_ANALYST)
        ticket = await world.ticket(cve_id=None, assignee_id=caller.id)
        a = await world.open_session()
        b = await world.open_session()

        await _unassign(b, ticket, caller)
        with SessionStatementRecorder(a) as recorder:
            task = world.start(a, _unassign(a, ticket, caller))
            await assert_lock_wait(task, waiter=a, blocked_by=b)
            await b.commit()
            result = await asyncio.wait_for(task, timeout=WAIT)

        assert result.assignee_id is None
        assert recorder.writes() == []
        await a.commit()
        assert await _committed(world, ticket) == (
            (TicketStatus.ANALYSIS, None),
            [_self_unassignment(caller)],
        )


# ---------------------------------------------------------------------------
# No User root (conventions.md, Cross-Domain Root Lock Order)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestNoUserLock:
    async def test_completes_while_the_caller_is_held_for_no_key_update(
        self, world: RaceWorld
    ) -> None:
        """B holds the caller's User row `FOR NO KEY UPDATE` and writes
        `active = false`, as a lifecycle writer does. A `FOR SHARE` or `FOR
        UPDATE` User lock would conflict with it; the audit insert's
        foreign-key `FOR KEY SHARE` does not. A therefore completes and
        commits while B still holds the lock."""
        caller = await world.user(role=Role.VULNERABILITY_ANALYST)
        ticket = await world.ticket(cve_id=None, assignee_id=caller.id)
        a = await world.open_session()
        b = await world.open_session()

        await b.execute(
            select(User.id).where(User.id == caller.id).with_for_update(key_share=True)
        )
        await b.execute(update(User).where(User.id == caller.id).values(active=False))
        task = world.start(a, _unassign(a, ticket, caller))
        await asyncio.wait_for(task, timeout=WAIT)
        await asyncio.wait_for(a.commit(), timeout=WAIT)
        await b.rollback()

        assert await _committed(world, ticket) == (
            (TicketStatus.ANALYSIS, None),
            [_self_unassignment(caller)],
        )


# ---------------------------------------------------------------------------
# Races with the real deactivation of the caller
# ---------------------------------------------------------------------------


def _system_clear(user: User) -> EventRow:
    """The deactivation's system unassignment of `user`."""
    return unassigned_event(user.username, USER_DEACTIVATED)


@pytest.mark.integration
class TestDeactivationRaces:
    @pytest.mark.parametrize(
        ("status", "expected_events", "batch_clears"),
        [
            # The batch clears an active-status assignment; the waiter is a
            # no-op.
            pytest.param(TicketStatus.ANALYSIS, "system", True, id="analysis"),
            # The batch preserves `Resolved`; the waiter clears it.
            pytest.param(TicketStatus.RESOLVED, "self", False, id="resolved"),
        ],
    )
    async def test_waiter_decides_from_the_committed_deactivation(
        self,
        world: RaceWorld,
        status: TicketStatus,
        expected_events: str,
        batch_clears: bool,
    ) -> None:
        """B's real deactivation of the caller locks every Ticket assigned to
        the caller, whatever its status, and stays uncommitted; A's
        self-unassignment blocks on the Ticket lock and, after B commits,
        decides from the locked-current assignee."""
        actors = await race_actors(world)
        ticket = await world.ticket(
            cve_id=None, status=status, assignee_id=actors.target.id
        )
        a = await world.open_session()
        b = await world.open_session()

        result = await deactivate(b, actors.target, REASON, actors.admin)
        assert result.deactivated is True
        with SessionStatementRecorder(a) as recorder:
            task = world.start(a, _unassign(a, ticket, actors.target))
            await assert_lock_wait(task, waiter=a, blocked_by=b)
            await b.commit()
            outcome = await asyncio.wait_for(task, timeout=WAIT)

        assert outcome.assignee_id is None
        assert (recorder.writes() == []) is batch_clears
        await a.commit()
        committed = await read_committed(world, actors, ticket.id)
        assert committed.ticket == (status, None, None, None, None)
        assert committed.events == (
            [_system_clear(actors.target)]
            if expected_events == "system"
            else [_self_unassignment(actors.target)]
        )
        assert committed.unassignments == ([ticket.id] if batch_clears else [])
        assert committed.active is False
        assert committed.identity == [
            user_deactivated(actors.admin, actors.target, REASON)
        ]

    async def test_self_unassignment_holding_the_ticket_does_not_deadlock(
        self, world: RaceWorld, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A holds the Ticket lock and pauses before its username read and
        audit insert. B's real deactivation of the caller then takes the User
        `FOR NO KEY UPDATE` and blocks on that Ticket. A resumes and inserts
        its event while B holds the User lock: a User lock taken by A after
        the Ticket lock would deadlock here. Both commit, and the batch,
        which revalidates the locked-current assignee, creates no system
        `assignment` event for the Ticket."""
        actors = await race_actors(world)
        ticket = await world.ticket(cve_id=None, assignee_id=actors.target.id)
        a = await world.open_session()
        b = await world.open_session()
        locked = asyncio.Event()
        resume = asyncio.Event()
        original = ticket_mutations.lock_accessible_ticket

        async def pausing_lock(*args: Any) -> Ticket:
            # Pauses after the Ticket lock and the accessibility check,
            # before any User statement of the operation.
            locked_ticket = await original(*args)
            locked.set()
            await resume.wait()
            return locked_ticket

        monkeypatch.setattr(ticket_service, "lock_accessible_ticket", pausing_lock)
        unassign_task = world.start(a, _unassign(a, ticket, actors.target))
        await asyncio.wait_for(locked.wait(), timeout=WAIT)
        with SessionStatementRecorder(b) as recorder:
            deactivation = world.start(
                b, deactivate(b, actors.target, REASON, actors.admin)
            )
            await assert_lock_wait(deactivation, waiter=b, blocked_by=a)
            assert _is_ticket_lock(recorder.statements[-1])
            resume.set()
            await asyncio.wait_for(unassign_task, timeout=WAIT)
            await asyncio.wait_for(a.commit(), timeout=WAIT)
            result = await asyncio.wait_for(deactivation, timeout=WAIT)
        await b.commit()

        assert result.deactivated is True
        committed = await read_committed(world, actors, ticket.id)
        assert committed.ticket == (TicketStatus.ANALYSIS, None, None, None, None)
        assert committed.events == [_self_unassignment(actors.target)]
        assert committed.unassignments == []
        assert committed.active is False


# ---------------------------------------------------------------------------
# ATR 21 / 15: locked-current accessibility
# ---------------------------------------------------------------------------


LOSSES = ["confidentiality-set", "grant-revoked", "last-package-excluded"]


@pytest.mark.integration
class TestLockedCurrentAccessibilityRaces:
    @pytest.mark.parametrize("loss", LOSSES)
    async def test_visibility_lost_while_waiting_for_the_lock_is_not_found(
        self, world: RaceWorld, loss: str
    ) -> None:
        """A passes the preliminary locator check; B then holds the Ticket
        `FOR UPDATE` and removes A's only visibility path. A is proven
        blocked on the Ticket lock, B commits, and A is denied from the
        locked-current state before the idempotent no-op of the unassigned
        Ticket (testing-strategy.md, Ticket Accessibility: Locked
        mutations)."""
        user, _cve, ticket, statements = await prepare_loss(world, loss)
        a = await world.open_session()
        b = await world.open_session()
        caller = TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL)

        resolved = await resolve_ticket_locator(
            a, format_ticket_id(ticket.sequence_id), caller
        )
        assert resolved.id == ticket.id
        for statement in statements:
            await b.execute(statement)
        with SessionStatementRecorder(a) as recorder:
            task = world.start(
                a, _unassign(a, ticket, user, scope=Scope.NON_CONFIDENTIAL)
            )
            await assert_lock_wait(task, waiter=a, blocked_by=b)
            assert _is_ticket_lock(recorder.statements[-1])
            await b.commit()
            with pytest.raises(TicketNotFoundError):
                await asyncio.wait_for(task, timeout=WAIT)

        assert recorder.writes() == []
        await a.rollback()
        assert await _committed(world, ticket) == ((TicketStatus.ANALYSIS, None), [])
