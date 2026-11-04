"""Independent-session races between the real bot marking (`update_user()`
changing `bot` to `true`, backend/app/services/user_service.py) and the
assignment-capable Ticket, CVSS, and package paths, plus the bot marking
concurrent with another eligibility loss of the same User.

Owning specifications:

- docs/features/identity/user-service.md (`update_user()` steps 1 and 6;
  Concurrency Considerations: Concurrent eligibility losses, Assignment
  concurrent with eligibility loss; Private Helpers).
- docs/features/identity/rbac.md (Business Rule 10: a bot account is never
  eligible; prospective and retroactive enforcement).
- docs/features/tickets/ticket-audit-log.md (Canonical Automatic Comment
  Vocabulary: `bot account`; Testing Requirement 19).
- docs/features/platform/testing-strategy.md (User Lifecycle and
  Management: assignment-first and eligibility-loss-first commit orders for
  bot marking; Concurrency Testing, Lock-Wait Observation).

The matrix takes the same representative per assignment category and
owning service as the role-loss and deactivation matrices, each in both
commit orders. The lifecycle writer is always the real `update_user()`
marking the target as a bot account, never a simulated lock. In the
assignment-first order the assignment path holds its uncommitted
assignment and the User `FOR SHARE` in session A; the bot marking in
session B is proven to wait on A with the User `FOR NO KEY UPDATE` as its
only statement, and after both commit the batch has cleared the assignment
with exactly one system event (`bot account`). In the marking-first order
B's uncommitted marking, which finds nothing to clear, holds the User; A is
proven to wait on B at its User `FOR SHARE` before touching any CVE or
Ticket row, and after B commits A decides from the committed bot account:
explicit assignment raises `AssigneeNotEligibleError` with no write, and
every other path skips the assignment while keeping its ordinary effects.

Committed state is always read through a fresh independent session and
committed rows are deleted explicitly at teardown (testing-strategy.md,
Concurrency Testing). Expected values are transcribed from the
specifications, never computed with the module under test.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable

import pytest
from sqlalchemy import select
from sqlalchemy import update as sql_update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import PackageStatus, Role, TicketStatus
from app.models.ticket import Ticket
from app.models.user import User
from app.services.assignment_eligibility import AssigneeIneligibility
from app.services.ticket_service import AssigneeNotEligibleError
from app.services.user_service import UserUpdateResult
from tests.support.assignment_lifecycle_races import (
    GATE,
    PROMOTION,
    REOPENED,
    WAIT,
    Actors,
    CommittedRace,
    Factory,
    Path,
    RaceWorld,
    assign_path,
    assignment_event,
    assignment_first,
    committed_track_status,
    create_path,
    is_user_lock,
    lifecycle_first,
    open_track_ticket,
    other_va,
    override_path,
    override_set_event,
    race_actors,
    race_world,
    read_committed,
    reopen_path,
    severity_path,
    severity_set_event,
    track_changed_event,
    track_status_path,
)
from tests.support.cvss_chain import priority_event
from tests.support.database import assert_lock_wait
from tests.support.identity_lifecycle_races import (
    BOT_ACCOUNT,
    ROLE_REMOVED,
    bot_changed,
    mark_bot,
    remove_roles,
    role_removed,
)
from tests.support.suse_cvss_races import SessionStatementRecorder
from tests.support.ticket_creation import creation_events
from tests.support.ticket_mutations import EventRow, unassigned_event

VA_WIRE = "vulnerability_analyst"


@pytest.fixture
async def world(db_session_factory: Factory) -> AsyncIterator[RaceWorld]:
    async with race_world(db_session_factory) as created:
        yield created


# ---------------------------------------------------------------------------
# The lifecycle writer: bot marking
# ---------------------------------------------------------------------------


def _marking(actors: Actors) -> Callable[[AsyncSession], Awaitable[UserUpdateResult]]:
    """The real `update_user()` marking the target as a bot account, by the
    admin."""

    def run(session: AsyncSession) -> Awaitable[UserUpdateResult]:
        return mark_bot(session, actors.target, actors.admin)

    return run


async def _assignment_first(world: RaceWorld, actors: Actors, path: Path) -> uuid.UUID:
    ticket_id, result = await assignment_first(world, path, _marking(actors))
    assert result.changed_fields == ["bot"]
    return ticket_id


async def _marking_first(
    world: RaceWorld,
    actors: Actors,
    path: Path,
    *,
    error: type[Exception] | None = None,
) -> uuid.UUID | None:
    ticket_id, result = await lifecycle_first(
        world, path, _marking(actors), error=error
    )
    assert result.changed_fields == ["bot"]
    return ticket_id


async def _committed_bot(world: RaceWorld, user: User) -> bool:
    probe = await world.open_session()
    bot = (await probe.execute(select(User.bot).where(User.id == user.id))).scalar_one()
    await probe.rollback()
    return bot


async def _assert_marked(
    world: RaceWorld, committed: CommittedRace, actors: Actors
) -> None:
    """The committed marking: the target is a bot account, keeps its role,
    and its Identity trail holds exactly one `bot_changed`."""
    assert await _committed_bot(world, actors.target) is True
    assert committed.origins == {(Role.VULNERABILITY_ANALYST.value, "_manual")}
    assert committed.identity == [bot_changed(actors.admin, actors.target)]


def _cleared(actors: Actors, reason: str = BOT_ACCOUNT) -> EventRow:
    return unassigned_event(actors.target.username, reason)


# ---------------------------------------------------------------------------
# Explicit assignment: assign_ticket()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestExplicitAssignment:
    async def test_assignment_first_is_cleared_by_the_marking(
        self, world: RaceWorld
    ) -> None:
        actors = await race_actors(world)
        assigner = await other_va(world, "carol.va")
        ticket = await world.ticket(cve_id=None, status=TicketStatus.NEW)

        await _assignment_first(
            world, actors, assign_path(ticket, actors.target, assigner)
        )

        committed = await read_committed(world, actors, ticket.id)
        assert committed.ticket == (TicketStatus.ANALYSIS, None, None, None, None)
        assert committed.events == [
            assignment_event(assigner, None, actors.target),
            PROMOTION,
            _cleared(actors),
        ]
        assert committed.unassignments == [ticket.id]
        await _assert_marked(world, committed, actors)

    async def test_marking_first_rejects_the_bot_target_without_effect(
        self, world: RaceWorld
    ) -> None:
        actors = await race_actors(world)
        assigner = await other_va(world, "carol.va")
        ticket = await world.ticket(cve_id=None, status=TicketStatus.NEW)

        await _marking_first(
            world,
            actors,
            assign_path(ticket, actors.target, assigner),
            error=AssigneeNotEligibleError,
        )

        committed = await read_committed(world, actors, ticket.id)
        assert committed.ticket == (TicketStatus.NEW, None, None, None, None)
        assert committed.events == []
        assert committed.unassignments == []
        await _assert_marked(world, committed, actors)


# ---------------------------------------------------------------------------
# Creation assignment: manual create_ticket()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCreationAssignment:
    async def test_assignment_first_is_cleared_by_the_marking(
        self, world: RaceWorld
    ) -> None:
        actors = await race_actors(world)

        ticket_id = await _assignment_first(world, actors, create_path(actors.target))

        committed = await read_committed(world, actors, ticket_id)
        assert committed.ticket == (TicketStatus.ANALYSIS, None, None, None, None)
        assert committed.events == [
            *creation_events(
                creator_id=actors.target.id, assignee_username=actors.target.username
            ),
            _cleared(actors),
        ]
        assert committed.unassignments == [ticket_id]
        await _assert_marked(world, committed, actors)

    async def test_marking_first_creates_new_and_unassigned(
        self, world: RaceWorld
    ) -> None:
        actors = await race_actors(world)

        ticket_id = await _marking_first(world, actors, create_path(actors.target))

        assert ticket_id is not None
        committed = await read_committed(world, actors, ticket_id)
        assert committed.ticket == (TicketStatus.NEW, None, None, None, None)
        assert committed.events == creation_events(creator_id=actors.target.id)
        assert committed.unassignments == []
        await _assert_marked(world, committed, actors)


# ---------------------------------------------------------------------------
# Auto-assignment: set_priority_override(), set_severity_manual(),
# set_track_status()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestPriorityOverrideAutoAssignment:
    async def test_assignment_first_is_cleared_by_the_marking(
        self, world: RaceWorld
    ) -> None:
        actors = await race_actors(world)
        ticket = await world.ticket(cve_id=None, status=TicketStatus.NEW)

        await _assignment_first(world, actors, override_path(ticket, actors.target))

        committed = await read_committed(world, actors, ticket.id)
        assert committed.ticket == (TicketStatus.ANALYSIS, None, None, "P1", None)
        assert committed.events == [
            assignment_event(actors.target, None, actors.target),
            PROMOTION,
            override_set_event(actors.target),
            _cleared(actors),
        ]
        assert committed.unassignments == [ticket.id]
        await _assert_marked(world, committed, actors)

    async def test_marking_first_sets_the_override_and_the_ticket_stays_new(
        self, world: RaceWorld
    ) -> None:
        """tickets.md, Architectural Invariant: a `New` Ticket that only a
        bot account works on stays `New`."""
        actors = await race_actors(world)
        ticket = await world.ticket(cve_id=None, status=TicketStatus.NEW)

        await _marking_first(world, actors, override_path(ticket, actors.target))

        committed = await read_committed(world, actors, ticket.id)
        assert committed.ticket == (TicketStatus.NEW, None, None, "P1", None)
        assert committed.events == [override_set_event(actors.target)]
        assert committed.unassignments == []
        await _assert_marked(world, committed, actors)


@pytest.mark.integration
class TestSeverityAutoAssignment:
    async def test_assignment_first_is_cleared_by_the_marking(
        self, world: RaceWorld
    ) -> None:
        actors = await race_actors(world)
        ticket = await world.ticket(cve_id=None)

        await _assignment_first(world, actors, severity_path(ticket, actors.target))

        committed = await read_committed(world, actors, ticket.id)
        assert committed.ticket == (TicketStatus.ANALYSIS, None, "P3", None, "High")
        assert committed.events == [
            assignment_event(actors.target, None, actors.target),
            severity_set_event(actors.target),
            priority_event(None, "P3"),
            _cleared(actors),
        ]
        assert committed.unassignments == [ticket.id]
        await _assert_marked(world, committed, actors)

    async def test_marking_first_sets_the_severity_without_assignment(
        self, world: RaceWorld
    ) -> None:
        actors = await race_actors(world)
        ticket = await world.ticket(cve_id=None)

        await _marking_first(world, actors, severity_path(ticket, actors.target))

        committed = await read_committed(world, actors, ticket.id)
        assert committed.ticket == (TicketStatus.ANALYSIS, None, "P3", None, "High")
        assert committed.events == [
            severity_set_event(actors.target),
            priority_event(None, "P3"),
        ]
        assert committed.unassignments == []
        await _assert_marked(world, committed, actors)


@pytest.mark.integration
class TestTrackStatusAutoAssignment:
    async def test_assignment_first_is_cleared_by_the_marking(
        self, world: RaceWorld
    ) -> None:
        actors = await race_actors(world)
        ticket, track = await open_track_ticket(world)

        await _assignment_first(
            world, actors, track_status_path(ticket, track, actors.target)
        )

        committed = await read_committed(world, actors, ticket.id)
        assert committed.ticket == (TicketStatus.ANALYZED, None, None, None, "High")
        assert committed.events == [
            assignment_event(actors.target, None, actors.target),
            track_changed_event(track, actors.target),
            GATE,
            _cleared(actors),
        ]
        assert committed.unassignments == [ticket.id]
        assert await committed_track_status(world, track) == PackageStatus.AFFECTED
        await _assert_marked(world, committed, actors)

    async def test_marking_first_changes_the_track_without_assignment(
        self, world: RaceWorld
    ) -> None:
        actors = await race_actors(world)
        ticket, track = await open_track_ticket(world)

        await _marking_first(
            world, actors, track_status_path(ticket, track, actors.target)
        )

        committed = await read_committed(world, actors, ticket.id)
        assert committed.ticket == (TicketStatus.ANALYZED, None, None, None, "High")
        assert committed.events == [track_changed_event(track, actors.target), GATE]
        assert committed.unassignments == []
        assert await committed_track_status(world, track) == PackageStatus.AFFECTED
        await _assert_marked(world, committed, actors)


# ---------------------------------------------------------------------------
# Embedded assignment: reopen_from_ignored()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestReopenEmbeddedAssignment:
    async def test_assignment_first_is_cleared_by_the_marking(
        self, world: RaceWorld
    ) -> None:
        await world.ensure_default_setting()
        actors = await race_actors(world)
        previous = await other_va(world, "dave.va")
        ticket = await world.ticket(
            cve_id=None, status=TicketStatus.IGNORED, assignee_id=previous.id
        )

        await _assignment_first(world, actors, reopen_path(ticket, actors.target))

        committed = await read_committed(world, actors, ticket.id)
        assert committed.ticket == (TicketStatus.ANALYSIS, None, None, None, None)
        assert committed.events == [
            assignment_event(actors.target, previous, actors.target),
            REOPENED,
            _cleared(actors),
        ]
        assert committed.unassignments == [ticket.id]
        await _assert_marked(world, committed, actors)

    async def test_marking_first_reopens_and_keeps_the_previous_assignee(
        self, world: RaceWorld
    ) -> None:
        await world.ensure_default_setting()
        actors = await race_actors(world)
        previous = await other_va(world, "dave.va")
        ticket = await world.ticket(
            cve_id=None, status=TicketStatus.IGNORED, assignee_id=previous.id
        )

        await _marking_first(world, actors, reopen_path(ticket, actors.target))

        committed = await read_committed(world, actors, ticket.id)
        assert committed.ticket == (
            TicketStatus.ANALYSIS,
            previous.id,
            None,
            None,
            None,
        )
        assert committed.events == [REOPENED]
        assert committed.unassignments == []
        await _assert_marked(world, committed, actors)


# ---------------------------------------------------------------------------
# Concurrent eligibility losses (user-service.md)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestConcurrentEligibilityLosses:
    async def test_marking_and_role_removal_serialize_with_one_clear(
        self, world: RaceWorld
    ) -> None:
        """user-service.md, Concurrent eligibility losses: the marking and
        the removal of the target's only role serialize on the User lock.
        The first to commit clears the assignment; the second finds it no
        longer assigned to the User and creates no duplicate event."""
        actors = await race_actors(world)
        ticket = await world.ticket(cve_id=None, assignee_id=actors.target.id)
        a = await world.open_session()
        b = await world.open_session()

        marking = await mark_bot(a, actors.target, actors.admin)
        assert marking.changed_fields == ["bot"]
        with SessionStatementRecorder(b) as recorder:
            task = world.start(
                b,
                remove_roles(
                    b, actors.target, [Role.VULNERABILITY_ANALYST], actors.admin
                ),
            )
            await assert_lock_wait(task, waiter=b, blocked_by=a)
            assert [is_user_lock(s) for s in recorder.statements] == [True]
            await a.commit()
            removal = await asyncio.wait_for(task, timeout=WAIT)
        await b.commit()

        assert removal.removed_roles == [Role.VULNERABILITY_ANALYST]
        assert [w for w in recorder.writes() if "UPDATE ticket " in w] == []
        committed = await read_committed(world, actors, ticket.id)
        assert committed.ticket == (TicketStatus.ANALYSIS, None, None, None, None)
        assert committed.events == [_cleared(actors)]
        assert committed.unassignments == [ticket.id]
        assert committed.origins == set()
        assert committed.identity == [
            bot_changed(actors.admin, actors.target),
            role_removed(actors.admin, actors.target, VA_WIRE),
        ]

    async def test_role_removal_first_leaves_the_marking_nothing_to_clear(
        self, world: RaceWorld
    ) -> None:
        actors = await race_actors(world)
        ticket = await world.ticket(cve_id=None, assignee_id=actors.target.id)
        a = await world.open_session()
        b = await world.open_session()

        await remove_roles(a, actors.target, [Role.VULNERABILITY_ANALYST], actors.admin)
        with SessionStatementRecorder(b) as recorder:
            task = world.start(b, mark_bot(b, actors.target, actors.admin))
            await assert_lock_wait(task, waiter=b, blocked_by=a)
            await a.commit()
            marking = await asyncio.wait_for(task, timeout=WAIT)
        await b.commit()

        assert marking.changed_fields == ["bot"]
        assert [w for w in recorder.writes() if "ticket" in w] == []
        committed = await read_committed(world, actors, ticket.id)
        assert committed.events == [_cleared(actors, ROLE_REMOVED)]
        assert committed.unassignments == [ticket.id]


@pytest.mark.integration
class TestEligibilityConditionOfTheRejection:
    async def test_marking_first_rejection_names_the_bot_condition(
        self, world: RaceWorld
    ) -> None:
        """ticket-service.md, `assign_ticket` step 5: the waiter rejects
        the committed bot account with the `BOT` condition."""
        actors = await race_actors(world)
        assigner = await other_va(world, "carol.va")
        ticket = await world.ticket(cve_id=None, status=TicketStatus.NEW)
        a = await world.open_session()
        b = await world.open_session()

        await mark_bot(b, actors.target, actors.admin)
        task = world.start(a, assign_path(ticket, actors.target, assigner)(a))
        await assert_lock_wait(task, waiter=a, blocked_by=b)
        await b.commit()
        with pytest.raises(AssigneeNotEligibleError) as raised:
            await asyncio.wait_for(task, timeout=WAIT)
        await a.rollback()

        assert raised.value.condition is AssigneeIneligibility.BOT


# ---------------------------------------------------------------------------
# Ticket locks before the User write (user-service.md, `update_user()`
# step 6; docs/conventions.md, Cross-Domain Root Lock Order)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestUpdateUserTicketLockOrder:
    async def test_marking_with_an_email_change_does_not_deadlock(
        self, world: RaceWorld
    ) -> None:
        """Session A holds the target's Ticket and writes it again, which
        revalidates its `assignee_id` foreign key to the User (`FOR KEY
        SHARE`). Session B marks the target as a bot account and changes
        its `email`: it locks the User `FOR NO KEY UPDATE`, which is
        compatible with A's foreign-key check, and waits for the Ticket
        before it writes the unique `email` column. A's revalidation
        therefore completes while B waits, and both commit without
        deadlock; B then clears the assignment A committed, recording the
        username before its update."""
        actors = await race_actors(world)
        ticket = await world.ticket(cve_id=None, assignee_id=actors.target.id)
        a = await world.open_session()
        b = await world.open_session()

        await a.execute(
            select(Ticket.id).where(Ticket.id == ticket.id).with_for_update()
        )
        await a.execute(
            sql_update(Ticket).where(Ticket.id == ticket.id).values(assignee_id=None)
        )
        with SessionStatementRecorder(b) as recorder:
            task = world.start(
                b,
                mark_bot(
                    b, actors.target, actors.admin, email="bob.scanner@example.com"
                ),
            )
            await assert_lock_wait(task, waiter=b, blocked_by=a)
            assert recorder.statements[0].rstrip().endswith("FOR NO KEY UPDATE")
            assert [s for s in recorder.writes() if 'UPDATE "user"' in s] == []
            # The foreign-key revalidation of A does not wait on B.
            await asyncio.wait_for(
                a.execute(
                    sql_update(Ticket)
                    .where(Ticket.id == ticket.id)
                    .values(assignee_id=actors.target.id)
                ),
                timeout=WAIT,
            )
            await a.commit()
            result = await asyncio.wait_for(task, timeout=WAIT)
        await b.commit()

        assert result.changed_fields == ["email", "bot"]
        committed = await read_committed(world, actors, ticket.id)
        assert committed.ticket[:2] == (TicketStatus.ANALYSIS, None)
        assert committed.events == [_cleared(actors)]
        probe = await world.open_session()
        email = (
            await probe.execute(select(User.email).where(User.id == actors.target.id))
        ).scalar_one()
        await probe.rollback()
        assert email == "bob.scanner@example.com"
