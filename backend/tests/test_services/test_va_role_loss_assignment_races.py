"""Independent-session races between the real final manual
`vulnerability_analyst` origin loss (`update_roles()`,
backend/app/services/user_service.py) and the assignment-capable Ticket,
CVSS, and package paths.

Owning specifications:

- docs/features/identity/user-service.md (Concurrency Considerations:
  Assignment concurrent with eligibility loss;
  `update_roles()`; Private Helpers).
- docs/features/identity/rbac.md (Business Rule 10, Assignment target
  constraint: prospective and retroactive enforcement).
- docs/features/tickets/ticket-audit-log.md (Canonical Automatic Comment
  Vocabulary; Canonical Mutation and No-Event Matrix; Cross-Event Ordering,
  Locking, and Rollback; Testing Requirements 19 and 23).
- docs/features/platform/testing-strategy.md (User Lifecycle and
  Management: every assignment-capable path acquires User `FOR SHARE`
  before CVE/Ticket locks; final VA-origin removal concurrent with
  assignment; Concurrency Testing, Lock-Wait Observation).
- The counterparts' owning contracts: docs/features/tickets/ticket-service.md
  (Concurrency control; `create_ticket`; `assign_ticket`;
  `set_priority_override`; `reopen_from_ignored()`),
  docs/features/tickets/ticket-priority.md (`set_priority_override()`),
  docs/features/tickets/ticket-mutations.md (`set_severity_manual()`;
  Auto-Assignment Rule; `auto_assign_actor()`), and
  docs/features/packages/package-service.md (Auto-Assignment Rule;
  `set_track_status()`).

The matrix takes one representative per assignment category and owning
service, each in both commit orders (twelve cases):

| Category | Representative | Owner |
|---|---|---|
| explicit | `assign_ticket()` (target loses VA) | `ticket_service` |
| creation | manual `create_ticket()` | `ticket_service` |
| auto-assignment | `set_priority_override()` | `ticket_service` |
| auto-assignment | `set_severity_manual()` | `ticket_mutations` |
| auto-assignment | `set_track_status()` | `package_service` |
| embedded | `reopen_from_ignored()` (`force=True`) | `ticket_service` |

The lifecycle writer is always the real `update_roles()` removing the
User's only (`_manual`) VA origin, never a simulated lock. In the
assignment-first order the assignment path holds its uncommitted
assignment and the User `FOR SHARE` in session A; the role loss in session
B is proven to wait on A with the User lock as its only statement, and
after both commit the lifecycle batch has cleared the assignment with
exactly one system event. In the role-loss-first order B's uncommitted
role loss, which finds nothing to clear, holds the User
`FOR NO KEY UPDATE`; A is proven to wait on B at its User `FOR SHARE`
before touching any CVE or Ticket row, and after B commits A decides from
the committed ineligible User: explicit assignment raises its existing
target error with no write, and every other path skips the assignment
without an `assignment` event while keeping its ordinary effects.

The writer-independent world, drivers, observations, and path builders are
shared with the deactivation matrix through
`tests/support/assignment_lifecycle_races.py`.

Committed state is always read through a fresh independent session.
Committed rows, including service-created Tickets and the committed
`default_cvss_version` setting, are deleted explicitly at teardown
(testing-strategy.md, Concurrency Testing). Expected values are
transcribed from the specifications, never computed with the module under
test.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import PackageStatus, Role, TicketStatus
from app.services.ticket_service import AssigneeNotEligibleError
from app.services.user_service import RoleUpdateResult
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
    ROLE_REMOVED,
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
# The lifecycle writer: final manual VA-origin loss
# ---------------------------------------------------------------------------


def _role_loss(
    actors: Actors,
) -> Callable[[AsyncSession], Awaitable[RoleUpdateResult]]:
    """The real `update_roles()` removing the target's only (`_manual`) VA
    origin, by the admin."""

    def run(session: AsyncSession) -> Awaitable[RoleUpdateResult]:
        return remove_roles(
            session, actors.target, [Role.VULNERABILITY_ANALYST], actors.admin
        )

    return run


async def _assignment_first(world: RaceWorld, actors: Actors, path: Path) -> uuid.UUID:
    """`assignment_first()` with the real final VA-origin removal as B,
    which removes exactly the VA role. Returns the Ticket UUID of `path`."""
    ticket_id, removal = await assignment_first(world, path, _role_loss(actors))
    assert removal.removed_roles == [Role.VULNERABILITY_ANALYST]
    return ticket_id


async def _role_loss_first(
    world: RaceWorld,
    actors: Actors,
    path: Path,
    *,
    error: type[Exception] | None = None,
) -> uuid.UUID | None:
    """`lifecycle_first()` with the real final VA-origin removal as B, which
    removes exactly the VA role. Returns the Ticket UUID of `path`, or
    `None` when it raised `error`."""
    ticket_id, removal = await lifecycle_first(
        world, path, _role_loss(actors), error=error
    )
    assert removal.removed_roles == [Role.VULNERABILITY_ANALYST]
    return ticket_id


def _assert_role_lost(committed: CommittedRace, actors: Actors) -> None:
    """The committed final manual VA-origin loss: no origin remains and the
    Identity trail holds exactly one `role_removed`."""
    assert committed.origins == set()
    assert committed.identity == [role_removed(actors.admin, actors.target, VA_WIRE)]


def _cleared(actors: Actors) -> EventRow:
    """The lifecycle batch's system unassignment of the target."""
    return unassigned_event(actors.target.username, ROLE_REMOVED)


# ---------------------------------------------------------------------------
# Explicit assignment: assign_ticket()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestExplicitAssignment:
    """Another VA assigns an unassigned CVE-less `New` Ticket to the User
    who loses the role (ticket-service.md, `assign_ticket`: target User
    `FOR SHARE`, then Ticket)."""

    async def test_assignment_first_is_cleared_by_the_lifecycle_batch(
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
        _assert_role_lost(committed, actors)

    async def test_role_loss_first_raises_the_target_error_without_effect(
        self, world: RaceWorld
    ) -> None:
        actors = await race_actors(world)
        assigner = await other_va(world, "carol.va")
        ticket = await world.ticket(cve_id=None, status=TicketStatus.NEW)

        await _role_loss_first(
            world,
            actors,
            assign_path(ticket, actors.target, assigner),
            error=AssigneeNotEligibleError,
        )

        committed = await read_committed(world, actors, ticket.id)
        assert committed.ticket == (TicketStatus.NEW, None, None, None, None)
        assert committed.events == []
        assert committed.unassignments == []
        _assert_role_lost(committed, actors)


# ---------------------------------------------------------------------------
# Creation assignment: manual create_ticket()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCreationAssignment:
    """The User who loses the role manually creates a CVE-less Ticket
    without severity (ticket-service.md, `create_ticket` steps 1 and 4-6:
    creator `FOR SHARE`, then INSERT; no automatic priority)."""

    async def test_assignment_first_is_cleared_by_the_lifecycle_batch(
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
        _assert_role_lost(committed, actors)

    async def test_role_loss_first_creates_new_and_unassigned(
        self, world: RaceWorld
    ) -> None:
        actors = await race_actors(world)

        ticket_id = await _role_loss_first(world, actors, create_path(actors.target))

        assert ticket_id is not None
        committed = await read_committed(world, actors, ticket_id)
        assert committed.ticket == (TicketStatus.NEW, None, None, None, None)
        assert committed.events == creation_events(creator_id=actors.target.id)
        assert committed.unassignments == []
        _assert_role_lost(committed, actors)


# ---------------------------------------------------------------------------
# Auto-assignment (ticket_service): set_priority_override()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestPriorityOverrideAutoAssignment:
    """The User who loses the role sets a `P1` override on an unassigned
    CVE-less `New` Ticket without severity (ticket-priority.md,
    `set_priority_override()`: acting User `FOR SHARE`, then Ticket)."""

    async def test_assignment_first_is_cleared_by_the_lifecycle_batch(
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
        _assert_role_lost(committed, actors)

    async def test_role_loss_first_sets_the_override_without_assignment(
        self, world: RaceWorld
    ) -> None:
        """No assignment, hence no promotion: the Ticket stays `New`
        (reconciliation never leaves `New`)."""
        actors = await race_actors(world)
        ticket = await world.ticket(cve_id=None, status=TicketStatus.NEW)

        await _role_loss_first(world, actors, override_path(ticket, actors.target))

        committed = await read_committed(world, actors, ticket.id)
        assert committed.ticket == (TicketStatus.NEW, None, None, "P1", None)
        assert committed.events == [override_set_event(actors.target)]
        assert committed.unassignments == []
        _assert_role_lost(committed, actors)


# ---------------------------------------------------------------------------
# Auto-assignment (ticket_mutations): set_severity_manual()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestSeverityAutoAssignment:
    """The User who loses the role sets `High` on an unassigned CVE-less
    `Analysis` Ticket without severity or packages (ticket-mutations.md,
    `set_severity_manual()`: acting User `FOR SHARE`, then Ticket; the
    refresh moves `priority_auto` to `P3`; no gate change)."""

    async def test_assignment_first_is_cleared_by_the_lifecycle_batch(
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
        _assert_role_lost(committed, actors)

    async def test_role_loss_first_sets_the_severity_without_assignment(
        self, world: RaceWorld
    ) -> None:
        actors = await race_actors(world)
        ticket = await world.ticket(cve_id=None)

        await _role_loss_first(world, actors, severity_path(ticket, actors.target))

        committed = await read_committed(world, actors, ticket.id)
        assert committed.ticket == (TicketStatus.ANALYSIS, None, "P3", None, "High")
        assert committed.events == [
            severity_set_event(actors.target),
            priority_event(None, "P3"),
        ]
        assert committed.unassignments == []
        _assert_role_lost(committed, actors)


# ---------------------------------------------------------------------------
# Auto-assignment (package_service): set_track_status()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestTrackStatusAutoAssignment:
    """The User who loses the role sets the only track `AFFECTED`
    (package-service.md, `set_track_status()`: acting User `FOR SHARE`,
    then Ticket; the gate result becomes `Analyzed`)."""

    async def test_assignment_first_is_cleared_by_the_lifecycle_batch(
        self, world: RaceWorld
    ) -> None:
        actors = await race_actors(world)
        ticket, track = await open_track_ticket(world)

        await _assignment_first(
            world, actors, track_status_path(ticket, track, actors.target)
        )

        committed = await read_committed(world, actors, ticket.id)
        # The lifecycle batch clears the assignee only: `Analyzed` remains.
        assert committed.ticket == (TicketStatus.ANALYZED, None, None, None, "High")
        assert committed.events == [
            assignment_event(actors.target, None, actors.target),
            track_changed_event(track, actors.target),
            GATE,
            _cleared(actors),
        ]
        assert committed.unassignments == [ticket.id]
        assert await committed_track_status(world, track) == PackageStatus.AFFECTED
        _assert_role_lost(committed, actors)

    async def test_role_loss_first_changes_the_track_without_assignment(
        self, world: RaceWorld
    ) -> None:
        actors = await race_actors(world)
        ticket, track = await open_track_ticket(world)

        await _role_loss_first(
            world, actors, track_status_path(ticket, track, actors.target)
        )

        committed = await read_committed(world, actors, ticket.id)
        assert committed.ticket == (TicketStatus.ANALYZED, None, None, None, "High")
        assert committed.events == [track_changed_event(track, actors.target), GATE]
        assert committed.unassignments == []
        assert await committed_track_status(world, track) == PackageStatus.AFFECTED
        _assert_role_lost(committed, actors)


# ---------------------------------------------------------------------------
# Embedded assignment: reopen_from_ignored()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestReopenEmbeddedAssignment:
    """The User who loses the role reopens a CVE-less `Ignored` Ticket
    without severity or packages that is assigned to another active VA
    (ticket-service.md, `reopen_from_ignored()`: acting User `FOR SHARE`,
    then Ticket; `auto_assign_actor(force=True)` takes ownership only for an
    eligible actor, so a skip keeps the other assignee)."""

    async def test_assignment_first_is_cleared_by_the_lifecycle_batch(
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
        _assert_role_lost(committed, actors)

    async def test_role_loss_first_reopens_and_keeps_the_previous_assignee(
        self, world: RaceWorld
    ) -> None:
        await world.ensure_default_setting()
        actors = await race_actors(world)
        previous = await other_va(world, "dave.va")
        ticket = await world.ticket(
            cve_id=None, status=TicketStatus.IGNORED, assignee_id=previous.id
        )

        await _role_loss_first(world, actors, reopen_path(ticket, actors.target))

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
        _assert_role_lost(committed, actors)


# ---------------------------------------------------------------------------
# Loss of scope `all` while `triage_ticket` remains
# ---------------------------------------------------------------------------


async def _scope_loss_actors(world: RaceWorld) -> Actors:
    """The admin and a target holding `_manual` VA and restricted analyst
    origins: removing the VA origin keeps `triage_ticket` but leaves scope
    `non_confidential` (rbac.md, Business Rule 10)."""
    return Actors(
        admin=await world.identity_user(manual=[Role.ADMIN], prefix="alice.admin"),
        target=await world.identity_user(
            manual=[Role.VULNERABILITY_ANALYST, Role.RESTRICTED_ANALYST],
            prefix="bob.va",
        ),
    )


def _assert_scope_lost(committed: CommittedRace, actors: Actors) -> None:
    assert committed.origins == {(Role.RESTRICTED_ANALYST.value, "_manual")}
    assert committed.identity == [role_removed(actors.admin, actors.target, VA_WIRE)]


@pytest.mark.integration
class TestScopeLossWithRemainingTriage:
    """rbac.md, Business Rule 10 and user-service.md,
    `_unassign_ineligible_tickets()`: the removal decides each assigned
    Ticket from its locked-current confidentiality."""

    async def test_confidential_assignment_first_is_cleared_by_the_removal(
        self, world: RaceWorld
    ) -> None:
        actors = await _scope_loss_actors(world)
        assigner = await other_va(world, "carol.va")
        ticket = await world.ticket(
            cve_id=None, status=TicketStatus.NEW, is_confidential=True
        )

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
        _assert_scope_lost(committed, actors)

    async def test_removal_first_rejects_the_confidential_assignment(
        self, world: RaceWorld
    ) -> None:
        actors = await _scope_loss_actors(world)
        assigner = await other_va(world, "carol.va")
        ticket = await world.ticket(
            cve_id=None, status=TicketStatus.NEW, is_confidential=True
        )

        await _role_loss_first(
            world,
            actors,
            assign_path(ticket, actors.target, assigner),
            error=AssigneeNotEligibleError,
        )

        committed = await read_committed(world, actors, ticket.id)
        assert committed.ticket == (TicketStatus.NEW, None, None, None, None)
        assert committed.events == []
        assert committed.unassignments == []
        _assert_scope_lost(committed, actors)

    async def test_non_confidential_assignment_first_survives_the_removal(
        self, world: RaceWorld
    ) -> None:
        """The removal waits for the assignment's User `FOR SHARE`, then
        locks the committed assigned Ticket and keeps it: the remaining
        restricted analyst role is eligible for a non-confidential
        Ticket."""
        actors = await _scope_loss_actors(world)
        assigner = await other_va(world, "carol.va")
        ticket = await world.ticket(cve_id=None, status=TicketStatus.NEW)
        a = await world.open_session()
        b = await world.open_session()

        await assign_path(ticket, actors.target, assigner)(a)
        with SessionStatementRecorder(b) as recorder:
            task = world.start(b, _role_loss(actors)(b))
            await assert_lock_wait(task, waiter=b, blocked_by=a)
            await a.commit()
            removal = await asyncio.wait_for(task, timeout=WAIT)
        await b.commit()

        assert removal.removed_roles == [Role.VULNERABILITY_ANALYST]
        assert [w for w in recorder.writes() if "UPDATE ticket " in w] == []
        assert len([s for s in recorder.row_locks() if "FROM ticket" in s]) == 1
        committed = await read_committed(world, actors, ticket.id)
        assert committed.ticket == (
            TicketStatus.ANALYSIS,
            actors.target.id,
            None,
            None,
            None,
        )
        assert committed.events == [
            assignment_event(assigner, None, actors.target),
            PROMOTION,
        ]
        assert committed.unassignments == []
        _assert_scope_lost(committed, actors)
