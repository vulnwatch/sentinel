"""Independent-session race tests for the CNA auto-ignore policy: the
administrative change of `CNA.auto_ignore` (`cna_service.set_cna_auto_ignore()`)
and its application by `cve_service.upsert_cve()` through
`ticket_service.ignore_new_for_cna_policy()`.

Owning specifications:

- docs/features/tickets/cna.md (`set_cna_auto_ignore()` Q3; Concurrency:
  the reads of `auto_ignore` by an ingestion, the `FOR NO KEY UPDATE` of
  Set CNA Auto-Ignore, the foreign-key `FOR KEY SHARE` that does not
  conflict with it, and the operations that acquire CNA rows; Testing
  Requirements, item 4 (a policy change committed concurrently with an
  ingestion, in both commit orders; a user's assignment or ignore
  concurrent with the policy ignore, in both commit orders) and item 5
  (two concurrent equal requests create one event)).
- docs/features/tickets/cve-service.md (Complete `upsert_cve()`
  Composition, steps 4, 5, and 7c).
- docs/features/tickets/ticket-service.md (`ignore_new_for_cna_policy()`;
  `assign_ticket`, `ignore_ticket`).
- docs/conventions.md (Cross-Domain Root Lock Order: the CNA row after the
  CVE root, before the Ticket roots).
- docs/features/platform/testing-strategy.md (Concurrency Testing and
  Lock-Wait Observation).

Every race keeps the holder's transaction open after its call returns,
proves the waiter blocked by the holder with `assert_lock_wait()` (never a
sleep), releases the holder, and waits for the waiter with a bounded wait;
an operation that must not wait completes while the holder still holds its
lock. Committed rows are deleted at teardown by `IngestionWorld`, the CNA
rows and their audit events once no CVE references them; each test uses
fresh fictional CVE-IDs and organization UUIDs.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Coroutine
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    CVESourceType,
    CveState,
    Role,
    Scope,
    TicketIgnoreReason,
    TicketStatus,
)
from app.core.exceptions import TicketNotMutableError
from app.models.cna import CNA
from app.models.cna_audit_event import CNAAuditEvent
from app.models.cve import CVE
from app.models.ticket import Ticket
from app.models.user import User
from app.services import cna_service, cve_service, ticket_service
from app.services.cve_ingest import CNAEntry, CVEIngestPayload, UpsertResult
from app.services.ticket_visibility import TicketCaller
from tests.support.cve_ingest import IngestionWorld, is_root_lock, tickets_of
from tests.support.database import assert_lock_wait
from tests.support.suse_cvss_races import SessionStatementRecorder
from tests.support.ticket_mutations import EVAL, EventRow, ticket_events_by_id

SessionFactory = Callable[[], Awaitable[AsyncSession]]

MITRE = CVESourceType.MITRE
NVD = CVESourceType.NVD
OLD = datetime(2022, 1, 1, tzinfo=UTC)
NEW = datetime(2026, 1, 1, tzinfo=UTC)
WAIT = 5
"""Upper bound, in seconds, of every wait that is expected to finish."""

POLICY = EventRow(
    "status_change",
    None,
    TicketStatus.NEW.value,
    TicketStatus.IGNORED.value,
    "CNA auto-ignore policy",
    {"ignore_reason": "cna_policy"},
)
"""The exact system event of the policy (cna.md, When the Policy Applies)."""


@pytest.fixture
async def world(db_session_factory: SessionFactory) -> AsyncIterator[IngestionWorld]:
    created = IngestionWorld(db_session_factory, await db_session_factory())
    try:
        created.probe = await created.open_session()
        await created.ensure_default_setting()
        yield created
    finally:
        await created.cleanup()


async def _observe[T](
    world: IngestionWorld, read: Callable[[AsyncSession], Awaitable[T]]
) -> T:
    """Read committed state through the probe, then end its transaction."""
    try:
        return await read(world.probe)
    finally:
        await world.probe.rollback()


async def _cna(
    world: IngestionWorld, *, auto_ignore: bool, short_name: str = "example"
) -> CNA:
    """A committed CNA row with a dated short name; deleted at teardown
    once no CVE references it."""
    cna = CNA(
        org_id=uuid.uuid4(),
        short_name=short_name,
        short_name_observed_at=OLD,
        auto_ignore=auto_ignore,
    )
    world.session.add(cna)
    await world.session.commit()
    return cna


def _owner(cna: CNA, *, short_name: str | None = None) -> CVEIngestPayload:
    """A published record of `cna`. Without `short_name` the resolution
    writes nothing to the row; a different, newer short name is an
    effective write, which locks the row."""
    return CVEIngestPayload(
        cve_state=CveState.PUBLISHED,
        cna=CNAEntry(
            org_id=cna.org_id,
            short_name=short_name,
            short_name_observed_at=NEW if short_name is not None else None,
        ),
    )


def _set(
    db: AsyncSession, cna: CNA, admin: User, value: bool
) -> Coroutine[Any, Any, CNA]:
    return cna_service.set_cna_auto_ignore(
        db, org_id=str(cna.org_id), auto_ignore=value, acting_user_id=admin.id
    )


def _ingest(
    db: AsyncSession,
    cve_id: str,
    payload: CVEIngestPayload,
    *,
    source: CVESourceType = MITRE,
) -> Coroutine[Any, Any, UpsertResult]:
    return cve_service.upsert_cve(db, cve_id, source, payload)


async def _status_and_reason(
    db: AsyncSession, ticket_id: uuid.UUID
) -> tuple[str, str | None]:
    row = (
        await db.execute(
            select(Ticket.status, Ticket.ignore_reason).where(Ticket.id == ticket_id)
        )
    ).one()
    return row[0], row[1]


async def _ticket_of(world: IngestionWorld, cve_id: str) -> uuid.UUID:
    [ticket_id] = await _observe(world, lambda s: tickets_of(s, cve_id))
    world.ticket_ids.append(ticket_id)
    return ticket_id


async def _committed_policy(
    world: IngestionWorld, cna: CNA
) -> tuple[bool, list[tuple[str, uuid.UUID | None]]]:
    """The committed `auto_ignore` of `cna` and its audit events, oldest
    first, as `(event_type, user_id)`."""

    async def read(db: AsyncSession) -> tuple[bool, list[tuple[str, Any]]]:
        flag = await db.scalar(select(CNA.auto_ignore).where(CNA.id == cna.id))
        events = await db.execute(
            select(CNAAuditEvent.event_type, CNAAuditEvent.user_id)
            .where(CNAAuditEvent.cna_id == cna.id)
            .order_by(CNAAuditEvent.id)
        )
        assert flag is not None
        return flag, [(row[0], row[1]) for row in events]

    return await _observe(world, read)


# ---------------------------------------------------------------------------
# Policy change and ingestion (cna.md, Concurrency, first bullet)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestPolicyChangeAndIngestion:
    async def test_ingestion_does_not_wait_for_an_uncommitted_change(
        self, world: IngestionWorld
    ) -> None:
        """Ingestion first: the change holds the CNA row `FOR NO KEY
        UPDATE`; an ingestion that writes nothing to the row completes
        without waiting, including the foreign-key check of its new CVE,
        and reads the committed `false`. After the change commits, a later
        ingestion applies it."""
        admin = await world.user(role=Role.ADMIN)
        cna = await _cna(world, auto_ignore=False)
        changer = await world.open_session()
        ingester = await world.open_session()
        later = await world.open_session()
        first_id, second_id = world.new_cve_id(), world.new_cve_id()

        await _set(changer, cna, admin, True)
        result = await asyncio.wait_for(
            world.start(ingester, _ingest(ingester, first_id, _owner(cna))),
            timeout=WAIT,
        )
        await ingester.commit()
        await changer.commit()
        await _ingest(later, second_id, _owner(cna))
        await later.commit()

        first = await _ticket_of(world, first_id)
        second = await _ticket_of(world, second_id)
        assert result.ticket.id == first
        assert await _observe(world, lambda s: _status_and_reason(s, first)) == (
            "New",
            None,
        )
        assert await _observe(world, lambda s: _status_and_reason(s, second)) == (
            "Ignored",
            "cna_policy",
        )
        assert await _committed_policy(world, cna) == (
            True,
            [("auto_ignore_enabled", admin.id)],
        )

    async def test_change_committed_after_the_ingestion_read_alters_nothing(
        self, world: IngestionWorld
    ) -> None:
        """Change committed first: the ingestion has already read `false`
        and still holds its CVE and Ticket; the change neither waits for it
        nor alters its decision, and commits before the ingestion. That a
        later ingestion applies the change is proven by
        `test_ingestion_does_not_wait_for_an_uncommitted_change`."""
        admin = await world.user(role=Role.ADMIN)
        cna = await _cna(world, auto_ignore=False)
        ingester = await world.open_session()
        changer = await world.open_session()
        cve_id = world.new_cve_id()

        await _ingest(ingester, cve_id, _owner(cna))
        await asyncio.wait_for(
            world.start(changer, _set(changer, cna, admin, True)), timeout=WAIT
        )
        await changer.commit()
        await ingester.commit()

        ticket_id = await _ticket_of(world, cve_id)
        assert await _observe(world, lambda s: _status_and_reason(s, ticket_id)) == (
            "New",
            None,
        )
        assert (await _committed_policy(world, cna))[0] is True

    @pytest.mark.parametrize("outcome", ["commit", "rollback"])
    async def test_short_name_write_waits_and_applies_the_committed_value(
        self, world: IngestionWorld, outcome: str
    ) -> None:
        """An ingestion that changes the short name writes the CNA row, so
        it waits for the uncommitted change; it then reads the row as
        committed: `true` ignores its new Ticket, a rolled-back change
        leaves it `New`."""
        admin = await world.user(role=Role.ADMIN)
        cna = await _cna(world, auto_ignore=False)
        changer = await world.open_session()
        ingester = await world.open_session()
        cve_id = world.new_cve_id()

        await _set(changer, cna, admin, True)
        task = world.start(
            ingester, _ingest(ingester, cve_id, _owner(cna, short_name="renamed"))
        )
        await assert_lock_wait(task, waiter=ingester, blocked_by=changer)
        if outcome == "commit":
            await changer.commit()
        else:
            await changer.rollback()
        await asyncio.wait_for(task, timeout=WAIT)
        await ingester.commit()

        ticket_id = await _ticket_of(world, cve_id)
        assert await _observe(world, lambda s: _status_and_reason(s, ticket_id)) == (
            ("Ignored", "cna_policy") if outcome == "commit" else ("New", None)
        )

    async def test_change_waits_for_a_short_name_write(
        self, world: IngestionWorld
    ) -> None:
        """The ingestion holds the CNA row after its effective short-name
        write; the change waits for it, then classifies against the
        committed `false` and records its event. The Ticket that the
        ingestion created stays `New`."""
        admin = await world.user(role=Role.ADMIN)
        cna = await _cna(world, auto_ignore=False)
        ingester = await world.open_session()
        changer = await world.open_session()
        cve_id = world.new_cve_id()

        await _ingest(ingester, cve_id, _owner(cna, short_name="renamed"))
        task = world.start(changer, _set(changer, cna, admin, True))
        await assert_lock_wait(task, waiter=changer, blocked_by=ingester)
        await ingester.commit()
        changed = await asyncio.wait_for(task, timeout=WAIT)
        await changer.commit()

        assert changed.auto_ignore is True
        ticket_id = await _ticket_of(world, cve_id)
        assert await _observe(world, lambda s: _status_and_reason(s, ticket_id)) == (
            "New",
            None,
        )
        assert await _committed_policy(world, cna) == (
            True,
            [("auto_ignore_enabled", admin.id)],
        )

    async def test_reused_ingestion_session_reads_a_change_committed_meanwhile(
        self, world: IngestionWorld
    ) -> None:
        """A fetcher ingests every record of a run in one session whose
        objects survive each commit. A change committed between two
        ingestions applies to the second, although the session still holds
        the CNA row that it read for the first (Flag: a change applies to
        the ingestions that read it after its commit)."""
        admin = await world.user(role=Role.ADMIN)
        cna = await _cna(world, auto_ignore=False)
        ingester = await world.open_session()
        changer = await world.open_session()
        first_id, second_id = world.new_cve_id(), world.new_cve_id()

        await _ingest(ingester, first_id, _owner(cna))
        await ingester.commit()
        held = await ingester.get(CNA, cna.id)
        assert held is not None
        assert held.auto_ignore is False
        await _set(changer, cna, admin, True)
        await changer.commit()
        await _ingest(ingester, second_id, _owner(cna))
        await ingester.commit()

        first = await _ticket_of(world, first_id)
        second = await _ticket_of(world, second_id)
        assert await _observe(world, lambda s: _status_and_reason(s, first)) == (
            "New",
            None,
        )
        assert await _observe(world, lambda s: _status_and_reason(s, second)) == (
            "Ignored",
            "cna_policy",
        )

    async def test_read_of_the_recorded_cna_does_not_wait(
        self, world: IngestionWorld
    ) -> None:
        """A source that omits `cna` reads the `auto_ignore` of the recorded
        CNA without a lock: it re-tickets the orphan while an uncommitted
        disable holds the row, from the committed `true`."""
        admin = await world.user(role=Role.ADMIN)
        cna = await _cna(world, auto_ignore=True)
        cve = await world.cve_in()
        cve.cna_id = cna.id
        await world.session.commit()
        changer = await world.open_session()
        ingester = await world.open_session()

        await _set(changer, cna, admin, False)
        await asyncio.wait_for(
            world.start(
                ingester,
                _ingest(ingester, cve.cve_id, CVEIngestPayload(), source=NVD),
            ),
            timeout=WAIT,
        )
        await ingester.commit()
        await changer.commit()

        ticket_id = await _ticket_of(world, cve.cve_id)
        assert await _observe(world, lambda s: _status_and_reason(s, ticket_id)) == (
            "Ignored",
            "cna_policy",
        )
        assert (await _committed_policy(world, cna))[0] is False


# ---------------------------------------------------------------------------
# A user's assignment or ignore and the policy ignore of the same Ticket
# (cna.md, Testing Requirements, item 4)
# ---------------------------------------------------------------------------


def _user_operation(
    operation: str, db: AsyncSession, ticket_id: uuid.UUID, actor: User
) -> Coroutine[Any, Any, Ticket]:
    caller = TicketCaller.authenticated(actor.id, Scope.ALL)
    if operation == "assign":
        return ticket_service.assign_ticket(
            db,
            ticket_id=ticket_id,
            assignee=actor.username,
            acting_user_id=actor.id,
            caller=caller,
            evaluation_date=EVAL,
        )
    return ticket_service.ignore_ticket(
        db,
        ticket_id=ticket_id,
        acting_user_id=actor.id,
        caller=caller,
        reason=TicketIgnoreReason.NOT_SHIPPED,
    )


def _user_events(operation: str, actor: User) -> list[EventRow]:
    """The events of the user's operation on an unassigned `New` Ticket:
    the assignment and its system promotion, then, for the ignore, the
    acting-user `Analysis -> Ignored`."""
    events = [
        EventRow("assignment", actor.id, None, actor.username, None, None),
        EventRow("status_change", None, "New", "Analysis", None, None),
    ]
    if operation == "ignore":
        events.append(
            EventRow(
                "status_change",
                actor.id,
                "Analysis",
                "Ignored",
                None,
                {"ignore_reason": "not_shipped"},
            )
        )
    return events


@pytest.mark.integration
class TestUserOperationAndPolicy:
    async def _new_ticket(self, world: IngestionWorld) -> tuple[CVE, Ticket, CNA]:
        cna = await _cna(world, auto_ignore=True)
        cve = await world.cve_in()
        ticket = await world.ticket(cve_id=cve.id, status=TicketStatus.NEW)
        return cve, ticket, cna

    @pytest.mark.parametrize("operation", ["assign", "ignore"])
    async def test_policy_waiting_for_the_user_is_a_no_op(
        self, world: IngestionWorld, operation: str
    ) -> None:
        """The user holds the Ticket; the ingestion that records the CNA
        locks the CVE, waits for the Ticket, and then leaves the Ticket
        that is no longer `New` unchanged."""
        actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        cve, ticket, cna = await self._new_ticket(world)
        user = await world.open_session()
        ingester = await world.open_session()

        await _user_operation(operation, user, ticket.id, actor)
        with SessionStatementRecorder(ingester) as recorder:
            task = world.start(ingester, _ingest(ingester, cve.cve_id, _owner(cna)))
            await assert_lock_wait(task, waiter=ingester, blocked_by=user)
            assert is_root_lock(recorder.statements[-1], "ticket")
            await user.commit()
            await asyncio.wait_for(task, timeout=WAIT)
            await ingester.commit()

        expected = (
            ("Analysis", None) if operation == "assign" else ("Ignored", "not_shipped")
        )
        assert await _observe(world, lambda s: _status_and_reason(s, ticket.id)) == (
            expected
        )
        assert await _observe(world, lambda s: ticket_events_by_id(s, ticket.id)) == (
            _user_events(operation, actor)
        )

    @pytest.mark.parametrize("operation", ["assign", "ignore"])
    async def test_user_waiting_for_the_policy_is_not_mutable(
        self, world: IngestionWorld, operation: str
    ) -> None:
        """The ingestion holds the CVE and the Ticket it ignored; the user
        waits for the Ticket and then receives `TICKET_NOT_MUTABLE` with no
        effect."""
        actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        cve, ticket, cna = await self._new_ticket(world)
        ingester = await world.open_session()
        user = await world.open_session()

        await _ingest(ingester, cve.cve_id, _owner(cna))
        task = world.start(user, _user_operation(operation, user, ticket.id, actor))
        await assert_lock_wait(task, waiter=user, blocked_by=ingester)
        await ingester.commit()
        with pytest.raises(TicketNotMutableError):
            await asyncio.wait_for(task, timeout=WAIT)
        await user.rollback()

        assert await _observe(world, lambda s: _status_and_reason(s, ticket.id)) == (
            "Ignored",
            "cna_policy",
        )
        assert await _observe(world, lambda s: ticket_events_by_id(s, ticket.id)) == [
            POLICY
        ]


# ---------------------------------------------------------------------------
# Concurrent administrative changes (cna.md, `set_cna_auto_ignore()` Q3;
# Testing Requirements, item 5)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestConcurrentChanges:
    async def test_two_equal_requests_create_one_event(
        self, world: IngestionWorld
    ) -> None:
        """The second request waits for the row lock of the first, then
        observes `true` under the lock and is a no-op."""
        first_admin = await world.user(role=Role.ADMIN)
        second_admin = await world.user(role=Role.ADMIN)
        cna = await _cna(world, auto_ignore=False)
        first = await world.open_session()
        second = await world.open_session()

        await _set(first, cna, first_admin, True)
        task = world.start(second, _set(second, cna, second_admin, True))
        await assert_lock_wait(task, waiter=second, blocked_by=first)
        await first.commit()
        result = await asyncio.wait_for(task, timeout=WAIT)
        await second.commit()

        assert result.auto_ignore is True
        assert await _committed_policy(world, cna) == (
            True,
            [("auto_ignore_enabled", first_admin.id)],
        )

    async def test_opposite_requests_serialize_on_the_row(
        self, world: IngestionWorld
    ) -> None:
        """The waiting disable classifies against the committed enable and
        records its own event after it."""
        first_admin = await world.user(role=Role.ADMIN)
        second_admin = await world.user(role=Role.ADMIN)
        cna = await _cna(world, auto_ignore=False)
        first = await world.open_session()
        second = await world.open_session()

        await _set(first, cna, first_admin, True)
        task = world.start(second, _set(second, cna, second_admin, False))
        await assert_lock_wait(task, waiter=second, blocked_by=first)
        await first.commit()
        result = await asyncio.wait_for(task, timeout=WAIT)
        await second.commit()

        assert result.auto_ignore is False
        assert await _committed_policy(world, cna) == (
            False,
            [
                ("auto_ignore_enabled", first_admin.id),
                ("auto_ignore_disabled", second_admin.id),
            ],
        )
