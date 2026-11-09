"""Independent-session race tests for the CNA row of an ingested record
(backend/app/services/cna_service.py, `resolve_ingested_cna()`, composed by
`cve_service.upsert_cve()`).

Owning specifications: docs/features/tickets/cna.md (`resolve_ingested_cna()`
Q3 and Locking; Concurrency; Short Name; Testing Requirements, item 3:
concurrent first ingestions of two CVEs of a new CNA create one row and
commit both CVEs), docs/features/tickets/cve-service.md (Concurrency > CVE
Upsert Serialization: CNA row), and docs/conventions.md (Cross-Domain Root
Lock Order: the CNA row after the CVE root, before the Ticket root).

Every race keeps the holder's transaction open, proves the waiter blocked by
the holder with `assert_lock_wait()` (never a sleep), releases the holder,
and waits for the waiter with a bounded wait; a resolution that must not
wait completes while the holder still holds its lock. Committed rows are
deleted at teardown by `IngestionWorld`, the CNA rows once no CVE references
them; each test uses fresh fictional CVE-IDs and organization UUIDs.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import CVESourceType, CveState
from app.models.cna import CNA
from app.models.cve import CVE
from app.services import cve_service
from app.services.cna_service import resolve_ingested_cna
from app.services.cve_ingest import CNAEntry, CVEIngestPayload, UpsertAction
from tests.support.cve_ingest import IngestionWorld, root_lock_order
from tests.support.database import assert_lock_wait
from tests.support.suse_cvss_races import SessionStatementRecorder

SessionFactory = Callable[[], Awaitable[AsyncSession]]

MITRE = CVESourceType.MITRE
KERNEL = CVESourceType.KERNEL
OLD = datetime(2022, 1, 1, tzinfo=UTC)
MID = datetime(2024, 1, 1, tzinfo=UTC)
NEW = datetime(2026, 1, 1, tzinfo=UTC)
NEWER = datetime(2026, 6, 1, tzinfo=UTC)
WAIT = 5
"""Upper bound, in seconds, of every wait that is expected to finish."""


@pytest.fixture
async def world(db_session_factory: SessionFactory) -> AsyncIterator[IngestionWorld]:
    created = IngestionWorld(db_session_factory, await db_session_factory())
    try:
        created.probe = await created.open_session()
        await created.ensure_default_setting()
        yield created
    finally:
        await created.cleanup()


def _payload(org_id: uuid.UUID, short_name: str = "example") -> CVEIngestPayload:
    return CVEIngestPayload(
        cve_state=CveState.PUBLISHED,
        cna=CNAEntry(org_id=org_id, short_name=short_name, short_name_observed_at=NEW),
    )


async def _committed_cna(
    world: IngestionWorld, org_id: uuid.UUID
) -> list[tuple[uuid.UUID, str | None, datetime | None]]:
    """`(id, short_name, short_name_observed_at)` of each committed row."""
    try:
        rows = await world.probe.execute(
            select(CNA.id, CNA.short_name, CNA.short_name_observed_at).where(
                CNA.org_id == org_id
            )
        )
        return [(row[0], row[1], row[2]) for row in rows.all()]
    finally:
        await world.probe.rollback()


async def _cna_ids_of(world: IngestionWorld, *cve_ids: str) -> list[uuid.UUID | None]:
    try:
        rows = await world.probe.execute(
            select(CVE.cve_id, CVE.cna_id).where(CVE.cve_id.in_(cve_ids))
        )
        by_id: dict[str, uuid.UUID | None] = {
            str(cve_id): cna_id for cve_id, cna_id in rows.all()
        }
        return [by_id[cve_id] for cve_id in cve_ids]
    finally:
        await world.probe.rollback()


async def _seed_cna(
    world: IngestionWorld, short_name: str | None, date: datetime | None
) -> uuid.UUID:
    """A committed CNA row, deleted at teardown (it has no CVE)."""
    org_id = uuid.uuid4()
    world.session.add(
        CNA(org_id=org_id, short_name=short_name, short_name_observed_at=date)
    )
    await world.session.commit()
    return org_id


def _entry(
    org_id: uuid.UUID, short_name: str | None, date: datetime | None
) -> CNAEntry:
    return CNAEntry(org_id=org_id, short_name=short_name, short_name_observed_at=date)


@pytest.mark.integration
class TestConcurrentFirstIngestions:
    @pytest.mark.parametrize("holder_outcome", ["commit", "rollback"])
    async def test_two_cves_of_a_new_cna_create_one_row_and_both_commit(
        self, world: IngestionWorld, holder_outcome: str
    ) -> None:
        """The second creation waits for the uncommitted first one, then uses
        its committed row; when the first rolls back, the second creates the
        row. Neither raises a unique violation, and both transactions stay
        usable."""
        org_id = uuid.uuid4()
        first_id, second_id = world.new_cve_id(), world.new_cve_id()
        a = await world.open_session()
        b = await world.open_session()

        first = await cve_service.upsert_cve(a, first_id, MITRE, _payload(org_id))
        first_cna = first.cve.cna_id
        task = world.start(
            b, cve_service.upsert_cve(b, second_id, KERNEL, _payload(org_id))
        )
        await assert_lock_wait(task, waiter=b, blocked_by=a)
        if holder_outcome == "commit":
            await a.commit()
        else:
            await a.rollback()
        second = await asyncio.wait_for(task, timeout=WAIT)
        second_cna, second_action = second.cve.cna_id, second.action
        await b.commit()

        rows = await _committed_cna(world, org_id)
        assert len(rows) == 1
        assert second_action is UpsertAction.CREATED
        assert second_cna == rows[0][0]
        if holder_outcome == "commit":
            assert first_cna == rows[0][0]
            assert await _cna_ids_of(world, first_id, second_id) == [
                rows[0][0],
                rows[0][0],
            ]
        else:
            assert await _cna_ids_of(world, second_id) == [rows[0][0]]

    async def test_cna_row_is_acquired_after_the_cve_root_and_before_the_ticket(
        self, world: IngestionWorld
    ) -> None:
        cve_id = world.new_cve_id()
        session = await world.open_session()

        with SessionStatementRecorder(session) as recorder:
            await cve_service.upsert_cve(session, cve_id, MITRE, _payload(uuid.uuid4()))
        await session.commit()

        statements = recorder.statements
        cve_lock = next(
            i for i, s in enumerate(statements) if s.endswith("FOR NO KEY UPDATE")
        )
        cna_insert = next(
            i for i, s in enumerate(statements) if s.startswith("INSERT INTO cna ")
        )
        ticket_lock = next(
            i
            for i, s in enumerate(statements)
            if s.startswith("SELECT ticket.") and s.endswith("FOR UPDATE")
        )
        assert cve_lock < cna_insert < ticket_lock
        assert root_lock_order(statements) == ["cve", "ticket"]


@pytest.mark.integration
class TestShortNameWrites:
    @pytest.mark.parametrize(
        "entry",
        [
            pytest.param(("old", OLD), id="same-dated"),
            pytest.param((None, None), id="no-short-name"),
            pytest.param(("other", MID), id="older-than-stored"),
        ],
    )
    async def test_ineffective_resolution_neither_writes_nor_waits(
        self, world: IngestionWorld, entry: tuple[str | None, datetime | None]
    ) -> None:
        """Ingestions of one CNA serialize only on a creation or an
        effective short-name change: a resolution that changes nothing does
        not wait for a concurrent short-name writer."""
        org_id = await _seed_cna(world, "old", NEW if entry[0] == "other" else OLD)
        a = await world.open_session()
        b = await world.open_session()
        await resolve_ingested_cna(a, _entry(org_id, "renamed", NEWER))

        cna = await asyncio.wait_for(
            resolve_ingested_cna(b, _entry(org_id, *entry)), timeout=WAIT
        )
        # The committed row, not the holder's uncommitted change.
        assert cna.short_name == "old"
        await b.commit()
        await a.commit()

        [(_, short_name, observed_at)] = await _committed_cna(world, org_id)
        assert (short_name, observed_at) == ("renamed", NEWER)

    @pytest.mark.parametrize(
        ("waiter_entry", "result"),
        [
            pytest.param(("latest", NEWER), ("latest", NEWER), id="later-wins"),
            pytest.param(("stale", MID), ("renamed", NEW), id="earlier-loses"),
        ],
    )
    async def test_effective_write_waits_and_re_evaluates_the_committed_row(
        self,
        world: IngestionWorld,
        waiter_entry: tuple[str, datetime],
        result: tuple[str, datetime],
    ) -> None:
        """A second effective writer waits for the first, then applies the
        Short Name rules against the row the first committed."""
        org_id = await _seed_cna(world, "old", OLD)
        a = await world.open_session()
        b = await world.open_session()
        await resolve_ingested_cna(a, _entry(org_id, "renamed", NEW))

        task = world.start(b, resolve_ingested_cna(b, _entry(org_id, *waiter_entry)))
        await assert_lock_wait(task, waiter=b, blocked_by=a)
        await a.commit()
        cna = await asyncio.wait_for(task, timeout=WAIT)
        if waiter_entry[0] == result[0]:
            # An applied write returns the row it wrote.
            assert (cna.short_name, cna.short_name_observed_at) == result
        await b.commit()

        [(_, short_name, observed_at)] = await _committed_cna(world, org_id)
        assert (short_name, observed_at) == result
