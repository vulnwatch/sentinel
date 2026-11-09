"""Single-session tests of the CNA of a CVE through `upsert_cve()`
(backend/app/services/cve_service.py).

Owning specifications: docs/features/tickets/cve-service.md (Merge Strategy:
CNA of the CVE; Complete `upsert_cve()` Composition steps 1 and 4;
Transaction Boundaries > Phase 1, no Ticket event for `CVE.cna_id`;
UpsertResult: `CVE.cna_id` is part of `updated`, a write to the CNA row alone
is not) and docs/features/tickets/cna.md (Ingestion Writers: Payload, Merge
of `CVE.cna_id`, Short Name; Testing Requirements, items 2 and 3).

The rows of `resolve_ingested_cna()` itself are covered in
`tests/test_services/test_cna_service.py`; the concurrent first ingestions
of two CVEs of a new CNA in `tests/test_services/test_cna_atomicity.py`.
Every test runs in the rolled-back `db_session` with fictional identifiers.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import CVESourceType, CveState, TicketStatus
from app.models.cna import CNA
from app.models.cve import CVE
from app.models.system_setting import SystemSetting
from app.models.ticket_audit_event import TicketAuditEvent
from app.services.cve_ingest import CNAEntry, CVEIngestPayload, UpsertAction
from app.services.cve_service import upsert_cve
from tests.support.cve_ingest import create_default_cvss_version, ctid

Factory = Callable[..., Awaitable[Any]]

MITRE = CVESourceType.MITRE
KERNEL = CVESourceType.KERNEL
OLD = datetime(2022, 12, 28, tzinfo=UTC)
NEW = datetime(2026, 7, 16, tzinfo=UTC)


@pytest.fixture(autouse=True)
async def default_setting(system_setting_factory: Factory) -> SystemSetting:
    """The persisted `default_cvss_version` (the test schema has none)."""
    return await create_default_cvss_version(system_setting_factory)


def _cve_id() -> str:
    return f"CVE-2099-{uuid.uuid4().int % 10**8:08d}"


def _entry(
    org_id: uuid.UUID, short_name: str | None = "example", date: datetime | None = NEW
) -> CNAEntry:
    return CNAEntry(
        org_id=org_id,
        short_name=short_name,
        short_name_observed_at=date if short_name is not None else None,
    )


def _payload(entry: CNAEntry | None = None, **fields: Any) -> CVEIngestPayload:
    values: dict[str, Any] = {"cve_state": CveState.PUBLISHED, **fields}
    if entry is not None:
        values["cna"] = entry
    return CVEIngestPayload(**values)


async def _cna_of(db: AsyncSession, cve_id: str) -> CNA | None:
    return (
        await db.execute(
            select(CNA)
            .join(CVE, CVE.cna_id == CNA.id)
            .where(CVE.cve_id == cve_id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()


async def _cna_rows(db: AsyncSession, org_id: uuid.UUID) -> int:
    return int(
        await db.scalar(
            select(func.count()).select_from(CNA).where(CNA.org_id == org_id)
        )
        or 0
    )


async def _events(db: AsyncSession, ticket_id: uuid.UUID) -> list[str]:
    rows = await db.scalars(
        select(TicketAuditEvent.event_type)
        .where(TicketAuditEvent.ticket_id == ticket_id)
        .order_by(TicketAuditEvent.id)
    )
    return list(rows.all())


@pytest.mark.integration
class TestWriters:
    @pytest.mark.parametrize("source", [MITRE, KERNEL])
    async def test_writer_records_the_cna_of_a_new_cve(
        self, db_session: AsyncSession, source: CVESourceType
    ) -> None:
        cve_id = _cve_id()
        org_id = uuid.uuid4()

        result = await upsert_cve(db_session, cve_id, source, _payload(_entry(org_id)))

        cna = await _cna_of(db_session, cve_id)
        assert cna is not None
        assert (cna.org_id, cna.short_name, cna.short_name_observed_at) == (
            org_id,
            "example",
            NEW,
        )
        assert result.cve.cna_id == cna.id
        assert result.action is UpsertAction.CREATED

    @pytest.mark.parametrize(
        "source", [s for s in CVESourceType if s not in {MITRE, KERNEL}]
    )
    async def test_other_source_supplying_cna_raises_before_any_write(
        self, db_session: AsyncSession, source: CVESourceType
    ) -> None:
        cve_id = _cve_id()
        org_id = uuid.uuid4()

        with pytest.raises(ValueError, match="Only MITRE and kernel"):
            await upsert_cve(db_session, cve_id, source, _payload(_entry(org_id)))

        assert (
            await db_session.scalar(select(CVE.id).where(CVE.cve_id == cve_id)) is None
        )
        assert await _cna_rows(db_session, org_id) == 0

    async def test_rejected_record_records_its_owner(
        self, db_session: AsyncSession
    ) -> None:
        cve_id = _cve_id()
        org_id = uuid.uuid4()

        await upsert_cve(
            db_session,
            cve_id,
            MITRE,
            _payload(_entry(org_id), cve_state=CveState.REJECTED),
        )

        cna = await _cna_of(db_session, cve_id)
        assert cna is not None
        assert cna.org_id == org_id


@pytest.mark.integration
class TestMerge:
    async def test_existing_cve_without_a_cna_takes_one_and_is_updated(
        self, db_session: AsyncSession, cve_factory: Factory, ticket_factory: Factory
    ) -> None:
        cve: CVE = await cve_factory(cve_id=_cve_id())
        ticket = await ticket_factory(cve_id=cve.id)

        result = await upsert_cve(
            db_session, cve.cve_id, MITRE, CVEIngestPayload(cna=_entry(uuid.uuid4()))
        )

        assert result.action is UpsertAction.UPDATED
        assert result.cve.cna_id is not None
        # `CVE.cna_id` and the CNA row create no Ticket event; the new CNA
        # is not under the auto-ignore policy, so the Ticket keeps its status.
        assert await _events(db_session, ticket.id) == []
        assert result.ticket.status == TicketStatus.NEW

    @pytest.mark.parametrize("source", [CVESourceType.NVD, MITRE, KERNEL])
    async def test_omitted_cna_preserves_the_recorded_one(
        self, db_session: AsyncSession, source: CVESourceType
    ) -> None:
        cve_id = _cve_id()
        first = await upsert_cve(
            db_session, cve_id, MITRE, _payload(_entry(uuid.uuid4()))
        )
        recorded = first.cve.cna_id

        result = await upsert_cve(db_session, cve_id, source, _payload())

        assert result.cve.cna_id == recorded
        assert result.action is UpsertAction.UNCHANGED

    async def test_repeated_payload_is_unchanged_and_rewrites_neither_row(
        self, db_session: AsyncSession
    ) -> None:
        cve_id = _cve_id()
        payload = _payload(_entry(uuid.uuid4()))
        first = await upsert_cve(db_session, cve_id, MITRE, payload)
        assert first.cve.cna_id is not None
        cve_tuple = await ctid(db_session, CVE, first.cve.id)
        cna_tuple = await ctid(db_session, CNA, first.cve.cna_id)

        second = await upsert_cve(db_session, cve_id, MITRE, payload)

        assert second.action is UpsertAction.UNCHANGED
        assert await ctid(db_session, CNA, first.cve.cna_id) == cna_tuple
        assert await ctid(db_session, CVE, first.cve.id) == cve_tuple

    async def test_transfer_replaces_the_cna_and_retains_the_previous_row(
        self, db_session: AsyncSession
    ) -> None:
        cve_id = _cve_id()
        previous_org, owner_org = uuid.uuid4(), uuid.uuid4()
        first = await upsert_cve(
            db_session, cve_id, MITRE, _payload(_entry(previous_org, "previous"))
        )
        previous_id = first.cve.cna_id

        result = await upsert_cve(
            db_session, cve_id, MITRE, _payload(_entry(owner_org, "owner"))
        )

        cna = await _cna_of(db_session, cve_id)
        assert cna is not None
        assert (cna.org_id, cna.short_name) == (owner_org, "owner")
        assert result.action is UpsertAction.UPDATED
        assert await db_session.get(CNA, previous_id) is not None

    async def test_kernel_and_mitre_values_of_a_kernel_cve_are_equal(
        self, db_session: AsyncSession
    ) -> None:
        """Both writers are authoritative; for a kernel CVE their values are
        equal by construction, so alternating them changes nothing."""
        cve_id = _cve_id()
        org_id = uuid.uuid4()
        await upsert_cve(
            db_session, cve_id, MITRE, _payload(_entry(org_id, "Linux", OLD))
        )

        result = await upsert_cve(
            db_session, cve_id, KERNEL, _payload(_entry(org_id, "Linux", None))
        )

        assert result.action is UpsertAction.UNCHANGED
        cna = await _cna_of(db_session, cve_id)
        assert cna is not None
        assert (cna.short_name, cna.short_name_observed_at) == ("Linux", OLD)

    async def test_short_name_change_alone_is_not_an_update_of_the_cve(
        self, db_session: AsyncSession
    ) -> None:
        cve_id = _cve_id()
        org_id = uuid.uuid4()
        await upsert_cve(
            db_session, cve_id, MITRE, _payload(_entry(org_id, "@huntrdev", OLD))
        )

        result = await upsert_cve(
            db_session, cve_id, MITRE, _payload(_entry(org_id, "@huntr_ai", NEW))
        )

        assert result.action is UpsertAction.UNCHANGED
        cna = await _cna_of(db_session, cve_id)
        assert cna is not None
        assert cna.short_name == "@huntr_ai"

    async def test_two_cves_of_one_cna_share_its_row(
        self, db_session: AsyncSession
    ) -> None:
        org_id = uuid.uuid4()
        first_id, second_id = _cve_id(), _cve_id()

        first = await upsert_cve(db_session, first_id, MITRE, _payload(_entry(org_id)))
        second = await upsert_cve(
            db_session, second_id, KERNEL, _payload(_entry(org_id))
        )

        assert first.cve.cna_id == second.cve.cna_id
        assert await _cna_rows(db_session, org_id) == 1
