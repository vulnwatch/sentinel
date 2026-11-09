"""Single-session tests of the CNA auto-ignore policy applied by
`upsert_cve()` (backend/app/services/cve_service.py).

Owning specifications:

- docs/features/tickets/cna.md (Auto-Ignore Policy: Flag, When the Policy
  Applies, Precedence and Exclusions, No Automatic Reopen, Order of Arrival
  of the Sources, Concurrency (the reads of `auto_ignore`); Testing
  Requirements, item 4).
- docs/features/tickets/cve-service.md (Ticket Creation Decision; Complete
  `upsert_cve()` Composition, steps 3, 4, and 7c; Post-Ingestion Side
  Effects; Idempotency of re-invocation).
- docs/features/tickets/ticket-service.md (`ignore_new_for_cna_policy()`;
  `create_ticket` and `associate_cve` never call it).
- docs/features/tickets/tickets.md (Status Transitions, the CNA-policy
  row; Ignore Reason).
- docs/features/tickets/ticket-audit-log.md (Canonical Mutation and
  No-Event Matrix row "CNA auto-ignore policy": the policy event is last;
  Testing Requirement 30).

The boundary itself is covered by `test_ignore_new_for_cna_policy.py`, the
independent-session races by `test_cna_policy_atomicity.py`. Every test
runs in the rolled-back `db_session` with fictional identifiers. Expected
values are transcribed from the specifications and the `Vector` constants,
never computed with the module under test.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, date, datetime
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    CVESourceType,
    CveState,
    Scope,
    SSVCAutomatable,
    SSVCExploitation,
    SSVCTechnicalImpact,
    TicketIgnoreReason,
    TicketStatus,
)
from app.models.cna import CNA
from app.models.cve import CVE
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.services import cna_service, cve_service, ticket_service
from app.services.cve_ingest import (
    CNAEntry,
    CVEIngestPayload,
    EPSSEntry,
    KEVEntry,
    SSVCEntry,
    UpsertAction,
    UpsertResult,
)
from app.services.ticket_service import TicketCreationSource
from app.services.ticket_visibility import TicketCaller
from tests.support.cve_ingest import (
    CompositionTimeline,
    create_default_cvss_version,
    cvss,
)
from tests.support.cvss_chain import priority_event, severity_event, ticket_state
from tests.support.external_cvss import external_cvss_event, external_value
from tests.support.suse_cvss import V31_HIGH, V31_MEDIUM, Vector
from tests.support.ticket_creation import creation_events, ingestion_comment
from tests.support.ticket_mutations import (
    EventRow,
    StatementRecorder,
    TicketFactory,
    VAUser,
    status_event,
    ticket_events,
)

pytest_plugins = ["tests.support.ticket_mutation_fixtures"]
"""Provides the shared `va_user` fixture."""

pytestmark = pytest.mark.usefixtures("no_fetch_single_sources")
"""An empty fetch-single registry: the freshness refresh of a manual
creation or association takes its no-eligible-source branch."""

Factory = Callable[..., Awaitable[Any]]

MITRE = CVESourceType.MITRE
KERNEL = CVESourceType.KERNEL
NVD = CVESourceType.NVD
PROVIDER = "Example CNA"
REJECTED_AT = datetime(2099, 3, 4, tzinfo=UTC)
KEV = KEVEntry(date_added=date(2099, 1, 15))

POLICY_CALL = "ignore_new_for_cna_policy"
CREATE = "create_ticket"
BATCH = "upsert_external_cvss_batch"
REFRESH = "refresh_priority_auto"
REJECT = "ignore_new_for_rejected_cve"
REOPEN = "reopen_from_ignored_as_system"
SOURCE_STATUS = "record_source_status"

POLICY = EventRow(
    "status_change",
    None,
    TicketStatus.NEW.value,
    TicketStatus.IGNORED.value,
    "CNA auto-ignore policy",
    {"ignore_reason": "cna_policy"},
)
"""The exact system event of the policy (cna.md, When the Policy Applies)."""

REJECTION = EventRow(
    "status_change",
    None,
    TicketStatus.NEW.value,
    TicketStatus.IGNORED.value,
    "CVE rejected",
    {"ignore_reason": "cve_rejected"},
)
"""The exact system rejection event (cve-tracking.md, Rejection handling)."""


@pytest.fixture(autouse=True)
async def default_setting(system_setting_factory: Factory) -> SystemSetting:
    """The persisted `default_cvss_version` (the test schema has none)."""
    return await create_default_cvss_version(system_setting_factory)


def _cve_id() -> str:
    return f"CVE-2099-{uuid.uuid4().int % 10**8:08d}"


def _entry(cna: CNA) -> CNAEntry:
    """The owner of a record of `cna`, without a short name, so that the
    resolution writes nothing to the row."""
    return CNAEntry(org_id=cna.org_id)


def _payload(
    cna: CNA | None = None,
    *,
    state: CveState | None = CveState.PUBLISHED,
    vector: Vector | None = None,
    **fields: Any,
) -> CVEIngestPayload:
    values: dict[str, Any] = dict(fields)
    if state is not None:
        values["cve_state"] = state
        if state is CveState.REJECTED:
            values.setdefault("date_rejected", REJECTED_AT)
    if cna is not None:
        values["cna"] = _entry(cna)
    if vector is not None:
        values["cvss_assessments"] = [cvss(PROVIDER, vector.canonical)]
    return CVEIngestPayload(**values)


async def _upsert(
    db: AsyncSession,
    cve_id: str,
    payload: CVEIngestPayload,
    *,
    source: CVESourceType = MITRE,
) -> UpsertResult:
    return await cve_service.upsert_cve(db, cve_id, source, payload)


async def _status_and_reason(
    db: AsyncSession, ticket_id: uuid.UUID
) -> tuple[str, str | None]:
    row = (
        await db.execute(
            select(Ticket.status, Ticket.ignore_reason)
            .where(Ticket.id == ticket_id)
            .execution_options(populate_existing=True)
        )
    ).one()
    return row[0], row[1]


def _high_batch() -> list[EventRow]:
    """The system batch events of a first `High` assessment."""
    return [
        external_cvss_event(None, external_value(PROVIDER, V31_HIGH)),
        severity_event(None, "High"),
        priority_event(None, "P3"),
    ]


def _creation(cve_id: str, source: CVESourceType) -> list[EventRow]:
    return creation_events(
        creator_id=None, comment=ingestion_comment(source), cve_id=cve_id
    )


async def _existing(
    cve_factory: Factory,
    ticket_factory: TicketFactory,
    *,
    cna: CNA | None = None,
    state: CveState = CveState.PUBLISHED,
    **ticket_columns: Any,
) -> tuple[CVE, Ticket]:
    """An existing CVE, with `cna` recorded when given, and its Ticket
    (`New` unless `status` is given)."""
    cve: CVE = await cve_factory(
        cve_state=state.value,
        date_rejected=REJECTED_AT if state is CveState.REJECTED else None,
        cna_id=cna.id if cna is not None else None,
    )
    ticket_columns.setdefault("status", TicketStatus.NEW.value)
    ticket = await ticket_factory(cve_id=cve.id, **ticket_columns)
    return cve, ticket


# ---------------------------------------------------------------------------
# Ticket created by the ingestion (When the Policy Applies, condition 3;
# Order of Arrival, row 1)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCreatedTicket:
    @pytest.mark.parametrize("source", [MITRE, KERNEL])
    async def test_created_and_ignored_with_the_policy_event_last(
        self,
        db_session: AsyncSession,
        cna_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        source: CVESourceType,
    ) -> None:
        """The Ticket is created `New` and ignored in the same transaction:
        creation events, the CVSS batch and priority refresh, then the
        policy `status_change`, which is the last event. The policy changes
        no CVE-owned data, so the action is still `created`."""
        cna = await cna_factory(auto_ignore=True)
        cve_id = _cve_id()
        timeline = CompositionTimeline(db_session, monkeypatch)

        result = await _upsert(
            db_session, cve_id, _payload(cna, vector=V31_HIGH), source=source
        )

        assert result.action is UpsertAction.CREATED
        assert timeline.top_level() == [
            CREATE,
            BATCH,
            REFRESH,
            POLICY_CALL,
            SOURCE_STATUS,
        ]
        [call] = timeline.calls_of(POLICY_CALL)
        assert call.kwargs["cve_id"] == result.cve.id
        assert call.kwargs["ticket"] is result.ticket
        assert result.ticket.status == TicketStatus.IGNORED
        assert await _status_and_reason(db_session, result.ticket.id) == (
            "Ignored",
            "cna_policy",
        )
        assert await ticket_events(db_session, result.ticket) == [
            *_creation(cve_id, source),
            *_high_batch(),
            POLICY,
        ]

    async def test_cna_not_under_the_policy_leaves_the_ticket_new(
        self,
        db_session: AsyncSession,
        cna_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cna = await cna_factory(auto_ignore=False)
        cve_id = _cve_id()
        timeline = CompositionTimeline(db_session, monkeypatch)

        result = await _upsert(db_session, cve_id, _payload(cna))

        assert timeline.calls_of(POLICY_CALL) == []
        assert await _status_and_reason(db_session, result.ticket.id) == ("New", None)
        assert await ticket_events(db_session, result.ticket) == _creation(
            cve_id, MITRE
        )

    async def test_orphan_with_a_supplied_cna_is_reticketed_and_ignored(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        cna_factory: Factory,
    ) -> None:
        cna = await cna_factory(auto_ignore=True)
        cve = await cve_factory(cna_id=cna.id)

        result = await _upsert(db_session, cve.cve_id, _payload(cna))

        assert await _status_and_reason(db_session, result.ticket.id) == (
            "Ignored",
            "cna_policy",
        )
        assert await ticket_events(db_session, result.ticket) == [
            *_creation(cve.cve_id, MITRE),
            POLICY,
        ]

    @pytest.mark.parametrize(
        "payload",
        [
            pytest.param(CVEIngestPayload(), id="empty"),
            pytest.param(CVEIngestPayload(kev_data=KEV), id="kev"),
        ],
    )
    async def test_orphan_whose_recorded_cna_is_under_the_policy_is_ignored(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        cna_factory: Factory,
        payload: CVEIngestPayload,
    ) -> None:
        """A source that omits `cna` re-tickets the orphan; the policy reads
        the `auto_ignore` of the recorded CNA with one column statement and
        no lock. An empty payload changes no CVE-owned data, so the action
        stays `unchanged` although the Ticket is created and ignored."""
        cna = await cna_factory(auto_ignore=True)
        cve = await cve_factory(cna_id=cna.id)

        with StatementRecorder(db_session) as recorder:
            result = await _upsert(db_session, cve.cve_id, payload, source=NVD)

        cna_reads = recorder.selects_from("cna")
        assert len(cna_reads) == 1
        assert cna_reads[0].startswith("SELECT cna.auto_ignore ")
        assert "FOR " not in cna_reads[0]
        assert result.action is (
            UpsertAction.UNCHANGED if payload.kev_data is None else UpsertAction.UPDATED
        )
        assert await _status_and_reason(db_session, result.ticket.id) == (
            "Ignored",
            "cna_policy",
        )
        events = await ticket_events(db_session, result.ticket)
        assert events[:2] == _creation(cve.cve_id, NVD)
        assert events[-1] == POLICY

    async def test_source_omitting_cna_for_a_cve_without_one_reads_no_cna(
        self,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Order of Arrival, row 2: NVD creates the Ticket `New` without a
        CNA."""
        cve_id = _cve_id()
        timeline = CompositionTimeline(db_session, monkeypatch)

        with StatementRecorder(db_session) as recorder:
            result = await _upsert(db_session, cve_id, _payload(), source=NVD)

        assert recorder.selects_from("cna") == []
        assert timeline.calls_of(POLICY_CALL) == []
        assert result.cve.cna_id is None
        assert await _status_and_reason(db_session, result.ticket.id) == ("New", None)


# ---------------------------------------------------------------------------
# Existing Ticket (When the Policy Applies, condition 3; Order of Arrival)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestExistingTicket:
    async def test_nvd_first_then_mitre_ignores_the_new_ticket_and_keeps_packages(
        self,
        db_session: AsyncSession,
        cna_factory: Factory,
        ticket_package_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Order of Arrival, rows 2 and 3: the Tickets that other sources
        create stay `New` without a CNA; KEV, EPSS, and SSVC recorded before
        the CNA do not exempt the Ticket (Precedence and Exclusions); the
        first MITRE ingestion records the CNA and ignores the Ticket, whose
        packages remain."""
        cna = await cna_factory(auto_ignore=True)
        cve_id = _cve_id()
        created = await _upsert(
            db_session, cve_id, _payload(vector=V31_HIGH), source=NVD
        )
        ticket = created.ticket
        package: TicketPackage = await ticket_package_factory(ticket_id=ticket.id)
        await _upsert(
            db_session, cve_id, CVEIngestPayload(kev_data=KEV), source=CVESourceType.KEV
        )
        await _upsert(
            db_session,
            cve_id,
            CVEIngestPayload(
                epss_score=EPSSEntry(
                    score=0.5, percentile=0.97, assessed_at=date(2099, 1, 15)
                )
            ),
            source=CVESourceType.EPSS,
        )
        await _upsert(
            db_session,
            cve_id,
            CVEIngestPayload(
                ssvc_assessment=SSVCEntry(
                    exploitation=SSVCExploitation.ACTIVE,
                    automatable=SSVCAutomatable.NO,
                    technical_impact=SSVCTechnicalImpact.PARTIAL,
                    version="2.0.3",
                )
            ),
            source=MITRE,
        )
        assert await _status_and_reason(db_session, ticket.id) == ("New", None)
        before = await ticket_events(db_session, ticket)
        timeline = CompositionTimeline(db_session, monkeypatch)

        result = await _upsert(db_session, cve_id, _payload(cna))

        assert result.action is UpsertAction.UPDATED
        assert result.ticket.id == ticket.id
        assert timeline.top_level() == [BATCH, REFRESH, POLICY_CALL, SOURCE_STATUS]
        assert await _status_and_reason(db_session, ticket.id) == (
            "Ignored",
            "cna_policy",
        )
        assert await ticket_events(db_session, ticket) == [*before, POLICY]
        assert (
            await db_session.scalar(
                select(TicketPackage.id).where(TicketPackage.ticket_id == ticket.id)
            )
            == package.id
        )

    async def test_ticket_in_another_status_is_unchanged(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        ticket_factory: TicketFactory,
        cna_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Order of Arrival, row 4, and Precedence and Exclusions: a Ticket
        that a user already works on stays as it is; the boundary is called
        and decides from the Ticket. Every status is covered by
        `test_ignore_new_for_cna_policy.py` (test_every_other_status_is_a_no_op);
        the `sync_mitre_cnas` row by `test_tickets/test_sync_mitre_cnas.py`."""
        cna = await cna_factory(auto_ignore=True)
        cve, ticket = await _existing(
            cve_factory, ticket_factory, status=TicketStatus.ANALYSIS.value
        )
        before = await _status_and_reason(db_session, ticket.id)
        timeline = CompositionTimeline(db_session, monkeypatch)

        await _upsert(db_session, cve.cve_id, _payload(cna))

        assert timeline.top_level() == [BATCH, REFRESH, POLICY_CALL, SOURCE_STATUS]
        assert await _status_and_reason(db_session, ticket.id) == before
        assert await ticket_events(db_session, ticket) == []

    async def test_confidential_new_ticket_is_unchanged(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        ticket_factory: TicketFactory,
        cna_factory: Factory,
    ) -> None:
        cna = await cna_factory(auto_ignore=True)
        cve, ticket = await _existing(cve_factory, ticket_factory, is_confidential=True)

        await _upsert(db_session, cve.cve_id, _payload(cna))

        assert await _status_and_reason(db_session, ticket.id) == ("New", None)
        assert await ticket_events(db_session, ticket) == []

    async def test_transfer_to_a_cna_under_the_policy_ignores_a_new_ticket(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        ticket_factory: TicketFactory,
        cna_factory: Factory,
    ) -> None:
        """Order of Arrival, row 7: a changed `CVE.cna_id` applies the
        policy of the new CNA."""
        previous = await cna_factory(auto_ignore=False)
        target = await cna_factory(auto_ignore=True)
        cve, ticket = await _existing(cve_factory, ticket_factory, cna=previous)

        result = await _upsert(db_session, cve.cve_id, _payload(target))

        assert result.cve.cna_id == target.id
        assert result.action is UpsertAction.UPDATED
        assert await _status_and_reason(db_session, ticket.id) == (
            "Ignored",
            "cna_policy",
        )
        assert await ticket_events(db_session, ticket) == [POLICY]

    @pytest.mark.parametrize("supplied", [True, False], ids=["supplied", "omitted"])
    async def test_unchanged_cna_under_the_policy_makes_no_call(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        ticket_factory: TicketFactory,
        cna_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        supplied: bool,
    ) -> None:
        """When the Policy Applies, consequences: re-ingesting a record does
        not ignore a `New` Ticket that the policy did not ignore before."""
        cna = await cna_factory(auto_ignore=True)
        cve, ticket = await _existing(cve_factory, ticket_factory, cna=cna)
        timeline = CompositionTimeline(db_session, monkeypatch)

        await _upsert(
            db_session,
            cve.cve_id,
            _payload(cna if supplied else None, title="Fictional title"),
            source=MITRE if supplied else NVD,
        )

        assert timeline.calls_of(POLICY_CALL) == []
        assert await _status_and_reason(db_session, ticket.id) == ("New", None)
        assert await ticket_events(db_session, ticket) == []


# ---------------------------------------------------------------------------
# Rejection precedence (Precedence and Exclusions: Rejected CVE; Order of
# Arrival, rows 5 and 6; composition step 7)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRejectionPrecedence:
    async def test_rejected_first_ingestion_ignores_with_cve_rejected_only(
        self,
        db_session: AsyncSession,
        cna_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The rejection boundary takes the Ticket; after the revert, which
        reopens it, the policy does not apply because the Ticket is no
        longer `New` and the CNA is unchanged."""
        cna = await cna_factory(auto_ignore=True)
        cve_id = _cve_id()
        timeline = CompositionTimeline(db_session, monkeypatch)

        result = await _upsert(
            db_session, cve_id, _payload(cna, state=CveState.REJECTED)
        )

        assert timeline.top_level() == [
            CREATE,
            BATCH,
            REFRESH,
            REJECT,
            SOURCE_STATUS,
        ]
        assert await _status_and_reason(db_session, result.ticket.id) == (
            "Ignored",
            "cve_rejected",
        )

        reverted = await _upsert(db_session, cve_id, _payload(cna))

        assert timeline.calls_of(POLICY_CALL) == []
        assert reverted.ticket.status == TicketStatus.ANALYSIS
        assert await _status_and_reason(db_session, result.ticket.id) == (
            "Analysis",
            None,
        )
        assert await ticket_events(db_session, result.ticket) == [
            *_creation(cve_id, MITRE),
            REJECTION,
            status_event("Ignored", "Analysis"),
        ]

    async def test_rejection_of_a_policy_ignored_ticket_keeps_its_reason(
        self,
        db_session: AsyncSession,
        cna_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Order of Arrival, row 6, and No Automatic Reopen: the rejection
        keeps `cna_policy`, and its revert reopens only `cve_rejected`."""
        cna = await cna_factory(auto_ignore=True)
        cve_id = _cve_id()
        created = await _upsert(db_session, cve_id, _payload(cna))
        timeline = CompositionTimeline(db_session, monkeypatch)

        await _upsert(db_session, cve_id, _payload(cna, state=CveState.REJECTED))
        await _upsert(db_session, cve_id, _payload(cna))

        assert timeline.calls_of(REOPEN) == []
        assert timeline.calls_of(POLICY_CALL) == []
        assert await _status_and_reason(db_session, created.ticket.id) == (
            "Ignored",
            "cna_policy",
        )
        assert await ticket_events(db_session, created.ticket) == [
            *_creation(cve_id, MITRE),
            POLICY,
        ]

    async def test_revert_with_a_cna_change_reopens_and_does_not_ignore(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        ticket_factory: TicketFactory,
        cna_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """One ingestion reverts the rejection and changes the CNA to one
        under the policy: the reopen applies first, so the policy does not
        (composition step 7: at most one lifecycle decision)."""
        previous = await cna_factory(auto_ignore=False)
        target = await cna_factory(auto_ignore=True)
        cve, ticket = await _existing(
            cve_factory,
            ticket_factory,
            cna=previous,
            state=CveState.REJECTED,
            status=TicketStatus.IGNORED.value,
            ignore_reason=TicketIgnoreReason.CVE_REJECTED.value,
        )
        timeline = CompositionTimeline(db_session, monkeypatch)

        result = await _upsert(db_session, cve.cve_id, _payload(target))

        assert result.cve.cna_id == target.id
        assert timeline.top_level() == [BATCH, REFRESH, REOPEN, SOURCE_STATUS]
        assert await _status_and_reason(db_session, ticket.id) == ("Analysis", None)
        assert await ticket_events(db_session, ticket) == [
            status_event("Ignored", "Analysis")
        ]

    async def test_revert_of_a_new_ticket_with_a_cna_change_applies_the_policy(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        ticket_factory: TicketFactory,
        cna_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A `New` Ticket of a rejected CVE, such as one created manually by
        a bot account, is not reopened by the revert; the change of its CNA
        to one under the policy is then the first decision that applies."""
        target = await cna_factory(auto_ignore=True)
        cve, ticket = await _existing(
            cve_factory, ticket_factory, state=CveState.REJECTED
        )
        timeline = CompositionTimeline(db_session, monkeypatch)

        await _upsert(db_session, cve.cve_id, _payload(target))

        assert timeline.top_level() == [BATCH, REFRESH, POLICY_CALL, SOURCE_STATUS]
        assert await _status_and_reason(db_session, ticket.id) == (
            "Ignored",
            "cna_policy",
        )
        assert await ticket_events(db_session, ticket) == [POLICY]

    async def test_rejected_cve_with_a_cna_change_does_not_apply_the_policy(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        ticket_factory: TicketFactory,
        cna_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When the Policy Applies, condition 1: the post-merge state is
        `REJECTED`, so a changed CNA under the policy applies nothing (the
        unchanged rejection makes no lifecycle call either)."""
        target = await cna_factory(auto_ignore=True)
        cve, ticket = await _existing(
            cve_factory, ticket_factory, state=CveState.REJECTED
        )
        timeline = CompositionTimeline(db_session, monkeypatch)

        await _upsert(db_session, cve.cve_id, _payload(target, state=CveState.REJECTED))

        assert timeline.top_level() == [BATCH, REFRESH, SOURCE_STATUS]
        assert await _status_and_reason(db_session, ticket.id) == ("New", None)


# ---------------------------------------------------------------------------
# No Automatic Reopen (cna.md, No Automatic Reopen; Order of Arrival, rows
# 8 to 11)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestNoAutomaticReopen:
    @pytest.mark.parametrize(
        "later",
        [
            pytest.param((CVESourceType.KEV, CVEIngestPayload(kev_data=KEV)), id="kev"),
            pytest.param(
                (
                    CVESourceType.EPSS,
                    CVEIngestPayload(
                        epss_score=EPSSEntry(
                            score=0.9, percentile=0.99, assessed_at=date(2099, 1, 15)
                        )
                    ),
                ),
                id="epss",
            ),
            pytest.param(
                (
                    MITRE,
                    CVEIngestPayload(
                        ssvc_assessment=SSVCEntry(
                            exploitation=SSVCExploitation.ACTIVE,
                            automatable=SSVCAutomatable.YES,
                            technical_impact=SSVCTechnicalImpact.TOTAL,
                            version="2.0.3",
                        )
                    ),
                ),
                id="ssvc",
            ),
            pytest.param(
                (NVD, CVEIngestPayload(cvss_assessments=[cvss("NVD", "x")])),
                id="invalid-cvss",
            ),
            pytest.param(
                (
                    NVD,
                    CVEIngestPayload(
                        cvss_assessments=[cvss(PROVIDER, V31_MEDIUM.canonical)]
                    ),
                ),
                id="cvss",
            ),
        ],
    )
    async def test_later_evidence_never_reopens(
        self,
        db_session: AsyncSession,
        cna_factory: Factory,
        later: tuple[CVESourceType, CVEIngestPayload],
    ) -> None:
        cna = await cna_factory(auto_ignore=True)
        cve_id = _cve_id()
        created = await _upsert(db_session, cve_id, _payload(cna))
        source, payload = later

        await _upsert(db_session, cve_id, payload, source=source)

        assert await _status_and_reason(db_session, created.ticket.id) == (
            "Ignored",
            "cna_policy",
        )
        assert [
            event
            for event in await ticket_events(db_session, created.ticket)
            if event.event_type == "status_change"
        ] == [POLICY]

    @pytest.mark.parametrize("target_policy", [False, True], ids=["off", "on"])
    async def test_transfer_never_reopens(
        self,
        db_session: AsyncSession,
        cna_factory: Factory,
        target_policy: bool,
    ) -> None:
        """A transfer to another CNA, under the policy or not, leaves the
        `Ignored` Ticket and its reason unchanged."""
        cna = await cna_factory(auto_ignore=True)
        target = await cna_factory(auto_ignore=target_policy)
        cve_id = _cve_id()
        created = await _upsert(db_session, cve_id, _payload(cna))

        result = await _upsert(db_session, cve_id, _payload(target))

        assert result.cve.cna_id == target.id
        assert await _status_and_reason(db_session, created.ticket.id) == (
            "Ignored",
            "cna_policy",
        )
        assert await ticket_events(db_session, created.ticket) == [
            *_creation(cve_id, MITRE),
            POLICY,
        ]

    async def test_cna_leaving_the_policy_never_reopens(
        self,
        db_session: AsyncSession,
        cna_factory: Factory,
        user_factory: Factory,
    ) -> None:
        """Flag: a change of `auto_ignore` changes no existing Ticket, and a
        later ingestion does not reopen one either."""
        cna = await cna_factory(auto_ignore=True)
        admin = await user_factory()
        cve_id = _cve_id()
        created = await _upsert(db_session, cve_id, _payload(cna))

        await cna_service.set_cna_auto_ignore(
            db_session,
            org_id=str(cna.org_id),
            auto_ignore=False,
            acting_user_id=admin.id,
        )
        await _upsert(db_session, cve_id, _payload(cna, title="Fictional title"))

        assert await _status_and_reason(db_session, created.ticket.id) == (
            "Ignored",
            "cna_policy",
        )
        assert await ticket_events(db_session, created.ticket) == [
            *_creation(cve_id, MITRE),
            POLICY,
        ]


# ---------------------------------------------------------------------------
# Manual creation and association (tickets.md, CVE Resolution Behavior;
# ticket-service.md, `create_ticket` and `associate_cve`)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestManualPaths:
    async def test_manual_creation_never_applies_the_policy(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        cna_factory: Factory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cna = await cna_factory(auto_ignore=True)
        cve = await cve_factory(cna_id=cna.id)
        bot = await va_user(bot=True)
        timeline = CompositionTimeline(db_session, monkeypatch)

        ticket = await ticket_service.create_ticket(
            db_session,
            acting_user_id=bot.id,
            cve_id=cve.cve_id,
            source=TicketCreationSource.MANUAL,
        )

        assert timeline.calls_of(POLICY_CALL) == []
        assert await _status_and_reason(db_session, ticket.id) == ("New", None)

    async def test_manual_association_never_applies_the_policy(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        ticket_factory: TicketFactory,
        cna_factory: Factory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cna = await cna_factory(auto_ignore=True)
        cve = await cve_factory(cna_id=cna.id)
        bot = await va_user(bot=True)
        ticket = await ticket_factory(status=TicketStatus.NEW.value)
        timeline = CompositionTimeline(db_session, monkeypatch)

        await ticket_service.associate_cve(
            db_session,
            ticket_id=ticket.id,
            cve_id=cve.cve_id,
            acting_user_id=bot.id,
            caller=TicketCaller.authenticated(bot.id, Scope.ALL),
        )

        assert timeline.calls_of(POLICY_CALL) == []
        assert await _status_and_reason(db_session, ticket.id) == ("New", None)

    async def test_bot_created_ticket_is_ignored_when_ingestion_records_the_cna(
        self,
        db_session: AsyncSession,
        cna_factory: Factory,
        va_user: VAUser,
    ) -> None:
        """When the Policy Applies, consequences: a Ticket created `New` by a
        bot account for an unknown CVE is ignored by the later ingestion that
        records its CNA, such as the freshness fetch of its creation."""
        cna = await cna_factory(auto_ignore=True)
        bot = await va_user(bot=True)
        cve_id = _cve_id()
        ticket = await ticket_service.create_ticket(
            db_session,
            acting_user_id=bot.id,
            cve_id=cve_id,
            source=TicketCreationSource.MANUAL,
        )
        assert await _status_and_reason(db_session, ticket.id) == ("New", None)

        await _upsert(db_session, cve_id, _payload(cna))

        assert await _status_and_reason(db_session, ticket.id) == (
            "Ignored",
            "cna_policy",
        )
        assert (await ticket_events(db_session, ticket))[-1] == POLICY
        assert (await ticket_state(db_session, ticket.id))[1] is None
