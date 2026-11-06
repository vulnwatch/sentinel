"""Service integration tests for the automatic priority basis of the Ticket
reads (`list_tickets()` and `get_ticket_detail()`,
backend/app/services/ticket_service.py).

Owning specifications:

- docs/features/tickets/ticket-priority.md (Exploitation Level: deciding
  evidence; Automatic Priority Basis; Testing Requirement 10).
- docs/features/tickets/ticket-service.md (`list_tickets()` step 4;
  `get_ticket_detail()` step 2).
- docs/features/tickets/tickets.md (PriorityBasis; PriorityEvidence;
  Severity Resolution).

The persisted evidence is built with the model factories, so these tests
prove that each read classifies the persisted rows of the Ticket's CVE into
the specified basis, independently of `priority_auto`. The agreement of the
basis with `priority_automatic` through a refresh point, the wire format,
and the post-mutation responses are proven in
tests/test_api/test_ticket_priority_basis.py and the mutation endpoint
tests; the pure classification in test_ticket_priority.py. Expected bases
are transcribed from the specification, never computed with the module
under test. All identifiers are fictional.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import date
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    ExploitationEvidenceKind,
    ExploitationLevel,
    Scope,
    Severity,
    TicketPriority,
    TicketStatus,
)
from app.core.identifiers import format_ticket_id
from app.models.ticket import Ticket
from app.services.ticket_priority import ExploitationEvidence
from app.services.ticket_service import (
    PriorityBasisProjection,
    get_ticket_detail,
    list_tickets,
)
from app.services.ticket_visibility import TicketCaller

Factory = Callable[..., Awaitable[Any]]

ALL_SCOPE = TicketCaller.authenticated(uuid.uuid4(), Scope.ALL)
KEV_DATE = date(2099, 1, 15)

KEV = ExploitationEvidence(ExploitationEvidenceKind.KEV, KEV_DATE)
SSVC_ACTIVE = ExploitationEvidence(ExploitationEvidenceKind.SSVC_EXPLOITATION, "active")
SSVC_POC = ExploitationEvidence(ExploitationEvidenceKind.SSVC_EXPLOITATION, "poc")


def _epss(percentile: float) -> ExploitationEvidence:
    return ExploitationEvidence(ExploitationEvidenceKind.EPSS_PERCENTILE, percentile)


@dataclass(frozen=True, slots=True)
class Evidence:
    """Persisted exploitation evidence of a CVE; `None` means no row."""

    kev: date | None = None
    ssvc: str | None = None
    epss: float | None = None


NO_EVIDENCE = Evidence()


@pytest.fixture
def cve_ticket(
    ticket_factory: Factory,
    cve_factory: Factory,
    cve_kev_entry_factory: Factory,
    cve_ssvc_assessment_factory: Factory,
    cve_epss_score_factory: Factory,
) -> Callable[..., Awaitable[Ticket]]:
    """A Ticket whose CVE has `severity` and the persisted `evidence`."""

    async def _create(
        *,
        severity: Severity | None,
        evidence: Evidence = NO_EVIDENCE,
        **ticket_columns: Any,
    ) -> Ticket:
        cve = await cve_factory(severity=severity.value if severity else None)
        if evidence.kev is not None:
            await cve_kev_entry_factory(cve_id=cve.id, date_added=evidence.kev)
        if evidence.ssvc is not None:
            # `automatable` and `technical_impact` are not inputs.
            await cve_ssvc_assessment_factory(
                cve_id=cve.id,
                exploitation=evidence.ssvc,
                automatable="yes",
                technical_impact="total",
            )
        if evidence.epss is not None:
            # The EPSS score is not an input: a high score never decides.
            await cve_epss_score_factory(
                cve_id=cve.id, percentile=evidence.epss, score=0.99
            )
        ticket: Ticket = await ticket_factory(cve_id=cve.id, **ticket_columns)
        return ticket

    return _create


async def _bases(
    db: AsyncSession, ticket: Ticket
) -> tuple[PriorityBasisProjection, PriorityBasisProjection]:
    """The basis of the Ticket in the list and in the detail read."""
    sntl = format_ticket_id(ticket.sequence_id)
    page = await list_tickets(db, caller=ALL_SCOPE, search=sntl)
    (summary,) = [item for item in page.items if item.ticket_id == sntl]
    detail = await get_ticket_detail(db, ticket_id=sntl, caller=ALL_SCOPE)
    return summary.priority_basis, detail.priority_basis


@pytest.mark.integration
class TestDecidingEvidenceInBothReads:
    @pytest.mark.parametrize(
        ("evidence", "level", "expected"),
        [
            pytest.param(
                Evidence(kev=KEV_DATE, ssvc="active", epss=0.99),
                ExploitationLevel.KEV,
                (KEV,),
                id="kev-hides-active-and-epss",
            ),
            pytest.param(
                Evidence(kev=KEV_DATE, ssvc="poc"),
                ExploitationLevel.KEV,
                (KEV,),
                id="kev-hides-poc",
            ),
            pytest.param(
                Evidence(ssvc="active", epss=0.95),
                ExploitationLevel.ACTIVE,
                (SSVC_ACTIVE,),
                id="active-hides-epss",
            ),
            pytest.param(
                Evidence(ssvc="poc"),
                ExploitationLevel.LIKELY,
                (SSVC_POC,),
                id="poc-alone",
            ),
            pytest.param(
                Evidence(epss=0.95),
                ExploitationLevel.LIKELY,
                (_epss(0.95),),
                id="epss-at-threshold",
            ),
            pytest.param(
                Evidence(ssvc="none", epss=0.97),
                ExploitationLevel.LIKELY,
                (_epss(0.97),),
                id="epss-with-ssvc-none",
            ),
            pytest.param(
                Evidence(ssvc="poc", epss=0.97),
                ExploitationLevel.LIKELY,
                (SSVC_POC, _epss(0.97)),
                id="poc-and-epss",
            ),
            pytest.param(
                Evidence(ssvc="none", epss=0.9499999),
                ExploitationLevel.UNKNOWN,
                (),
                id="ssvc-none-and-epss-just-below",
            ),
            pytest.param(
                NO_EVIDENCE, ExploitationLevel.UNKNOWN, (), id="no-evidence-rows"
            ),
        ],
    )
    async def test_each_read_projects_the_exact_basis(
        self,
        db_session: AsyncSession,
        cve_ticket: Callable[..., Awaitable[Ticket]],
        evidence: Evidence,
        level: ExploitationLevel,
        expected: tuple[ExploitationEvidence, ...],
    ) -> None:
        ticket = await cve_ticket(severity=Severity.HIGH, evidence=evidence)

        summary, detail = await _bases(db_session, ticket)

        basis = PriorityBasisProjection(
            severity=Severity.HIGH, exploitation=level, evidence=expected
        )
        assert summary == detail == basis

    @pytest.mark.parametrize(
        "status",
        [
            TicketStatus.NEW,
            TicketStatus.ANALYSIS,
            TicketStatus.ANALYZED,
            TicketStatus.RESOLVED,
            TicketStatus.IGNORED,
            TicketStatus.DUPLICATED,
        ],
        ids=str,
    )
    async def test_basis_is_projected_in_every_status(
        self,
        db_session: AsyncSession,
        cve_ticket: Callable[..., Awaitable[Ticket]],
        status: TicketStatus,
    ) -> None:
        ticket = await cve_ticket(
            severity=Severity.LOW, evidence=Evidence(kev=KEV_DATE), status=status.value
        )

        summary, detail = await _bases(db_session, ticket)

        assert (
            summary
            == detail
            == PriorityBasisProjection(
                severity=Severity.LOW,
                exploitation=ExploitationLevel.KEV,
                evidence=(KEV,),
            )
        )

    async def test_override_leaves_the_basis_unchanged(
        self,
        db_session: AsyncSession,
        cve_ticket: Callable[..., Awaitable[Ticket]],
    ) -> None:
        # Medium with SSVC `active` is the P2 cell; the override P4 is the
        # effective priority but explains nothing about the automatic one.
        ticket = await cve_ticket(
            severity=Severity.MEDIUM,
            evidence=Evidence(ssvc="active"),
            priority_auto=TicketPriority.P2.value,
            priority_override=TicketPriority.P4.value,
        )

        summary, detail = await _bases(db_session, ticket)

        assert (
            summary
            == detail
            == PriorityBasisProjection(
                severity=Severity.MEDIUM,
                exploitation=ExploitationLevel.ACTIVE,
                evidence=(SSVC_ACTIVE,),
            )
        )


@pytest.mark.integration
class TestListPageWithSeveralTickets:
    async def test_each_row_reads_the_evidence_of_its_own_cve(
        self,
        db_session: AsyncSession,
        cve_ticket: Callable[..., Awaitable[Ticket]],
        ticket_factory: Factory,
    ) -> None:
        """The list joins the evidence into the page statement: each row
        reads only its own CVE's rows, and the joins neither multiply rows
        nor change `total`."""
        kev = await cve_ticket(severity=Severity.HIGH, evidence=Evidence(kev=KEV_DATE))
        likely = await cve_ticket(
            severity=Severity.LOW, evidence=Evidence(ssvc="poc", epss=0.97)
        )
        bare = await cve_ticket(severity=Severity.CRITICAL)
        cveless: Ticket = await ticket_factory(severity_manual=Severity.MEDIUM.value)

        page = await list_tickets(db_session, caller=ALL_SCOPE, per_page=100)

        assert page.total == len(page.items) == 4
        assert {item.ticket_id: item.priority_basis for item in page.items} == {
            format_ticket_id(kev.sequence_id): PriorityBasisProjection(
                severity=Severity.HIGH,
                exploitation=ExploitationLevel.KEV,
                evidence=(KEV,),
            ),
            format_ticket_id(likely.sequence_id): PriorityBasisProjection(
                severity=Severity.LOW,
                exploitation=ExploitationLevel.LIKELY,
                evidence=(SSVC_POC, _epss(0.97)),
            ),
            format_ticket_id(bare.sequence_id): PriorityBasisProjection(
                severity=Severity.CRITICAL,
                exploitation=ExploitationLevel.UNKNOWN,
                evidence=(),
            ),
            format_ticket_id(cveless.sequence_id): PriorityBasisProjection(
                severity=Severity.MEDIUM,
                exploitation=ExploitationLevel.UNKNOWN,
                evidence=(),
            ),
        }


@pytest.mark.integration
class TestBasisSeverity:
    @pytest.mark.parametrize(
        "severity", [Severity.NONE, None], ids=["none-label", "sql-null"]
    )
    async def test_cve_severity_none_label_is_distinct_from_null(
        self,
        db_session: AsyncSession,
        cve_ticket: Callable[..., Awaitable[Ticket]],
        severity: Severity | None,
    ) -> None:
        ticket = await cve_ticket(severity=severity, evidence=Evidence(ssvc="poc"))

        summary, detail = await _bases(db_session, ticket)

        assert summary.severity is detail.severity is severity
        assert summary.exploitation is ExploitationLevel.LIKELY

    @pytest.mark.parametrize(
        "severity",
        [Severity.CRITICAL, Severity.NONE, None],
        ids=["critical", "none-label", "unset"],
    )
    async def test_ticket_without_cve_uses_its_manual_severity_and_no_evidence(
        self,
        db_session: AsyncSession,
        ticket_factory: Factory,
        severity: Severity | None,
    ) -> None:
        ticket: Ticket = await ticket_factory(
            severity_manual=severity.value if severity else None
        )

        summary, detail = await _bases(db_session, ticket)

        assert (
            summary
            == detail
            == PriorityBasisProjection(
                severity=severity,
                exploitation=ExploitationLevel.UNKNOWN,
                evidence=(),
            )
        )
