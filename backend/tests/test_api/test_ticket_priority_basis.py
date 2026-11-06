"""End-to-end tests for `priority_automatic_basis` in `TicketSummary` and
`TicketDetail` (`GET /api/v1/tickets`, `GET /api/v1/tickets/{ticket_id}`,
and the mutation responses).

Owning specifications:

- docs/features/tickets/ticket-priority.md (Exploitation Level; Decision
  Table; Refresh Points; Automatic Priority Basis; Testing Requirement 10).
- docs/features/tickets/tickets.md (PriorityBasis; PriorityEvidence;
  TicketSummary; TicketDetail; Create Ticket; Set Priority Override).

Each Decision Table cell is reached through a refresh point,
`cve_service.upsert_cve()` with an evidence payload, never through a
factory that writes `priority_auto`, so the agreement of the basis with
`priority_automatic` in the same response is the persisted state of a real
workflow. Expected cells and wire values are transcribed from the
specification. The post-mutation basis of `POST .../associate-cve` and
`PATCH .../severity` is asserted in their endpoint tests; the reads of
every evidence combination in tests/test_services/test_ticket_priority_basis.py.
All identifiers are fictional.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import date
from typing import Any

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    CVESourceType,
    Role,
    Severity,
    SSVCAutomatable,
    SSVCExploitation,
    SSVCTechnicalImpact,
)
from app.core.identifiers import format_ticket_id
from app.main import app
from app.models.ticket import Ticket
from app.models.user import User
from app.services import cve_service
from app.services.cve_ingest import CVEIngestPayload, EPSSEntry, KEVEntry, SSVCEntry
from tests.support.cve_ingest import create_default_cvss_version

pytestmark = pytest.mark.usefixtures("no_fetch_single_sources")
"""An empty fetch-single registry: the freshness refresh of a manual
creation takes its no-eligible-source branch."""

Factory = Callable[..., Awaitable[Any]]

_PATH = "/api/v1/tickets"
_KEV_DATE = date(2099, 1, 15)
_EPSS_PERCENTILE = 0.97

_P1, _P2, _P3, _P4 = "p1", "p2", "p3", "p4"
# ticket-priority.md (Decision Table). Columns: Critical, High, Medium,
# Low or None, Severity NULL.
_DECISION_TABLE: dict[str, tuple[str | None, ...]] = {
    "kev": (_P1, _P1, _P1, _P1, _P1),
    "active": (_P1, _P1, _P2, _P3, _P2),
    "likely": (_P2, _P2, _P3, _P4, _P3),
    "unknown": (_P2, _P3, _P4, _P4, None),
}
_COLUMNS: tuple[tuple[Severity | None, int], ...] = (
    (Severity.CRITICAL, 0),
    (Severity.HIGH, 1),
    (Severity.MEDIUM, 2),
    (Severity.LOW, 3),
    (Severity.NONE, 3),
    (None, 4),
)


def _ssvc(exploitation: SSVCExploitation) -> SSVCEntry:
    return SSVCEntry(
        exploitation=exploitation,
        automatable=SSVCAutomatable.NO,
        technical_impact=SSVCTechnicalImpact.PARTIAL,
        version="2.0.3",
    )


_EPSS = EPSSEntry(score=0.01, percentile=_EPSS_PERCENTILE, assessed_at=_KEV_DATE)

_LEVELS: dict[str, tuple[CVEIngestPayload, list[dict[str, Any]]]] = {
    "kev": (
        CVEIngestPayload(kev_data=KEVEntry(date_added=_KEV_DATE)),
        [{"kind": "kev", "value": "2099-01-15"}],
    ),
    "active": (
        CVEIngestPayload(ssvc_assessment=_ssvc(SSVCExploitation.ACTIVE)),
        [{"kind": "ssvc_exploitation", "value": "active"}],
    ),
    "likely": (
        CVEIngestPayload(ssvc_assessment=_ssvc(SSVCExploitation.POC), epss_score=_EPSS),
        [
            {"kind": "ssvc_exploitation", "value": "poc"},
            {"kind": "epss_percentile", "value": _EPSS_PERCENTILE},
        ],
    ),
    "unknown": (CVEIngestPayload(), []),
}
"""The evidence-only payload of each level and the wire evidence it decides
(ticket-priority.md, Exploitation Level: `likely` lists SSVC `poc` and a
qualifying percentile, both when both hold)."""


def _cells() -> list[Any]:
    return [
        pytest.param(
            level,
            severity,
            _DECISION_TABLE[level][column],
            id=f"{level}-{severity.value.lower() if severity else 'null'}",
        )
        for level in _DECISION_TABLE
        for severity, column in _COLUMNS
    ]


@pytest.fixture
def authenticated_user(
    _authenticated_user_and_client: tuple[User, AsyncClient],
) -> User:
    """The role-less `User` behind `authenticated_client`."""
    return _authenticated_user_and_client[0]


@pytest_asyncio.fixture
async def va_user(authenticated_user: User, user_role_factory: Factory) -> User:
    """`authenticated_client`'s user holding only `vulnerability_analyst`
    (`create_ticket` and `triage_ticket`)."""
    await user_role_factory(
        user_id=authenticated_user.id, role=Role.VULNERABILITY_ANALYST.value
    )
    return authenticated_user


@pytest_asyncio.fixture
async def default_setting(system_setting_factory: Factory) -> None:
    """The persisted `default_cvss_version` (the test schema has none)."""
    await create_default_cvss_version(system_setting_factory)


async def _ingested_ticket(
    db: AsyncSession,
    cve_factory: Factory,
    ticket_factory: Factory,
    *,
    severity: Severity | None,
    payload: CVEIngestPayload,
) -> Ticket:
    """A Ticket of a CVE with `severity` whose evidence arrives through
    `upsert_cve()`, the refresh point that sets its `priority_auto`."""
    cve = await cve_factory(severity=severity.value if severity else None)
    ticket: Ticket = await ticket_factory(cve_id=cve.id)
    await cve_service.upsert_cve(db, cve.cve_id, CVESourceType.NVD, payload)
    return ticket


async def _summary_and_detail(
    client: AsyncClient, ticket: Ticket
) -> tuple[dict[str, Any], dict[str, Any]]:
    sntl = format_ticket_id(ticket.sequence_id)
    listed = await client.get(_PATH, params={"search": sntl})
    detail = await client.get(f"{_PATH}/{sntl}")
    assert listed.status_code == detail.status_code == 200
    (summary,) = [i for i in listed.json()["data"] if i["ticket_id"] == sntl]
    data: dict[str, Any] = detail.json()["data"]
    return summary, data


@pytest.mark.e2e
@pytest.mark.usefixtures("default_setting")
class TestBasisAgreesWithAutomaticPriority:
    @pytest.mark.parametrize(("level", "severity", "cell"), _cells())
    async def test_each_cell_reached_through_a_refresh_point(
        self,
        authenticated_client: AsyncClient,
        db_session: AsyncSession,
        cve_factory: Factory,
        ticket_factory: Factory,
        level: str,
        severity: Severity | None,
        cell: str | None,
    ) -> None:
        payload, evidence = _LEVELS[level]
        ticket = await _ingested_ticket(
            db_session,
            cve_factory,
            ticket_factory,
            severity=severity,
            payload=payload,
        )

        summary, detail = await _summary_and_detail(authenticated_client, ticket)

        basis = {
            "severity": severity.value.lower() if severity else None,
            "exploitation": level,
            "evidence": evidence,
        }
        for data in (summary, detail):
            assert data["priority_automatic"] == data["priority"] == cell
            assert data["priority_override"] is None
            assert data["priority_automatic_basis"] == basis


@pytest.mark.e2e
@pytest.mark.usefixtures("default_setting")
class TestBasisInMutationResponses:
    async def test_override_leaves_the_basis_unchanged(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        cve_factory: Factory,
        ticket_factory: Factory,
    ) -> None:
        payload, evidence = _LEVELS["kev"]
        ticket = await _ingested_ticket(
            db_session,
            cve_factory,
            ticket_factory,
            severity=Severity.LOW,
            payload=payload,
        )
        sntl = format_ticket_id(ticket.sequence_id)

        response = await authenticated_client.patch(
            f"{_PATH}/{sntl}/priority", json={"priority": "p4"}
        )
        summary, detail = await _summary_and_detail(authenticated_client, ticket)

        assert response.status_code == 200
        basis = {"severity": "low", "exploitation": "kev", "evidence": evidence}
        for data in (response.json()["data"], summary, detail):
            assert (
                data["priority"],
                data["priority_automatic"],
                data["priority_override"],
            ) == ("p4", "p1", "p4")
            assert data["priority_automatic_basis"] == basis

    async def test_creation_with_an_existing_cve_returns_its_evidence_basis(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        cve_factory: Factory,
        cve_ssvc_assessment_factory: Factory,
        cve_epss_score_factory: Factory,
    ) -> None:
        # The evidence is persisted before the creation: the on-demand
        # fetch of a new CVE runs only after the commit.
        cve = await cve_factory(severity=Severity.MEDIUM.value)
        await cve_ssvc_assessment_factory(cve_id=cve.id, exploitation="poc")
        await cve_epss_score_factory(cve_id=cve.id, percentile=0.95)

        response = await authenticated_client.post(_PATH, json={"cve_id": cve.cve_id})

        assert response.status_code == 201
        data = response.json()["data"]
        # Medium with `likely` is the P3 cell.
        assert data["priority"] == data["priority_automatic"] == "p3"
        assert data["priority_automatic_basis"] == {
            "severity": "medium",
            "exploitation": "likely",
            "evidence": [
                {"kind": "ssvc_exploitation", "value": "poc"},
                {"kind": "epss_percentile", "value": 0.95},
            ],
        }


@pytest.mark.unit
class TestOpenApiContract:
    def test_basis_and_evidence_publish_their_response_enums(self) -> None:
        schemas: dict[str, Any] = app.openapi()["components"]["schemas"]

        for name in ("TicketSummary", "TicketDetail"):
            properties = schemas[name]["properties"]
            assert properties["priority_automatic_basis"]["$ref"] == (
                "#/components/schemas/PriorityBasis"
            )
            assert "priority_automatic_basis" in schemas[name]["required"]
        basis = schemas["PriorityBasis"]
        assert set(basis["properties"]) == {"severity", "exploitation", "evidence"}
        assert set(basis["required"]) == {"severity", "exploitation", "evidence"}
        assert schemas["ExploitationLevel"]["enum"] == [
            "kev",
            "active",
            "likely",
            "unknown",
        ]
        assert basis["properties"]["evidence"]["items"] == {
            "$ref": "#/components/schemas/PriorityEvidence"
        }
        evidence = schemas["PriorityEvidence"]
        assert evidence["discriminator"] == {
            "propertyName": "kind",
            "mapping": {
                "kev": "#/components/schemas/KEVPriorityEvidence",
                "ssvc_exploitation": (
                    "#/components/schemas/SSVCExploitationPriorityEvidence"
                ),
                "epss_percentile": (
                    "#/components/schemas/EPSSPercentilePriorityEvidence"
                ),
            },
        }
        kev = schemas["KEVPriorityEvidence"]["properties"]["value"]
        ssvc = schemas["SSVCExploitationPriorityEvidence"]["properties"]["value"]
        epss = schemas["EPSSPercentilePriorityEvidence"]["properties"]["value"]
        assert (kev["type"], kev["format"]) == ("string", "date")
        assert ssvc["$ref"] == "#/components/schemas/SSVCExploitationEvidenceValue"
        assert schemas["SSVCExploitationEvidenceValue"]["enum"] == ["active", "poc"]
        assert epss["type"] == "number"
