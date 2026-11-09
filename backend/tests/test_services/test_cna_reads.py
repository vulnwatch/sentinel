"""The CNA of a CVE in the CVE and Ticket reads, and their `cna` filters.

Owning specifications: docs/features/tickets/cna.md (Display Name; Response
Schemas: `CNASummary` in `CVESummary`, `CVEDetail`, and `CVEListItem`;
Security: `CNASummary` reaches a caller only inside a CVE representation
that applies CVE accessibility or Ticket visibility; Testing Requirements,
item 6), docs/features/tickets/cve-service.md (CVE List step 3 and 8; CVE
Detail step 3), docs/features/tickets/ticket-service.md (`list_tickets()`
step 3 and 6; `get_ticket_detail()` step 2), docs/features/tickets/tickets.md
(List Tickets: `cna`), and docs/features/tickets/cve-tracking.md (List CVEs:
`cna`).

Every test runs in the rolled-back `db_session`; each filter value is a
fresh fictional organization UUID, so the results contain only this test's
rows.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import CVESortField, Scope, SortOrder
from app.core.identifiers import format_ticket_id
from app.models.cna import CNA
from app.models.cve import CVE
from app.models.ticket import Ticket
from app.services.cve_projection import CNASummaryProjection
from app.services.cve_service import get_cve_detail, list_cves
from app.services.ticket_service import get_ticket_detail, list_tickets
from app.services.ticket_visibility import TicketCaller
from tests.support.callers import ROLELESS_CALLER

Factory = Callable[..., Awaitable[Any]]

ALL_SCOPE = TicketCaller.authenticated(uuid.uuid4(), Scope.ALL)


async def _cna(factory: Factory, **values: Any) -> CNA:
    cna: CNA = await factory(org_id=uuid.uuid4(), **values)
    return cna


async def _cve_list(
    db: AsyncSession, caller: TicketCaller, cna: list[uuid.UUID] | None
) -> list[str]:
    result = await list_cves(
        db,
        caller,
        search=None,
        cve_state=None,
        severity=None,
        has_ticket=None,
        cna=cna,
        from_date=None,
        to_date=None,
        page=1,
        per_page=100,
        sort_by=CVESortField.CVE_ID,
        sort_order=SortOrder.ASC,
    )
    assert result.total == len(result.items)
    return [item.cve_id for item in result.items]


async def _ticket_list(
    db: AsyncSession, caller: TicketCaller, **filters: Any
) -> list[str]:
    page = await list_tickets(db, caller=caller, per_page=100, **filters)
    assert page.total == len(page.items)
    return [item.ticket_id for item in page.items]


def _sntl(ticket: Ticket) -> str:
    return format_ticket_id(ticket.sequence_id)


@pytest.mark.integration
class TestCNASummaryProjection:
    @pytest.mark.parametrize(
        ("short_name", "organization_name", "name"),
        [
            ("example", "Example Corporation", "Example Corporation"),
            ("example", None, "example"),
            (None, None, None),
        ],
        ids=["organization-name", "short-name", "unnamed"],
    )
    async def test_every_cve_representation_carries_the_cna(
        self,
        db_session: AsyncSession,
        cna_factory: Factory,
        cve_factory: Factory,
        ticket_factory: Factory,
        short_name: str | None,
        organization_name: str | None,
        name: str | None,
    ) -> None:
        cna = await _cna(
            cna_factory, short_name=short_name, organization_name=organization_name
        )
        cve: CVE = await cve_factory(cna_id=cna.id)
        ticket: Ticket = await ticket_factory(cve_id=cve.id)
        expected = CNASummaryProjection(org_id=cna.org_id, name=name)

        listed_cves = await list_cves(
            db_session,
            ALL_SCOPE,
            search=cve.cve_id,
            cve_state=None,
            severity=None,
            has_ticket=None,
            cna=None,
            from_date=None,
            to_date=None,
            page=1,
            per_page=20,
            sort_by=CVESortField.CVE_ID,
            sort_order=SortOrder.ASC,
        )
        cve_detail = await get_cve_detail(db_session, ALL_SCOPE, cve.cve_id)
        ticket_page = await list_tickets(db_session, caller=ALL_SCOPE, cna=[cna.org_id])
        ticket_detail = await get_ticket_detail(
            db_session, ticket_id=_sntl(ticket), caller=ALL_SCOPE
        )

        [cve_item] = listed_cves.items
        [summary] = ticket_page.items
        assert summary.cve is not None
        assert ticket_detail.cve is not None
        assert cve_item.cna == expected
        assert cve_detail.cve.cna == expected
        assert summary.cve.cna == expected
        assert ticket_detail.cve.cna == expected

    async def test_cve_without_a_cna_has_none(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        ticket_factory: Factory,
    ) -> None:
        cve: CVE = await cve_factory()
        ticket: Ticket = await ticket_factory(cve_id=cve.id)

        cve_detail = await get_cve_detail(db_session, ALL_SCOPE, cve.cve_id)
        ticket_detail = await get_ticket_detail(
            db_session, ticket_id=_sntl(ticket), caller=ALL_SCOPE
        )

        assert cve_detail.cve.cna is None
        assert ticket_detail.cve is not None
        assert ticket_detail.cve.cna is None

    async def test_projection_follows_the_current_cna_of_the_cve(
        self,
        db_session: AsyncSession,
        cna_factory: Factory,
        cve_factory: Factory,
    ) -> None:
        """A transfer replaces the CNA that every read shows."""
        first = await _cna(cna_factory, short_name="first")
        second = await _cna(cna_factory, short_name="second")
        cve: CVE = await cve_factory(cna_id=first.id)
        cve.cna_id = second.id
        await db_session.flush()

        detail = await get_cve_detail(db_session, ALL_SCOPE, cve.cve_id)

        assert detail.cve.cna == CNASummaryProjection(
            org_id=second.org_id, name="second"
        )


@pytest.mark.integration
class TestCVEListFilter:
    async def test_matches_the_cves_of_any_supplied_cna(
        self,
        db_session: AsyncSession,
        cna_factory: Factory,
        cve_factory: Factory,
    ) -> None:
        first, second, other = (
            await _cna(cna_factory),
            await _cna(cna_factory),
            await _cna(cna_factory),
        )
        cve_1: CVE = await cve_factory(cna_id=first.id)
        cve_2: CVE = await cve_factory(cna_id=second.id)
        await cve_factory(cna_id=other.id)
        await cve_factory()

        listed = await _cve_list(
            db_session, ALL_SCOPE, [first.org_id, second.org_id, uuid.uuid4()]
        )

        assert listed == sorted([cve_1.cve_id, cve_2.cve_id])

    async def test_unknown_cna_matches_nothing(
        self, db_session: AsyncSession, cve_factory: Factory
    ) -> None:
        await cve_factory()

        assert await _cve_list(db_session, ALL_SCOPE, [uuid.uuid4()]) == []

    async def test_inaccessible_cve_is_excluded_from_rows_and_total(
        self,
        db_session: AsyncSession,
        cna_factory: Factory,
        cve_factory: Factory,
        ticket_factory: Factory,
    ) -> None:
        cna = await _cna(cna_factory)
        visible: CVE = await cve_factory(cna_id=cna.id)
        hidden: CVE = await cve_factory(cna_id=cna.id)
        await ticket_factory(cve_id=visible.id)
        await ticket_factory(cve_id=hidden.id, is_confidential=True)

        assert await _cve_list(db_session, ROLELESS_CALLER, [cna.org_id]) == [
            visible.cve_id
        ]
        assert await _cve_list(db_session, ALL_SCOPE, [cna.org_id]) == sorted(
            [visible.cve_id, hidden.cve_id]
        )


@pytest.mark.integration
class TestTicketListFilter:
    async def test_matches_the_tickets_whose_cve_has_a_supplied_cna(
        self,
        db_session: AsyncSession,
        cna_factory: Factory,
        cve_factory: Factory,
        ticket_factory: Factory,
    ) -> None:
        first, second = await _cna(cna_factory), await _cna(cna_factory)
        ticket_1: Ticket = await ticket_factory(
            cve_id=(await cve_factory(cna_id=first.id)).id
        )
        ticket_2: Ticket = await ticket_factory(
            cve_id=(await cve_factory(cna_id=second.id)).id
        )
        await ticket_factory(cve_id=(await cve_factory()).id)
        await ticket_factory()

        listed = await _ticket_list(
            db_session, ALL_SCOPE, cna=[first.org_id, second.org_id]
        )

        assert set(listed) == {_sntl(ticket_1), _sntl(ticket_2)}

    @pytest.mark.parametrize("values", [[], "unknown"])
    async def test_unknown_or_empty_filter_matches_nothing(
        self,
        db_session: AsyncSession,
        cna_factory: Factory,
        cve_factory: Factory,
        ticket_factory: Factory,
        values: Any,
    ) -> None:
        cna = await _cna(cna_factory)
        await ticket_factory(cve_id=(await cve_factory(cna_id=cna.id)).id)
        supplied = [] if values == [] else [uuid.uuid4()]

        assert await _ticket_list(db_session, ALL_SCOPE, cna=supplied) == []

    async def test_combines_with_other_filters_and_applies_visibility(
        self,
        db_session: AsyncSession,
        cna_factory: Factory,
        cve_factory: Factory,
        ticket_factory: Factory,
    ) -> None:
        cna = await _cna(cna_factory)
        visible: Ticket = await ticket_factory(
            cve_id=(await cve_factory(cna_id=cna.id)).id
        )
        confidential: Ticket = await ticket_factory(
            cve_id=(await cve_factory(cna_id=cna.id)).id, is_confidential=True
        )

        assert await _ticket_list(db_session, ROLELESS_CALLER, cna=[cna.org_id]) == [
            _sntl(visible)
        ]
        assert set(await _ticket_list(db_session, ALL_SCOPE, cna=[cna.org_id])) == {
            _sntl(visible),
            _sntl(confidential),
        }
        assert await _ticket_list(
            db_session, ALL_SCOPE, cna=[cna.org_id], is_confidential=True
        ) == [_sntl(confidential)]
