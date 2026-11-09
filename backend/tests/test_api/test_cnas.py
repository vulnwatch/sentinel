"""End-to-end tests for the CNA read endpoints and the `cna` filters.

See docs/features/tickets/cna.md (API Endpoints: Response Schemas, List
CNAs, Get CNA; Security; Testing Requirements, item 6), docs/api-spec.md
(CNA Identifier Resolution; Published Input Constraints; Query Parameter
Length Limit; Pagination; Sort Parameter Validation; Response Format;
Global Responses), docs/features/tickets/tickets.md (List Tickets: `cna`;
`CVESummary`), docs/features/tickets/cve-tracking.md (List CVEs: `cna`;
`CVEListItem`), and docs/features/identity/rbac.md (Endpoint Permission
Map: both reads are `Authenticated`).

These tests cover the HTTP contract: the envelope and wire format, the
display name, the `{org_id}` locator, filter validation, authentication,
handler delegation, and the OpenAPI document. Search, sorting, and paging
semantics are covered by `tests/test_services/test_cna_service.py`; the
reads and filters with visibility by `tests/test_services/test_cna_reads.py`.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any, Final
from unittest.mock import AsyncMock

import pytest
from httpx import AsyncClient
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import CNASortField, SortOrder
from app.core.identifiers import CNA_ORG_ID_PATTERN, format_ticket_id
from app.main import app
from app.models.cna import CNA
from app.models.cve import CVE
from app.models.ticket import Ticket
from app.services import cna_service, ticket_service
from app.services.cna_service import CNAListResult
from app.services.ticket_service import TicketPage
from tests.support.ticket_api import UNAUTHENTICATED

Factory = Callable[..., Awaitable[Any]]

_LIST: Final = "/api/v1/cnas"
_CREATED: Final = datetime(2026, 11, 9, 10, 0, tzinfo=UTC)
_UPDATED: Final = datetime(2026, 11, 9, 10, 5, tzinfo=UTC)
_FIELDS: Final = {
    "org_id",
    "name",
    "short_name",
    "organization_name",
    "types",
    "scope",
    "auto_ignore",
    "created_at",
    "updated_at",
}
_NOT_FOUND: Final = {"code": "CNA_NOT_FOUND", "detail": "CNA not found."}


def _detail(org_id: str) -> str:
    return f"{_LIST}/{org_id}"


async def _stamp(db: AsyncSession, cna: CNA) -> None:
    """Fixed timestamps, so the wire format is asserted exactly."""
    await db.execute(
        update(CNA)
        .where(CNA.id == cna.id)
        .values(created_at=_CREATED, updated_at=_UPDATED)
    )
    await db.refresh(cna)


@pytest.fixture
def token() -> str:
    """A unique fictional search token isolating this test's CNAs."""
    return f"zq{uuid.uuid4().hex[:10]}"


# ---------------------------------------------------------------------------
# Get CNA
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestGetCna:
    async def test_returns_the_complete_cna_in_the_data_envelope(
        self,
        authenticated_client: AsyncClient,
        db_session: AsyncSession,
        cna_factory: Factory,
    ) -> None:
        cna: CNA = await cna_factory(
            org_id=uuid.UUID("00000000-0000-4000-8000-0000000000a1"),
            short_name="example",
            organization_name="Example Corporation",
            types=["Open Source", "Vendor"],
            scope="Example Corporation products only.\nNothing else.",
        )
        await _stamp(db_session, cna)

        response = await authenticated_client.get(
            _detail("00000000-0000-4000-8000-0000000000A1")
        )

        assert response.status_code == 200
        assert response.json() == {
            "data": {
                "org_id": "00000000-0000-4000-8000-0000000000a1",
                "name": "Example Corporation",
                "short_name": "example",
                "organization_name": "Example Corporation",
                "types": ["Open Source", "Vendor"],
                "scope": "Example Corporation products only.\nNothing else.",
                "auto_ignore": False,
                "created_at": "2026-11-09T10:00:00Z",
                "updated_at": "2026-11-09T10:05:00Z",
            }
        }

    @pytest.mark.parametrize(
        ("short_name", "name"), [("example", "example"), (None, None)]
    )
    async def test_display_name_falls_back_and_is_never_an_identifier(
        self,
        authenticated_client: AsyncClient,
        cna_factory: Factory,
        short_name: str | None,
        name: str | None,
    ) -> None:
        cna: CNA = await cna_factory(short_name=short_name)

        data = (await authenticated_client.get(_detail(str(cna.org_id)))).json()["data"]

        assert (data["name"], data["organization_name"], data["types"]) == (
            name,
            None,
            [],
        )

    @pytest.mark.parametrize(
        "org_id",
        ["000000000000400080000000000000a1", str(uuid.uuid4())],
        ids=["unhyphenated", "unknown"],
    )
    async def test_malformed_or_unknown_org_id_is_404(
        self, authenticated_client: AsyncClient, org_id: str
    ) -> None:
        response = await authenticated_client.get(_detail(org_id))

        assert response.status_code == 404
        assert response.json() == _NOT_FOUND

    async def test_inadmissible_character_is_422_before_the_locator(
        self, authenticated_client: AsyncClient
    ) -> None:
        response = await authenticated_client.get(_detail("a%00b"))

        assert response.status_code == 422
        assert response.json()["code"] == "VALIDATION_ERROR"

    async def test_unauthenticated_request_is_401(
        self, client: AsyncClient, cna_factory: Factory
    ) -> None:
        cna: CNA = await cna_factory()

        response = await client.get(_detail(str(cna.org_id)))

        assert response.status_code == 401
        assert response.json() == UNAUTHENTICATED


# ---------------------------------------------------------------------------
# List CNAs
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestListCnas:
    async def test_paginated_envelope_with_complete_items(
        self,
        authenticated_client: AsyncClient,
        db_session: AsyncSession,
        cna_factory: Factory,
        token: str,
    ) -> None:
        cna: CNA = await cna_factory(short_name=f"{token}-a", auto_ignore=True)
        await _stamp(db_session, cna)
        await cna_factory(short_name=f"{token}-b")

        response = await authenticated_client.get(
            _LIST, params={"search": token, "per_page": 1}
        )

        assert response.status_code == 200
        body = response.json()
        assert body["meta"] == {"total": 2, "page": 1, "per_page": 1}
        [item] = body["data"]
        assert set(item) == _FIELDS
        assert item == {
            "org_id": str(cna.org_id),
            "name": f"{token}-a",
            "short_name": f"{token}-a",
            "organization_name": None,
            "types": [],
            "scope": None,
            "auto_ignore": True,
            "created_at": "2026-11-09T10:00:00Z",
            "updated_at": "2026-11-09T10:05:00Z",
        }

    async def test_filters_sort_and_order_reach_the_listing(
        self,
        authenticated_client: AsyncClient,
        cna_factory: Factory,
        token: str,
    ) -> None:
        await cna_factory(short_name=f"{token}-a", auto_ignore=True)
        await cna_factory(short_name=f"{token}-b", auto_ignore=True)
        await cna_factory(short_name=f"{token}-c")

        response = await authenticated_client.get(
            _LIST,
            params={
                "search": token,
                "auto_ignore": "true",
                "sort_by": "short_name",
                "sort_order": "desc",
            },
        )

        assert [item["short_name"] for item in response.json()["data"]] == [
            f"{token}-b",
            f"{token}-a",
        ]

    async def test_defaults_reach_the_service(
        self, authenticated_client: AsyncClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        spy = AsyncMock(
            return_value=CNAListResult(items=(), total=0, page=1, per_page=20)
        )
        monkeypatch.setattr(cna_service, "list_cnas", spy)

        response = await authenticated_client.get(_LIST)

        assert response.status_code == 200
        assert response.json() == {
            "data": [],
            "meta": {"total": 0, "page": 1, "per_page": 20},
        }
        assert spy.await_args is not None
        assert spy.await_args.kwargs == {
            "search": None,
            "auto_ignore": None,
            "page": 1,
            "per_page": 20,
            "sort_by": CNASortField.NAME,
            "sort_order": SortOrder.ASC,
        }

    @pytest.mark.parametrize(
        "params",
        [
            {"sort_by": "org_id"},
            {"sort_order": "up"},
            {"per_page": 101},
            {"page": 0},
            {"auto_ignore": "maybe"},
            {"search": "x" * 501},
        ],
    )
    async def test_invalid_parameter_is_422(
        self,
        authenticated_client: AsyncClient,
        monkeypatch: pytest.MonkeyPatch,
        params: dict[str, Any],
    ) -> None:
        spy = AsyncMock()
        monkeypatch.setattr(cna_service, "list_cnas", spy)

        response = await authenticated_client.get(_LIST, params=params)

        assert response.status_code == 422
        assert response.json()["code"] == "VALIDATION_ERROR"
        spy.assert_not_awaited()

    async def test_unauthenticated_request_is_401(self, client: AsyncClient) -> None:
        response = await client.get(_LIST)

        assert response.status_code == 401
        assert response.json() == UNAUTHENTICATED


# ---------------------------------------------------------------------------
# The CNA in the CVE and Ticket responses, and the `cna` filters
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestCNAInCVEAndTicketResponses:
    async def test_cve_and_ticket_responses_carry_the_cna_summary(
        self,
        authenticated_client: AsyncClient,
        cna_factory: Factory,
        cve_factory: Factory,
        ticket_factory: Factory,
    ) -> None:
        cna: CNA = await cna_factory(
            short_name="example", organization_name="Example Corporation"
        )
        cve: CVE = await cve_factory(cna_id=cna.id)
        ticket: Ticket = await ticket_factory(cve_id=cve.id)
        # Rows that the `cna` filters must exclude.
        other: CNA = await cna_factory()
        await ticket_factory(cve_id=(await cve_factory(cna_id=other.id)).id)
        await ticket_factory(cve_id=(await cve_factory()).id)
        await ticket_factory()
        expected = {"org_id": str(cna.org_id), "name": "Example Corporation"}
        sntl = format_ticket_id(ticket.sequence_id)

        cve_detail = await authenticated_client.get(f"/api/v1/cves/{cve.cve_id}")
        cve_list = await authenticated_client.get(
            "/api/v1/cves", params={"cna": str(cna.org_id)}
        )
        ticket_detail = await authenticated_client.get(f"/api/v1/tickets/{sntl}")
        ticket_list = await authenticated_client.get(
            "/api/v1/tickets", params={"cna": str(cna.org_id).upper()}
        )

        assert cve_detail.json()["data"]["cna"] == expected
        [cve_item] = cve_list.json()["data"]
        assert (cve_item["cve_id"], cve_item["cna"]) == (cve.cve_id, expected)
        assert ticket_detail.json()["data"]["cve"]["cna"] == expected
        [ticket_item] = ticket_list.json()["data"]
        assert (ticket_item["ticket_id"], ticket_item["cve"]["cna"]) == (
            sntl,
            expected,
        )

    async def test_cve_without_a_cna_serializes_null(
        self, authenticated_client: AsyncClient, cve_factory: Factory
    ) -> None:
        cve: CVE = await cve_factory()

        data = (await authenticated_client.get(f"/api/v1/cves/{cve.cve_id}")).json()

        assert data["data"]["cna"] is None

    @pytest.mark.parametrize("path", ["/api/v1/cves", "/api/v1/tickets"])
    async def test_unknown_cna_filter_value_is_an_empty_page(
        self,
        authenticated_client: AsyncClient,
        cna_factory: Factory,
        cve_factory: Factory,
        ticket_factory: Factory,
        path: str,
    ) -> None:
        cna: CNA = await cna_factory()
        await ticket_factory(cve_id=(await cve_factory(cna_id=cna.id)).id)
        assert (await authenticated_client.get(path)).json()["meta"]["total"] >= 1

        response = await authenticated_client.get(
            path, params={"cna": str(uuid.uuid4())}
        )

        assert response.status_code == 200
        assert response.json() == {
            "data": [],
            "meta": {"total": 0, "page": 1, "per_page": 20},
        }

    async def test_ticket_list_filter_reaches_the_service_as_uuids(
        self, authenticated_client: AsyncClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        spy = AsyncMock(return_value=TicketPage(items=(), total=0, page=1, per_page=20))
        monkeypatch.setattr(ticket_service, "list_tickets", spy)

        response = await authenticated_client.get(
            "/api/v1/tickets",
            params={
                "cna": [
                    "00000000-0000-4000-8000-0000000000A1",
                    "00000000-0000-4000-8000-0000000000a2",
                ]
            },
        )

        assert response.status_code == 200
        assert spy.await_args is not None
        assert spy.await_args.kwargs["cna"] == [
            uuid.UUID("00000000-0000-4000-8000-0000000000a1"),
            uuid.UUID("00000000-0000-4000-8000-0000000000a2"),
        ]

    async def test_omitted_ticket_list_filter_reaches_the_service_as_none(
        self, authenticated_client: AsyncClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        spy = AsyncMock(return_value=TicketPage(items=(), total=0, page=1, per_page=20))
        monkeypatch.setattr(ticket_service, "list_tickets", spy)

        await authenticated_client.get("/api/v1/tickets")

        assert spy.await_args is not None
        assert spy.await_args.kwargs["cna"] is None

    @pytest.mark.parametrize("path", ["/api/v1/cves", "/api/v1/tickets"])
    async def test_malformed_cna_filter_value_is_422(
        self, authenticated_client: AsyncClient, path: str
    ) -> None:
        """Every malformed form is pinned by the Core parser's tests
        (`tests/test_core/test_identifiers.py`); one suffices here."""
        response = await authenticated_client.get(
            path,
            params={"cna": [str(uuid.uuid4()), "000000000000400080000000000000a1"]},
        )

        assert response.status_code == 422
        body = response.json()
        assert body["code"] == "VALIDATION_ERROR"
        assert [error["loc"] for error in body["errors"]] == [["query", "cna"]]


# ---------------------------------------------------------------------------
# OpenAPI
# ---------------------------------------------------------------------------


def _operation(path: str) -> dict[str, Any]:
    operation: dict[str, Any] = app.openapi()["paths"][path]["get"]
    return operation


def _parameters(path: str) -> dict[str, dict[str, Any]]:
    return {p["name"]: p for p in _operation(path).get("parameters", [])}


@pytest.mark.unit
class TestOpenApiContract:
    def test_cna_operations_are_reads_with_the_cna_tag(self) -> None:
        paths = app.openapi()["paths"]

        assert set(paths[_LIST]) == {"get"}
        assert set(paths[f"{_LIST}/{{org_id}}"]) == {"get"}
        for path in (_LIST, f"{_LIST}/{{org_id}}"):
            operation = _operation(path)
            assert operation["summary"]
            assert operation["description"]
            assert operation["tags"] == ["CNAs"]

    def test_get_cna_declares_its_not_found_response(self) -> None:
        operation = _operation(f"{_LIST}/{{org_id}}")

        assert "CNA_NOT_FOUND" in operation["responses"]["404"]["description"]
        org_id = _parameters(f"{_LIST}/{{org_id}}")["org_id"]
        # A locator: its grammar is stated, not published as a keyword.
        assert "pattern" not in org_id["schema"]
        assert org_id["schema"]["type"] == "string"

    def test_list_cnas_declares_exactly_the_specified_parameters(self) -> None:
        parameters = _parameters(_LIST)

        assert set(parameters) == {
            "search",
            "auto_ignore",
            "page",
            "per_page",
            "sort_by",
            "sort_order",
        }
        assert not any(p.get("required", False) for p in parameters.values())

    @pytest.mark.parametrize("path", ["/api/v1/cves", "/api/v1/tickets"])
    def test_cna_filter_publishes_the_hyphenated_uuid_pattern(self, path: str) -> None:
        schema = _parameters(path)["cna"]["schema"]

        assert schema["type"] == "array"
        assert schema["items"]["pattern"] == CNA_ORG_ID_PATTERN.pattern
        assert schema["items"]["type"] == "string"

    def test_cna_summary_schema_is_the_org_id_and_the_name(self) -> None:
        schemas = app.openapi()["components"]["schemas"]

        assert set(schemas["CNASummary"]["properties"]) == {"org_id", "name"}
        assert set(schemas["CNAResponse"]["properties"]) == _FIELDS
        for owner in ("CVESummary", "CVEDetail", "CVEListItem"):
            assert "cna" in schemas[owner]["properties"]
            assert "cna" in schemas[owner]["required"]
        assert "id" not in schemas["CNAResponse"]["properties"]
