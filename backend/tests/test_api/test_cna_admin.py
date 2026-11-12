"""End-to-end tests for the administrative CNA endpoints: Set CNA
Auto-Ignore (`PATCH /api/v1/admin/cnas/{org_id}`) and List CNA Audit Events
(`GET /api/v1/admin/cnas/audit-log`).

See docs/features/tickets/cna.md (Set CNA Auto-Ignore; List CNA Audit
Events; CNA Audit Log; Security; Testing Requirements, items 5 and 6),
docs/api-spec.md (CNA Identifier Resolution; Partial Update Semantics: a
single-field PATCH; JSON Request Body Scalar Types; Enum Filter Validation;
Date Range Interpretation; Pagination; Global Responses), and
docs/features/identity/rbac.md (Endpoint Permission Map: both endpoints
require `manage_settings`).

These tests cover the HTTP contract: authentication and the capability,
the request body, the `{org_id}` locator, the wire format of the response
and of the audit events, query validation, handler delegation, and the
OpenAPI document. Classification, locking, filtering, and paging semantics
are covered by `tests/test_services/test_cna_policy_service.py` and
`tests/test_services/test_cna_policy_atomicity.py`.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any, Final
from unittest.mock import AsyncMock

import pytest
from httpx import AsyncClient
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import CNAAuditEventType
from app.core.identifiers import CNA_ORG_ID_PATTERN
from app.main import app
from app.models.cna import CNA
from app.models.cna_audit_event import CNAAuditEvent
from app.models.user import User
from app.services import cna_service
from app.services.cna_service import CNAAuditEventListResult
from tests.support.ticket_api import UNAUTHENTICATED

Factory = Callable[..., Awaitable[Any]]

_ORG_ID: Final = "00000000-0000-4000-8000-0000000000a2"
_PATCH: Final = "/api/v1/admin/cnas/{org_id}"
_AUDIT_LOG: Final = "/api/v1/admin/cnas/audit-log"
_NOT_FOUND: Final = {"code": "CNA_NOT_FOUND", "detail": "CNA not found."}
_FORBIDDEN: Final = {
    "code": "AUTH_INSUFFICIENT_PERMISSION",
    "detail": "Insufficient permissions",
}
_CREATED: Final = datetime(2026, 11, 9, 10, 0, tzinfo=UTC)
_UPDATED: Final = datetime(2026, 11, 9, 10, 5, tzinfo=UTC)
_EVENT_AT: Final = datetime(2026, 11, 9, 10, 10, tzinfo=UTC)


def _url(org_id: str = _ORG_ID) -> str:
    return _PATCH.format(org_id=org_id)


@pytest.fixture
def admin(_authenticated_user_and_client: tuple[User, AsyncClient]) -> User:
    """The user of `admin_client` (and of `authenticated_client`)."""
    return _authenticated_user_and_client[0]


async def _plugin_cna(cna_factory: Factory, db: AsyncSession, **values: Any) -> CNA:
    cna: CNA = await cna_factory(
        org_id=uuid.UUID(_ORG_ID),
        short_name="fictional-plugins",
        organization_name="Fictional Plugin Foundation",
        types=["Open Source"],
        **values,
    )
    await db.execute(
        update(CNA)
        .where(CNA.id == cna.id)
        .values(created_at=_CREATED, updated_at=_UPDATED)
    )
    await db.refresh(cna)
    return cna


async def _events(db: AsyncSession, cna: CNA) -> list[tuple[Any, ...]]:
    rows = await db.execute(
        select(CNAAuditEvent.event_type, CNAAuditEvent.user_id, CNAAuditEvent.detail)
        .where(CNAAuditEvent.cna_id == cna.id)
        .order_by(CNAAuditEvent.id)
    )
    return [tuple(row) for row in rows.all()]


# ---------------------------------------------------------------------------
# Set CNA Auto-Ignore
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestSetCnaAutoIgnore:
    async def test_admin_enables_the_policy_with_one_event(
        self,
        admin_client: AsyncClient,
        admin: User,
        db_session: AsyncSession,
        cna_factory: Factory,
    ) -> None:
        cna = await _plugin_cna(cna_factory, db_session)

        response = await admin_client.patch(_url(), json={"auto_ignore": True})

        assert response.status_code == 200
        data = response.json()["data"]
        updated_at = data.pop("updated_at")
        assert data == {
            "org_id": _ORG_ID,
            "name": "Fictional Plugin Foundation",
            "short_name": "fictional-plugins",
            "organization_name": "Fictional Plugin Foundation",
            "types": ["Open Source"],
            "scope": None,
            "auto_ignore": True,
            "created_at": "2026-11-09T10:00:00Z",
        }
        assert updated_at != "2026-11-09T10:05:00Z"
        assert await _events(db_session, cna) == [
            (
                "auto_ignore_enabled",
                admin.id,
                {"cna_name": "Fictional Plugin Foundation"},
            )
        ]

    async def test_unchanged_request_is_a_success_without_event(
        self,
        admin_client: AsyncClient,
        db_session: AsyncSession,
        cna_factory: Factory,
    ) -> None:
        cna = await _plugin_cna(cna_factory, db_session)

        response = await admin_client.patch(_url(), json={"auto_ignore": False})

        assert response.status_code == 200
        assert response.json()["data"]["auto_ignore"] is False
        assert response.json()["data"]["updated_at"] == "2026-11-09T10:05:00Z"
        assert await _events(db_session, cna) == []

    async def test_disable_records_the_disabled_event(
        self,
        admin_client: AsyncClient,
        admin: User,
        db_session: AsyncSession,
        cna_factory: Factory,
    ) -> None:
        cna = await _plugin_cna(cna_factory, db_session, auto_ignore=True)

        response = await admin_client.patch(
            _url(_ORG_ID.upper()), json={"auto_ignore": False}
        )

        assert response.status_code == 200
        assert response.json()["data"]["auto_ignore"] is False
        assert [event[:2] for event in await _events(db_session, cna)] == [
            ("auto_ignore_disabled", admin.id)
        ]

    @pytest.mark.parametrize(
        "org_id",
        [
            "000000000000400080000000000000a2",
            "{00000000-0000-4000-8000-0000000000a2}",
            "urn:uuid:00000000-0000-4000-8000-0000000000a2",
            "fictional-plugins",
            str(uuid.UUID(int=7)),
        ],
        ids=["unhyphenated", "braced", "urn", "short-name", "unknown"],
    )
    async def test_malformed_or_unknown_org_id_is_not_found(
        self,
        admin_client: AsyncClient,
        db_session: AsyncSession,
        cna_factory: Factory,
        org_id: str,
    ) -> None:
        cna = await _plugin_cna(cna_factory, db_session)

        response = await admin_client.patch(_url(org_id), json={"auto_ignore": True})

        assert response.status_code == 404
        assert response.json() == _NOT_FOUND
        assert await _events(db_session, cna) == []

    @pytest.mark.parametrize(
        ("body", "error_type"),
        [
            pytest.param(None, "missing", id="absent-body"),
            pytest.param({}, "missing", id="omitted-member"),
            pytest.param({"auto_ignore": None}, "bool_type", id="null"),
            pytest.param({"auto_ignore": "true"}, "bool_type", id="string"),
            pytest.param({"auto_ignore": 1}, "bool_type", id="integer"),
        ],
    )
    async def test_invalid_body_is_the_global_422_without_effect(
        self,
        admin_client: AsyncClient,
        db_session: AsyncSession,
        cna_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        body: dict[str, Any] | None,
        error_type: str,
    ) -> None:
        cna = await _plugin_cna(cna_factory, db_session)
        mutation = AsyncMock()
        monkeypatch.setattr(cna_service, "set_cna_auto_ignore", mutation)

        response = await admin_client.patch(_url(), json=body)

        assert response.status_code == 422
        payload = response.json()
        assert payload["code"] == "VALIDATION_ERROR"
        assert [error["type"] for error in payload["errors"]] == [error_type]
        mutation.assert_not_awaited()
        assert await _events(db_session, cna) == []

    async def test_caller_without_manage_settings_is_forbidden_before_lookup(
        self,
        authenticated_client: AsyncClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The capability check precedes the CNA lookup: an unknown CNA also
        returns `403`."""
        mutation = AsyncMock()
        monkeypatch.setattr(cna_service, "set_cna_auto_ignore", mutation)

        response = await authenticated_client.patch(
            _url(str(uuid.uuid4())), json={"auto_ignore": True}
        )

        assert response.status_code == 403
        assert response.json() == _FORBIDDEN
        mutation.assert_not_awaited()

    async def test_unauthenticated_is_401(self, client: AsyncClient) -> None:
        response = await client.patch(_url(), json={"auto_ignore": True})

        assert response.status_code == 401
        assert response.json() == UNAUTHENTICATED


# ---------------------------------------------------------------------------
# List CNA Audit Events
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestListCnaAuditEvents:
    async def test_returns_the_events_in_the_specified_shape(
        self,
        admin_client: AsyncClient,
        admin: User,
        db_session: AsyncSession,
        cna_factory: Factory,
    ) -> None:
        """`cna` is the current reference and `detail.cna_name` the
        event-time name; `actor` is the complete current user reference."""
        cna = await _plugin_cna(cna_factory, db_session)
        await admin_client.patch(_url(), json={"auto_ignore": True})
        await db_session.execute(
            update(CNAAuditEvent)
            .where(CNAAuditEvent.cna_id == cna.id)
            .values(created_at=_EVENT_AT)
        )
        await db_session.execute(
            update(CNA)
            .where(CNA.id == cna.id)
            .values(organization_name="Renamed Plugin Foundation")
        )
        [event_id] = (
            await db_session.scalars(
                select(CNAAuditEvent.id).where(CNAAuditEvent.cna_id == cna.id)
            )
        ).all()

        response = await admin_client.get(_AUDIT_LOG, params={"cna": _ORG_ID})

        assert response.status_code == 200
        assert response.json() == {
            "data": [
                {
                    "id": str(event_id),
                    "event_type": "auto_ignore_enabled",
                    "cna": {"org_id": _ORG_ID, "name": "Renamed Plugin Foundation"},
                    "detail": {"cna_name": "Fictional Plugin Foundation"},
                    "actor": {
                        "id": str(admin.id),
                        "username": admin.username,
                        "full_name": admin.full_name,
                        "active": True,
                        "bot": False,
                        "avatar_url": None,
                    },
                    "created_at": "2026-11-09T10:10:00Z",
                }
            ],
            "meta": {"total": 1, "page": 1, "per_page": 20},
        }

    async def test_handler_delegates_the_parsed_filters(
        self,
        admin_client: AsyncClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The `cna` value reaches the service as a UUID and an omitted
        `event_type` as `None`; the dates are parsed by the shared parser."""
        listing = AsyncMock(
            return_value=CNAAuditEventListResult(items=(), total=0, page=2, per_page=5)
        )
        monkeypatch.setattr(cna_service, "list_cna_audit_events", listing)

        response = await admin_client.get(
            _AUDIT_LOG,
            params={
                "cna": _ORG_ID.upper(),
                "actor": "system",
                "from_date": "2026-11-01",
                "to_date": "2026-11-09T12:00:00Z",
                "page": 2,
                "per_page": 5,
            },
        )

        assert response.status_code == 200
        assert response.json() == {
            "data": [],
            "meta": {"total": 0, "page": 2, "per_page": 5},
        }
        assert listing.await_args is not None
        kwargs = listing.await_args.kwargs
        assert kwargs["event_type"] is None
        assert kwargs["cna"] == uuid.UUID(_ORG_ID)
        assert kwargs["actor"] == "system"
        assert kwargs["from_date"].isoformat() == "2026-11-01"
        assert kwargs["to_date"] == datetime(2026, 11, 9, 12, tzinfo=UTC)
        assert (kwargs["page"], kwargs["per_page"]) == (2, 5)

    async def test_invalid_event_types_yield_an_empty_page(
        self,
        admin_client: AsyncClient,
        db_session: AsyncSession,
        cna_factory: Factory,
    ) -> None:
        await _plugin_cna(cna_factory, db_session)
        await admin_client.patch(_url(), json={"auto_ignore": True})

        valid = await admin_client.get(
            _AUDIT_LOG,
            params={"cna": _ORG_ID, "event_type": ["auto_ignore_enabled", "x"]},
        )
        invalid = await admin_client.get(
            _AUDIT_LOG, params={"cna": _ORG_ID, "event_type": "x"}
        )

        assert valid.json()["meta"]["total"] == 1
        assert invalid.status_code == 200
        assert invalid.json() == {
            "data": [],
            "meta": {"total": 0, "page": 1, "per_page": 20},
        }

    async def test_unknown_cna_yields_an_empty_page(
        self, admin_client: AsyncClient
    ) -> None:
        response = await admin_client.get(_AUDIT_LOG, params={"cna": str(uuid.uuid4())})

        assert response.status_code == 200
        assert response.json()["data"] == []

    @pytest.mark.parametrize(
        ("params", "loc"),
        [
            ({"cna": "000000000000400080000000000000a2"}, ["query", "cna"]),
            ({"cna": "fictional-plugins"}, ["query", "cna"]),
            ({"per_page": 101}, ["query", "per_page"]),
            ({"page": 0}, ["query", "page"]),
            ({"from_date": "yesterday"}, ["query", "from_date"]),
        ],
    )
    async def test_invalid_query_is_the_global_422(
        self,
        admin_client: AsyncClient,
        params: dict[str, Any],
        loc: list[str],
    ) -> None:
        response = await admin_client.get(_AUDIT_LOG, params=params)

        assert response.status_code == 422
        payload = response.json()
        assert payload["code"] == "VALIDATION_ERROR"
        assert [error["loc"] for error in payload["errors"]] == [loc]

    async def test_inverted_date_range_is_400(self, admin_client: AsyncClient) -> None:
        response = await admin_client.get(
            _AUDIT_LOG, params={"from_date": "2026-11-09", "to_date": "2026-11-01"}
        )

        assert response.status_code == 400
        assert response.json()["code"] == "DATE_RANGE_INVERTED"

    async def test_caller_without_manage_settings_is_forbidden(
        self, authenticated_client: AsyncClient
    ) -> None:
        response = await authenticated_client.get(_AUDIT_LOG)

        assert response.status_code == 403
        assert response.json() == _FORBIDDEN

    async def test_unauthenticated_is_401(self, client: AsyncClient) -> None:
        response = await client.get(_AUDIT_LOG)

        assert response.status_code == 401
        assert response.json() == UNAUTHENTICATED


# ---------------------------------------------------------------------------
# OpenAPI document
# ---------------------------------------------------------------------------


def _operation(path: str, method: str) -> dict[str, Any]:
    operation: dict[str, Any] = app.openapi()["paths"][path][method]
    return operation


def _parameters(path: str, method: str) -> dict[str, dict[str, Any]]:
    return {p["name"]: p for p in _operation(path, method).get("parameters", [])}


@pytest.mark.unit
class TestOpenApiContract:
    def test_admin_operations_with_the_cna_tag(self) -> None:
        paths = app.openapi()["paths"]

        assert set(paths["/api/v1/admin/cnas/{org_id}"]) == {"patch"}
        assert set(paths[_AUDIT_LOG]) == {"get"}
        for path, method in ((_PATCH, "patch"), (_AUDIT_LOG, "get")):
            operation = _operation(path, method)
            assert operation["summary"]
            assert "manage_settings" in operation["description"]
            assert operation["tags"] == ["CNAs"]
            assert (
                "AUTH_INSUFFICIENT_PERMISSION"
                in (operation["responses"]["403"]["description"])
            )

    def test_set_auto_ignore_declares_its_body_and_not_found(self) -> None:
        operation = _operation(_PATCH, "patch")
        schemas = app.openapi()["components"]["schemas"]

        assert "CNA_NOT_FOUND" in operation["responses"]["404"]["description"]
        assert operation["requestBody"]["required"] is True
        body = schemas["CNAAutoIgnoreRequest"]
        assert body["required"] == ["auto_ignore"]
        assert body["properties"]["auto_ignore"]["type"] == "boolean"
        assert "default" not in body["properties"]["auto_ignore"]
        org_id = _parameters(_PATCH, "patch")["org_id"]
        # A locator: its grammar is stated, not published as a keyword.
        assert "pattern" not in org_id["schema"]

    def test_audit_log_declares_exactly_the_specified_parameters(self) -> None:
        parameters = _parameters(_AUDIT_LOG, "get")

        assert set(parameters) == {
            "page",
            "per_page",
            "event_type",
            "cna",
            "actor",
            "from_date",
            "to_date",
        }
        assert parameters["cna"]["schema"]["pattern"] == CNA_ORG_ID_PATTERN.pattern
        assert parameters["event_type"]["schema"]["items"]["enum"] == [
            member.value for member in CNAAuditEventType
        ]
        assert (
            "DATE_RANGE_INVERTED"
            in (_operation(_AUDIT_LOG, "get")["responses"]["400"]["description"])
        )

    def test_audit_event_schema(self) -> None:
        schemas = app.openapi()["components"]["schemas"]
        event = schemas["CNAAuditEventData"]

        assert set(event["properties"]) == {
            "id",
            "event_type",
            "cna",
            "detail",
            "actor",
            "created_at",
        }
        assert set(event["required"]) == set(event["properties"])
        assert event["properties"]["cna"]["$ref"].endswith("/CNASummary")
        assert event["properties"]["actor"]["$ref"].endswith("/UserReference")
