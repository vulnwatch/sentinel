"""End-to-end tests for Search Maintained Packages
(`GET /api/v1/maintained-packages`, `backend/app/api/v1/maintained_packages.py`).

See docs/features/packages/maintained-package-names.md (API Endpoints,
Search Maintained Packages; Security; Test Requirements, Search) and
docs/api-spec.md (Query Parameter Length Limit; Undeclared Query Parameters;
Pagination; Response Format; Global Responses).

These tests cover the HTTP contract: the envelope, request validation,
authentication, handler delegation, independence from SMELT, and OpenAPI.
Matching, letter case, order, bounds, and the snapshot races are covered by
`tests/test_services/test_packages/test_maintained_package_names.py`.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from collections.abc import Awaitable, Callable
from typing import Any, Final
from unittest.mock import AsyncMock

import httpx
import pytest
from httpx import AsyncClient
from sqlalchemy import event, insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.api import dependencies
from app.api.dependencies import SESSION_COOKIE_NAME
from app.config import settings
from app.main import app
from app.models.api_key import ApiKey
from app.models.maintained_package import MaintainedPackage
from app.models.user import User
from app.services.packages import maintained_package_names
from app.services.packages.maintained_package_names import MaintainedPackagePage
from tests.support.ticket_api import UNAUTHENTICATED

_PATH: Final = "/api/v1/maintained-packages"
_EMPTY_PAGE: Final = {"data": [], "meta": {"total": 0, "page": 1, "per_page": 20}}
_TOO_LONG_MSG: Final = "String should have at most 500 characters"
_CALLER_RESOLUTION: Final = re.compile(r'\bFROM (?:session|"user"|user_role|api_key)\s')
"""A statement of the authentication dependency's caller resolution."""

_NAMES: Final = (
    "fictional-openssl",
    "fictional-openssl-3",
    "libfictional-openssl",
    "Fictional-ImageTool",
)


async def _store(db: AsyncSession, *names: str) -> None:
    await db.execute(insert(MaintainedPackage), [{"name": name} for name in names])


def _make_api_key_credential() -> tuple[str, str]:
    """Return `(plaintext_token, sha256_hex_digest)` for a synthetic key."""
    token = "stl_ak_" + secrets.token_hex(16)
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return token, digest


def _spy(
    monkeypatch: pytest.MonkeyPatch, page: MaintainedPackagePage | None = None
) -> AsyncMock:
    spy = AsyncMock(
        return_value=page
        or MaintainedPackagePage(names=(), total=0, page=1, per_page=20)
    )
    monkeypatch.setattr(maintained_package_names, "search_maintained_packages", spy)
    return spy


class _StatementRecorder:
    """Records every SQL statement executed through the session's engine."""

    def __init__(self, db: AsyncSession) -> None:
        self._engine = db.get_bind().engine
        self.statements: list[str] = []

    @property
    def handler_statements(self) -> list[str]:
        return [s for s in self.statements if not _CALLER_RESOLUTION.search(s)]

    def _record(self, *args: Any) -> None:
        self.statements.append(args[2])

    def __enter__(self) -> _StatementRecorder:
        event.listen(self._engine, "before_cursor_execute", self._record)
        return self

    def __exit__(self, *exc: object) -> None:
        event.remove(self._engine, "before_cursor_execute", self._record)


@pytest.mark.e2e
class TestSearch:
    async def test_returns_the_matching_names_in_order(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ) -> None:
        await _store(db_session, *_NAMES)

        response = await authenticated_client.get(
            _PATH, params={"search": "Fictional-OpenSSL"}
        )

        assert response.status_code == 200
        assert response.json() == {
            "data": [
                {"name": "fictional-openssl"},
                {"name": "fictional-openssl-3"},
                {"name": "libfictional-openssl"},
            ],
            "meta": {"total": 3, "page": 1, "per_page": 20},
        }

    async def test_empty_list_before_the_first_snapshot(
        self, authenticated_client: AsyncClient
    ) -> None:
        response = await authenticated_client.get(_PATH, params={"search": "openssl"})

        assert response.status_code == 200
        assert response.json() == _EMPTY_PAGE

    async def test_succeeds_while_smelt_is_unreachable_without_a_request_to_it(
        self,
        authenticated_client: AsyncClient,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Every outbound HTTP request of the application passes through
        `httpx.AsyncHTTPTransport`; the test client uses the ASGI
        transport, so a request to SMELT would reach the spy."""
        await _store(db_session, *_NAMES)
        monkeypatch.setattr(
            settings, "smelt_api_url", "https://smelt.example.invalid/api"
        )
        outbound = AsyncMock(side_effect=httpx.ConnectError("unreachable"))
        monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", outbound)

        response = await authenticated_client.get(_PATH, params={"search": "imagetool"})

        assert response.status_code == 200
        assert response.json()["data"] == [{"name": "Fictional-ImageTool"}]
        outbound.assert_not_awaited()


_INVALID_CASES: Final = [
    pytest.param({"page": 0}, "page", id="page-0"),
    pytest.param({"page": "x"}, "page", id="page-not-int"),
    pytest.param({"page": 2_147_483_648}, "page", id="page-overflow"),
    pytest.param({"per_page": 0}, "per_page", id="per-page-0"),
    pytest.param({"per_page": 101}, "per_page", id="per-page-101"),
    pytest.param({"per_page": "x"}, "per_page", id="per-page-not-int"),
]


@pytest.mark.e2e
class TestRequestValidation:
    @pytest.mark.parametrize(("params", "field"), _INVALID_CASES)
    async def test_invalid_pagination_returns_422_before_the_service(
        self,
        authenticated_client: AsyncClient,
        monkeypatch: pytest.MonkeyPatch,
        params: dict[str, Any],
        field: str,
    ) -> None:
        spy = _spy(monkeypatch)

        response = await authenticated_client.get(_PATH, params=params)

        assert response.status_code == 422
        body = response.json()
        assert body["code"] == "VALIDATION_ERROR"
        assert [error["loc"] for error in body["errors"]] == [["query", field]]
        spy.assert_not_awaited()

    async def test_a_501_character_search_is_a_422(
        self, authenticated_client: AsyncClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        spy = _spy(monkeypatch)

        response = await authenticated_client.get(_PATH, params={"search": "x" * 501})

        assert response.status_code == 422
        assert response.json() == {
            "code": "VALIDATION_ERROR",
            "detail": "Request validation failed",
            "errors": [
                {
                    "loc": ["query", "search"],
                    "msg": _TOO_LONG_MSG,
                    "type": "string_too_long",
                }
            ],
        }
        spy.assert_not_awaited()

    async def test_a_500_character_search_is_accepted(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ) -> None:
        await _store(db_session, *_NAMES)

        response = await authenticated_client.get(_PATH, params={"search": "x" * 500})

        assert response.status_code == 200
        assert response.json() == _EMPTY_PAGE

    async def test_boundary_page_values_are_accepted(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ) -> None:
        await _store(db_session, *_NAMES)

        for params, meta, size in (
            ({"per_page": 1}, {"total": 4, "page": 1, "per_page": 1}, 1),
            ({"per_page": 100}, {"total": 4, "page": 1, "per_page": 100}, 4),
            (
                {"page": 2_147_483_647, "per_page": 100},
                {"total": 4, "page": 2_147_483_647, "per_page": 100},
                0,
            ),
        ):
            response = await authenticated_client.get(_PATH, params=params)
            assert response.status_code == 200, (params, response.text)
            assert response.json()["meta"] == meta
            assert len(response.json()["data"]) == size

    async def test_undeclared_query_parameters_are_ignored(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ) -> None:
        await _store(db_session, *_NAMES)

        plain = await authenticated_client.get(_PATH)
        with_params = await authenticated_client.get(
            _PATH,
            params={"sort_by": "name", "sort_order": "desc", "q": "y" * 600},
        )

        assert plain.status_code == with_params.status_code == 200
        assert with_params.json() == plain.json()


@pytest.mark.e2e
class TestAuthentication:
    async def test_request_without_credential_returns_401_before_the_service(
        self, client: AsyncClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        spy = _spy(monkeypatch)

        response = await client.get(_PATH)

        assert response.status_code == 401
        assert response.json() == UNAUTHENTICATED
        spy.assert_not_awaited()

    async def test_role_less_session_cookie_is_accepted(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ) -> None:
        await _store(db_session, *_NAMES)

        response = await authenticated_client.get(_PATH)

        assert response.status_code == 200
        assert response.json()["meta"]["total"] == 4

    async def test_valid_api_key_is_accepted_and_processed(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        await _store(db_session, *_NAMES)
        user = await user_factory()
        token, digest = _make_api_key_credential()
        key = await api_key_factory(user_id=user.id, key_hash=digest)
        touch = AsyncMock()
        monkeypatch.setattr(dependencies._last_used_debouncer, "touch", touch)

        response = await client.get(_PATH, headers={"Authorization": f"Bearer {token}"})

        assert response.status_code == 200
        assert response.json()["meta"]["total"] == 4
        touch.assert_awaited_once()
        assert touch.await_args is not None
        assert touch.await_args.args[0] == key.id

    @pytest.mark.parametrize(
        "credential",
        [
            {"headers": {"Authorization": "Bearer invalid-token"}},
            {"headers": {"Authorization": "Bearer stl_ak_" + "0" * 32}},
            {"cookies": {SESSION_COOKIE_NAME: "invalid-session-token"}},
        ],
        ids=["bearer", "unknown-api-key", "cookie"],
    )
    async def test_invalid_selected_credential_returns_401_before_the_service(
        self,
        client: AsyncClient,
        monkeypatch: pytest.MonkeyPatch,
        credential: dict[str, dict[str, str]],
    ) -> None:
        spy = _spy(monkeypatch)
        for name, value in credential.get("cookies", {}).items():
            client.cookies.set(name, value)

        response = await client.get(_PATH, headers=credential.get("headers", {}))

        assert response.status_code == 401
        assert response.json() == UNAUTHENTICATED
        spy.assert_not_awaited()


@pytest.mark.e2e
class TestHandlerDelegation:
    async def test_defaults_reach_the_service_and_the_handler_runs_no_query(
        self,
        authenticated_client: AsyncClient,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        spy = _spy(monkeypatch)

        with _StatementRecorder(db_session) as recorder:
            response = await authenticated_client.get(_PATH)

        assert response.status_code == 200
        assert response.json() == _EMPTY_PAGE
        assert recorder.handler_statements == []
        spy.assert_awaited_once()
        assert spy.await_args is not None
        assert spy.await_args.args == (db_session,)
        assert spy.await_args.kwargs == {"search": None, "page": 1, "per_page": 20}

    async def test_raw_term_reaches_the_service_and_the_page_is_serialized(
        self,
        authenticated_client: AsyncClient,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        spy = _spy(
            monkeypatch,
            MaintainedPackagePage(
                names=("fictional-openssl-3",), total=9, page=3, per_page=4
            ),
        )

        response = await authenticated_client.get(
            _PATH, params={"search": "  Fictional%_\\  ", "page": 3, "per_page": 4}
        )

        assert response.status_code == 200
        assert response.json() == {
            "data": [{"name": "fictional-openssl-3"}],
            "meta": {"total": 9, "page": 3, "per_page": 4},
        }
        assert spy.await_args is not None
        assert spy.await_args.kwargs == {
            "search": "  Fictional%_\\  ",
            "page": 3,
            "per_page": 4,
        }


def _operation() -> dict[str, Any]:
    operation: dict[str, Any] = app.openapi()["paths"][_PATH]["get"]
    return operation


@pytest.mark.unit
class TestOpenApiContract:
    def test_operation_has_summary_description_and_tag(self) -> None:
        assert set(app.openapi()["paths"][_PATH]) == {"get"}
        operation = _operation()

        assert operation["summary"] == "Search Maintained Packages"
        assert operation["description"]
        assert operation["tags"] == ["Maintained Packages"]

    def test_declares_exactly_the_specified_query_parameters(self) -> None:
        parameters = {p["name"]: p for p in _operation()["parameters"]}

        assert set(parameters) == {"search", "page", "per_page"}
        assert all(p["in"] == "query" for p in parameters.values())
        assert not any(p.get("required", False) for p in parameters.values())
        assert parameters["search"]["schema"]["type"] == "string"
        assert parameters["search"]["schema"]["maxLength"] == 500
        per_page = parameters["per_page"]["schema"]
        assert (per_page["minimum"], per_page["maximum"], per_page["default"]) == (
            1,
            100,
            20,
        )
        page = parameters["page"]["schema"]
        assert (page["minimum"], page["maximum"], page["default"]) == (
            1,
            2_147_483_647,
            1,
        )

    def test_responses_are_the_derived_ones_only(self) -> None:
        """Access: Authenticated with no endpoint-specific error: `401`,
        `422`, and `500`, and no `SMELT_UNAVAILABLE`."""
        responses = _operation()["responses"]

        assert set(responses) == {"200", "401", "422", "500"}
        assert "SMELT_UNAVAILABLE" not in str(responses)

    def test_response_schema_exposes_exactly_the_name(self) -> None:
        schemas = app.openapi()["components"]["schemas"]
        response = _operation()["responses"]["200"]["content"]["application/json"]

        assert response["schema"]["$ref"].endswith("/MaintainedPackageListResponse")
        envelope = schemas["MaintainedPackageListResponse"]
        assert set(envelope["properties"]) == {"data", "meta"}
        assert envelope["properties"]["data"]["items"]["$ref"].endswith(
            "/MaintainedPackageItem"
        )
        item = schemas["MaintainedPackageItem"]
        assert set(item["properties"]) == {"name"}
        assert item["required"] == ["name"]
        assert item["properties"]["name"]["type"] == "string"
