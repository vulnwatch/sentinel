"""End-to-end tests for `GET /api/v1/bugzilla/needinfo-count`
(`backend/app/api/v1/bugzilla.py`).

See docs/features/integrations/bugzilla-needinfo-count.md (API Endpoint >
Get Bugzilla Needinfo Count; Security and Privacy; Testing Requirements),
docs/features/identity/rbac.md (Endpoint Permission Map > Bugzilla;
Predefined Roles), docs/api-spec.md (Response Format; Infrastructure
Dependency Errors; Response Applicability Derivation), and
docs/features/platform/testing-strategy.md (API Endpoints).

These tests cover the HTTP contract: the envelope, `authenticated` for both
configurations, `503 BUGZILLA_UNAVAILABLE`, authentication and the
`triage_ticket` capability, and OpenAPI. The Response Contract, the cache,
the read coordination, and Redis failures are proven by
`tests/test_services/test_bugzilla_needinfo_service.py`. Bugzilla is the
fake `JsonRpcServer` behind the production shared HTTP client.

Capability premise (rbac.md, Predefined Roles): `vulnerability_analyst` and
`restricted_analyst` hold `triage_ticket`; `admin` and a role-less user do
not. Every value is fictional.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from typing import Any, Final

import httpx
import pytest
import redis.asyncio as redis_asyncio
from httpx import AsyncClient
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.enums import Role, SessionCreationReason
from app.main import app
from app.services.session_service import create_session
from tests.support import bugzilla_jsonrpc as rpc
from tests.support.bugzilla_jsonrpc import (
    AUTHENTICATED_FIXTURE,
    PUBLIC_TEST_BUG,
    RESTRICTED_TEST_BUG,
    JsonRpcServer,
)
from tests.support.ticket_api import FORBIDDEN, UNAUTHENTICATED

Factory = Callable[..., Awaitable[Any]]

_PATH: Final = "/api/v1/bugzilla/needinfo-count"
_API_KEY: Final = "-".join(("fictional", "bugzilla", "key", "1111"))
_SEARCH_URL: Final = (
    "https://bugzilla.suse.com/buglist.cgi?bug_status=UNCONFIRMED&bug_status=NEW"
    "&bug_status=CONFIRMED&bug_status=IN_PROGRESS&bug_status=REOPENED"
    "&f1=flagtypes.name&o1=equals&v1=needinfo%3F&f2=requestees.login_name"
    "&o2=equals&v2=security-team%40suse.de&query_format=advanced"
)
_UNAVAILABLE: Final = {
    "code": "BUGZILLA_UNAVAILABLE",
    "detail": "No valid count could be obtained from SUSE Bugzilla.",
}


@pytest.fixture
def server(monkeypatch: pytest.MonkeyPatch) -> JsonRpcServer:
    fake = JsonRpcServer()
    monkeypatch.setattr(
        httpx, "AsyncHTTPTransport", lambda **_: httpx.MockTransport(fake.handler)
    )
    return fake


@pytest.fixture
def anonymous(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "bugzilla_api_key", SecretStr(""))


@pytest.fixture
def with_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "bugzilla_api_key", SecretStr(_API_KEY))


@pytest.fixture
def headers(
    db_session: AsyncSession,
    redis_client: redis_asyncio.Redis,
    user_factory: Factory,
    user_role_factory: Factory,
) -> Callable[..., Awaitable[dict[str, str]]]:
    """A Bearer credential of a new User holding `roles`."""

    async def make(*roles: Role) -> dict[str, str]:
        suffix = uuid.uuid4().hex[:10]
        user = await user_factory(
            username=f"erin.needinfo.{suffix}",
            email=f"erin.needinfo.{suffix}@example.com",
        )
        for role in roles:
            await user_role_factory(user_id=user.id, role=role.value)
        created = await create_session(
            db_session,
            user,
            SessionCreationReason.LOCAL_LOGIN,
            expected_password_hash=None,
        )
        assert created is not None
        return {"Authorization": f"Bearer {created.token}"}

    return make


@pytest.mark.e2e
class TestGetBugzillaNeedinfoCount:
    @pytest.mark.usefixtures("anonymous")
    @pytest.mark.parametrize(
        "role", [Role.VULNERABILITY_ANALYST, Role.RESTRICTED_ANALYST]
    )
    async def test_anonymous_read_returns_the_public_count(
        self,
        client: AsyncClient,
        server: JsonRpcServer,
        headers: Callable[..., Awaitable[dict[str, str]]],
        role: Role,
    ) -> None:
        response = await client.get(_PATH, headers=await headers(role))

        assert response.status_code == 200
        assert response.json() == {
            "data": {"count": 1, "authenticated": False, "url": _SEARCH_URL}
        }
        assert len(server.requests) == 1

    @pytest.mark.usefixtures("with_key")
    async def test_authenticated_read_includes_restricted_bugs(
        self,
        client: AsyncClient,
        server: JsonRpcServer,
        headers: Callable[..., Awaitable[dict[str, str]]],
    ) -> None:
        server.default = rpc.fixture(AUTHENTICATED_FIXTURE)

        response = await client.get(
            _PATH, headers=await headers(Role.RESTRICTED_ANALYST)
        )

        assert response.status_code == 200
        assert response.json() == {
            "data": {"count": 2, "authenticated": True, "url": _SEARCH_URL}
        }
        for secret in (_API_KEY, str(RESTRICTED_TEST_BUG), str(PUBLIC_TEST_BUG)):
            assert secret not in response.text

    @pytest.mark.usefixtures("anonymous")
    async def test_every_caller_receives_the_shared_result(
        self,
        client: AsyncClient,
        server: JsonRpcServer,
        headers: Callable[..., Awaitable[dict[str, str]]],
    ) -> None:
        first = await client.get(
            _PATH, headers=await headers(Role.VULNERABILITY_ANALYST)
        )
        second = await client.get(_PATH, headers=await headers(Role.RESTRICTED_ANALYST))

        assert first.json() == second.json()
        assert len(server.requests) == 1

    @pytest.mark.usefixtures("anonymous")
    async def test_query_parameters_are_ignored(
        self,
        client: AsyncClient,
        server: JsonRpcServer,
        headers: Callable[..., Awaitable[dict[str, str]]],
    ) -> None:
        response = await client.get(
            _PATH,
            params={"v2": "attacker@example.com", "limit": "1"},
            headers=await headers(Role.VULNERABILITY_ANALYST),
        )

        assert response.status_code == 200
        [request] = server.requests
        assert b"attacker" not in request.content

    @pytest.mark.usefixtures("with_key")
    @pytest.mark.parametrize(
        "responder",
        [rpc.status(403), rpc.fixture("jsonrpc_error_invalid_api_key")],
        ids=["http_failure", "api_key_rejected"],
    )
    async def test_failed_read_returns_503_bugzilla_unavailable(
        self,
        client: AsyncClient,
        server: JsonRpcServer,
        headers: Callable[..., Awaitable[dict[str, str]]],
        responder: rpc.Responder,
    ) -> None:
        server.default = responder

        response = await client.get(
            _PATH, headers=await headers(Role.VULNERABILITY_ANALYST)
        )

        assert response.status_code == 503
        assert response.json() == _UNAVAILABLE
        assert _API_KEY not in response.text

    @pytest.mark.usefixtures("redis_client", "anonymous")
    async def test_request_without_credentials_returns_401_without_a_read(
        self, client: AsyncClient, server: JsonRpcServer
    ) -> None:
        response = await client.get(_PATH)

        assert response.status_code == 401
        assert response.json() == UNAUTHENTICATED
        assert server.requests == []

    @pytest.mark.usefixtures("anonymous")
    @pytest.mark.parametrize("roles", [(), (Role.ADMIN,)], ids=["role_less", "admin"])
    async def test_caller_without_triage_ticket_returns_403_without_a_read(
        self,
        client: AsyncClient,
        server: JsonRpcServer,
        headers: Callable[..., Awaitable[dict[str, str]]],
        roles: tuple[Role, ...],
    ) -> None:
        response = await client.get(_PATH, headers=await headers(*roles))

        assert response.status_code == 403
        assert response.json() == FORBIDDEN
        assert server.requests == []


def _operation() -> dict[str, Any]:
    operation: dict[str, Any] = app.openapi()["paths"][_PATH]["get"]
    return operation


@pytest.mark.unit
class TestOpenApiContract:
    def test_operation_is_a_get_with_summary_description_and_tag(self) -> None:
        assert set(app.openapi()["paths"][_PATH]) == {"get"}
        operation = _operation()
        assert operation["summary"]
        assert "triage_ticket" in operation["description"]
        assert operation["tags"] == ["Bugzilla"]

    def test_declares_no_parameter_and_no_request_body(self) -> None:
        operation = _operation()

        assert "parameters" not in operation or all(
            parameter["in"] == "header" for parameter in operation["parameters"]
        )
        assert "requestBody" not in operation

    def test_responses_include_the_503_bugzilla_unavailable(self) -> None:
        responses = _operation()["responses"]

        assert set(responses) == {"200", "401", "403", "422", "500", "503"}
        assert "BUGZILLA_UNAVAILABLE" in responses["503"]["description"]
        assert "REDIS_UNAVAILABLE" not in str(responses)

    def test_response_schema_exposes_exactly_count_authenticated_and_url(
        self,
    ) -> None:
        schemas = app.openapi()["components"]["schemas"]
        response = _operation()["responses"]["200"]["content"]["application/json"]

        assert response["schema"]["$ref"].endswith("/BugzillaNeedinfoCountResponse")
        data = schemas["BugzillaNeedinfoCountData"]
        assert set(data["properties"]) == {"count", "authenticated", "url"}
        assert set(data["required"]) == {"count", "authenticated", "url"}
        assert data["properties"]["count"]["type"] == "integer"
        assert data["properties"]["authenticated"]["type"] == "boolean"
        assert data["properties"]["url"]["type"] == "string"
