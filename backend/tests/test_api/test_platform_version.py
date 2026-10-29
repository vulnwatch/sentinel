"""End-to-end tests for the platform version endpoint
(`GET /api/v1/version`, `backend/app/api/v1/platform.py`).

See docs/features/platform/platform-version.md (Get Platform Version),
docs/api-spec.md (Response Format; Undeclared Query Parameters; Response
Applicability Derivation; OpenAPI Document and Interactive Documentation),
and docs/features/platform/testing-strategy.md (API Endpoints).

These tests cover the HTTP contract: the envelope and the value, its
equality with the installed package version and with `info.version` of the
served OpenAPI document, its independence from the caller and the
credential, ignored query parameters, the route inventory, and OpenAPI.
Authentication goes through the shared `CurrentUser` dependency unchanged:
the route-wide test of `tests/test_api/test_route_authentication.py` proves
the `401` of this route without a credential, and
`tests/test_api/test_dependencies.py` proves the rejection of every invalid
credential.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from collections.abc import Awaitable, Callable
from importlib.metadata import version as get_version
from typing import Any, Final
from unittest.mock import AsyncMock

import pytest
from fastapi import routing as fastapi_routing
from fastapi.routing import APIRoute
from httpx import AsyncClient

from app.api import dependencies
from app.core.enums import Role
from app.main import app
from app.models.api_key import ApiKey
from app.models.user import User
from app.models.user_role import UserRole

_PATH: Final = "/api/v1/version"

# The release version form of docs/deployment.md (Platform Version and
# Source of Truth): `<major>.<minor>.<patch>`, without the tag's `v`.
_VERSION_FORM: Final = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")


def _expected_body() -> dict[str, Any]:
    return {"data": {"version": get_version("sentinel")}}


def _make_api_key_credential() -> tuple[str, str]:
    """Return `(plaintext_token, sha256_hex_digest)` for a synthetic key."""
    token = "stl_ak_" + secrets.token_hex(16)
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return token, digest


@pytest.mark.e2e
class TestGetPlatformVersion:
    async def test_role_less_session_returns_the_installed_package_version(
        self, authenticated_client: AsyncClient
    ) -> None:
        """The read-only profile, a user with no roles, suffices."""
        response = await authenticated_client.get(_PATH)

        assert response.status_code == 200
        assert response.json() == _expected_body()
        assert _VERSION_FORM.fullmatch(response.json()["data"]["version"])

    async def test_value_equals_info_version_of_the_served_openapi_document(
        self, authenticated_client: AsyncClient
    ) -> None:
        document = await authenticated_client.get("/api/openapi.json")
        response = await authenticated_client.get(_PATH)

        assert document.status_code == response.status_code == 200
        assert response.json()["data"]["version"] == document.json()["info"]["version"]

    async def test_api_key_of_another_caller_returns_the_same_value(
        self,
        authenticated_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
        user_role_factory: Callable[..., Awaitable[UserRole]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An API key of a user with roles receives the value that a
        role-less session receives. The session cookie is cleared first, so
        the key is the only credential sent; the `last_used_at` debouncer is
        replaced so that it does not commit through its own session."""
        user = await user_factory()
        await user_role_factory(user_id=user.id, role=Role.ADMIN.value)
        token, digest = _make_api_key_credential()
        await api_key_factory(user_id=user.id, key_hash=digest)
        monkeypatch.setattr(dependencies._last_used_debouncer, "touch", AsyncMock())
        authenticated_client.cookies.clear()

        response = await authenticated_client.get(
            _PATH, headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        assert response.json() == _expected_body()

    async def test_query_parameters_are_ignored(
        self, authenticated_client: AsyncClient
    ) -> None:
        response = await authenticated_client.get(
            _PATH, params={"version": "9.9.9", "page": "0", "q": "x" * 600}
        )

        assert response.status_code == 200
        assert response.json() == _expected_body()


# ---------------------------------------------------------------------------
# Route inventory and OpenAPI contract
# ---------------------------------------------------------------------------


def _schemas() -> dict[str, Any]:
    schemas: dict[str, Any] = app.openapi()["components"]["schemas"]
    return schemas


def _operation() -> dict[str, Any]:
    operation: dict[str, Any] = app.openapi()["paths"][_PATH]["get"]
    return operation


def _referenced(schema: dict[str, Any]) -> dict[str, Any]:
    referenced: dict[str, Any] = _schemas()[schema["$ref"].rsplit("/", 1)[1]]
    return referenced


@pytest.mark.unit
class TestRouteInventory:
    def test_only_get_is_registered_at_the_path(self) -> None:
        """Route discovery uses `iter_route_contexts()` — see
        `tests/test_api_conventions.py` for why `app.routes` alone does not
        expose routes included via `include_router()`."""
        routes = {
            (context.path, method)
            for context in fastapi_routing.iter_route_contexts(app.routes)
            if isinstance(context.original_route, APIRoute)
            and context.path is not None
            and context.path.startswith(_PATH)
            for method in (context.methods or set()) - {"HEAD", "OPTIONS"}
        }

        assert routes == {(_PATH, "GET")}


@pytest.mark.unit
class TestOpenApiContract:
    def test_operation_has_summary_description_tag_and_no_parameters(self) -> None:
        operation = _operation()

        assert operation["summary"]
        assert operation["description"]
        assert operation["tags"] == ["Platform"]
        assert operation.get("parameters", []) == []
        assert "requestBody" not in operation

    def test_responses_are_those_of_an_authenticated_read(self) -> None:
        """`Access: Authenticated` derives `401`, `422`, and `500`, and the
        endpoint adds no error of its own (docs/api-spec.md, Response
        Applicability Derivation)."""
        assert set(_operation()["responses"]) == {"200", "401", "422", "500"}

    def test_response_schema_is_the_envelope_with_a_required_string_version(
        self,
    ) -> None:
        response = _operation()["responses"]["200"]["content"]["application/json"]
        envelope = _referenced(response["schema"])

        assert response["schema"]["$ref"].endswith("/PlatformVersionResponse")
        assert set(envelope["properties"]) == {"data"}
        assert envelope["required"] == ["data"]
        data = _referenced(envelope["properties"]["data"])
        assert set(data["properties"]) == {"version"}
        assert data["required"] == ["version"]
        assert data["properties"]["version"]["type"] == "string"
