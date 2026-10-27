"""Every route of the registered application requires authentication,
except the Public allowlist.

See docs/features/identity/rbac.md (Access Levels, Criterion for Public
access), docs/api-spec.md (Public Endpoints; Global Responses; Derived
Responses in the OpenAPI Document), and
docs/features/platform/testing-strategy.md (Authentication and Session):
a test derives every route and method from the registered application and
proves that each one returns the generic 401 to a request without a
credential, except an explicit allowlist: the Public operations,
`/api/openapi.json`, and `/api/docs`. A new route is therefore covered
without a new test.

The Public operations that are registered today are the probes and local
login; SSO authorization and callback and authentication-provider
discovery join the allowlist with their routes.
"""

from __future__ import annotations

import re
from typing import Any, Final

import pytest
from fastapi import routing as fastapi_routing
from httpx import AsyncClient

from app.main import app

_UNAUTHENTICATED: Final = {
    "code": "AUTH_NOT_AUTHENTICATED",
    "detail": "Authentication required",
}
_REQUIRED_AUTHENTICATION_401: Final = (
    "`AUTH_NOT_AUTHENTICATED`: no credential was sent, or the credential is invalid."
)

_PUBLIC_OPERATIONS: Final = frozenset(
    {
        ("GET", "/health"),
        ("GET", "/ready"),
        ("POST", "/api/v1/auth/login"),
    }
)
"""The registered Public operations (docs/api-spec.md, Public Endpoints)."""

_DOCUMENTATION: Final = frozenset(
    {
        ("GET", "/api/openapi.json"),
        ("HEAD", "/api/openapi.json"),
        ("GET", "/api/docs"),
        ("HEAD", "/api/docs"),
    }
)
"""The OpenAPI document and the interactive documentation page, which are
not operations (docs/api-spec.md, OpenAPI Document and Interactive
Documentation)."""

_ALLOWLIST: Final = _PUBLIC_OPERATIONS | _DOCUMENTATION

_OWN_401: Final = frozenset({("POST", "/api/v1/auth/logout")})
"""Operations that produce the 401 without the shared authentication
dependency and therefore declare it themselves (docs/conventions.md,
FastAPI Conventions: logout's own credential handling)."""


def _registered_operations() -> list[tuple[str, str]]:
    """Every `(method, path)` that the registered application serves."""
    return sorted(
        {
            (method, context.path_format)
            for context in fastapi_routing.iter_route_contexts(app.routes)
            if context.path_format is not None
            for method in context.methods or ()
        }
    )


_OPERATIONS: Final = _registered_operations()
_PROTECTED_OPERATIONS: Final = [
    operation for operation in _OPERATIONS if operation not in _ALLOWLIST
]


def _concrete(path: str) -> str:
    """`path` with every path parameter replaced by a fictional value.
    Authentication precedes path parameter validation, so the value's
    shape does not matter."""
    return re.sub(r"\{[^}]+\}", "fictional", path)


@pytest.mark.e2e
class TestEveryRouteRequiresAuthentication:
    def test_every_allowlisted_operation_is_registered(self) -> None:
        """The allowlist names only served operations, so an entry cannot
        outlive its route and silently exempt a later one."""
        assert set(_OPERATIONS) >= _ALLOWLIST
        assert set(_PROTECTED_OPERATIONS) >= _OWN_401

    @pytest.mark.parametrize(("method", "path"), _PROTECTED_OPERATIONS)
    async def test_request_without_credential_returns_401(
        self, client: AsyncClient, method: str, path: str
    ) -> None:
        response = await client.request(method, _concrete(path))

        assert response.status_code == 401
        assert response.json() == _UNAUTHENTICATED
        assert "set-cookie" not in response.headers


@pytest.mark.unit
class TestEveryOperationDocumentsTheRequiredAuthentication:
    def test_every_protected_operation_documents_the_401(self) -> None:
        """Every documented operation outside the allowlist documents the
        `401` of required authentication; an operation that declares its
        own `401` names the code."""
        paths: dict[str, Any] = app.openapi()["paths"]
        documented: dict[tuple[str, str], str | None] = {
            (method.upper(), path): (
                operation["responses"].get("401", {}).get("description")
            )
            for path, operations in paths.items()
            for method, operation in operations.items()
        }

        protected = {
            operation: description
            for operation, description in documented.items()
            if operation not in _ALLOWLIST
        }
        assert set(protected) == set(_PROTECTED_OPERATIONS)
        assert {
            operation: description
            for operation, description in protected.items()
            if operation not in _OWN_401
        } == {
            operation: _REQUIRED_AUTHENTICATION_401
            for operation in protected
            if operation not in _OWN_401
        }
        for operation in _OWN_401:
            assert "`AUTH_NOT_AUTHENTICATED`" in (protected[operation] or "")
