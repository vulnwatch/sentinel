"""Structural tests over FastAPI route-level API conventions.

Verifies invariants declared in `docs/api-spec.md` across every
registered route. See `docs/features/platform/testing-strategy.md`
(Structural Tests) for scope and governing principle.

This module intentionally does not defer to "until the first real
endpoint exists": every check below iterates the app's registered
routes, so it started out passing vacuously (zero `APIRoute` instances
registered) and began enforcing automatically the moment the first
endpoint was added (`/health`, `/ready`) — no further action was
required from whoever added it. The same holds for every endpoint
added since.

Route discovery does not read `app.routes` directly: FastAPI represents
a router included via `include_router()` internally as a lazy
`_IncludedRouter` node, not as a flat list of `APIRoute` instances —
`app.routes` alone does not expose included routes. `_api_routes()`
flattens this via `fastapi.routing.iter_route_contexts()`, the same
mechanism FastAPI's own OpenAPI generation uses internally, and pairs
each route's *effective* path (accounting for any router-level prefix)
with the underlying `APIRoute` object for its FastAPI-specific
attributes (`response_model`, `status_code`, `summary`, `description`).

Out of scope: the RBAC Endpoint Permission Map cross-reference (see
`docs/features/identity/rbac.md`) is not verified here — it would
require parsing a Markdown table, which the governing principle
forbids. That cross-reference remains with `@docs-reviewer` /
`@api-parity-reviewer`.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from types import UnionType
from typing import Annotated, Any, Final, Literal, Union, get_args, get_origin

import pytest
from fastapi import FastAPI, Query
from fastapi import routing as fastapi_routing
from fastapi.dependencies.models import Dependant
from fastapi.routing import APIRoute
from pydantic import (
    MISSING,
    BaseModel,
    Field,
    Strict,
    ValidationError,
    WithJsonSchema,
    field_validator,
)
from pydantic.fields import FieldInfo
from starlette.routing import BaseRoute

from app.api.dependencies import drain_ticket_convergence_after_commit
from app.api.openapi import API_V1_RESPONSES
from app.core.errors import ErrorCode
from app.core.usernames import RESERVED_USERNAMES
from app.database import get_db
from app.main import app
from app.schemas.errors import ErrorResponse

# Endpoints intentionally outside the `/api/v1/` prefix — public,
# non-versioned operational endpoints. See
# `docs/features/platform/health-endpoints.md`. Their responses are
# also exempt from the `{"data": ...}` envelope (e.g. `/health` returns
# `{"status": "ok"}` directly) — see docs/api-spec.md Response Format,
# which scopes the envelope to API endpoints.
_PREFIX_EXEMPT_PATHS = {"/health", "/ready"}

# Every path the application serves starts with this prefix, except the
# probes above — see `docs/api-spec.md` (Base URL).
_API_PATH_PREFIX: Final = "/api/"

# The only HTTP methods used across the documented API surface — see
# `docs/api-spec.md` (Mutation Patterns: PATCH/POST) and the CORS
# `allow_methods` configuration in `app/main.py`. A route using any
# other method (e.g. PUT, HEAD) would be unreachable by the CORS
# configuration the application itself declares.
_ALLOWED_METHODS = {"GET", "POST", "PATCH", "DELETE"}

# Routes with this status code return no body — see docs/api-spec.md
# Response Format. They are exempt from both the response_model
# presence and the envelope-format checks below.
_NO_BODY_STATUS_CODE = 204


@dataclass(frozen=True)
class _RouteInfo:
    """A flattened view of one registered route.

    `path` is the *effective* path — resolved through any router-level
    prefix applied via `include_router()` — which is what every
    convention check below needs. `route` is the underlying `APIRoute`
    object, used for attributes that are intrinsic to the route
    definition itself and unaffected by inclusion context
    (`response_model`, `status_code`, `summary`, `description`).
    `dependant` is the *effective* dependency graph — it includes any
    dependency added at `include_router()` time, unlike `route.dependant`
    which reflects only the route's own declaration.
    """

    path: str
    methods: frozenset[str]
    route: APIRoute
    dependant: Dependant


def _api_routes() -> list[_RouteInfo]:
    infos: list[_RouteInfo] = []
    for context in fastapi_routing.iter_route_contexts(app.routes):
        if isinstance(context.original_route, APIRoute) and context.path is not None:
            infos.append(
                _RouteInfo(
                    path=context.path,
                    methods=frozenset(context.methods or ()),
                    route=context.original_route,
                    dependant=context.dependant,
                )
            )
    return infos


def _resolve_schema_ref(
    openapi_schema: dict[str, Any], node: dict[str, Any]
) -> dict[str, Any]:
    """Resolve a `$ref` pointer (e.g. `#/components/schemas/TicketDetail`)
    to the schema object it points to. Returns `node` unchanged if it is
    not a `$ref`.
    """
    ref = node.get("$ref")
    if not ref:
        return node
    target: Any = openapi_schema
    for part in ref.removeprefix("#/").split("/"):
        target = target[part]
    return target  # type: ignore[no-any-return]


def _response_schema(
    openapi_schema: dict[str, Any], info: _RouteInfo
) -> dict[str, Any] | None:
    """The resolved JSON schema for `info`'s primary success response
    (`info.route.status_code`, default 200), or `None` if the OpenAPI
    document does not describe a JSON body for it (e.g. no
    `response_model` was declared and FastAPI could not infer one).
    """
    method = next(iter(info.methods), "").lower()
    operation = openapi_schema.get("paths", {}).get(info.path, {}).get(method, {})
    status_code = str(info.route.status_code or 200)
    response = operation.get("responses", {}).get(status_code, {})
    schema = response.get("content", {}).get("application/json", {}).get("schema")
    if schema is None:
        return None
    return _resolve_schema_ref(openapi_schema, schema)


@pytest.mark.unit
class TestRoutePrefixConvention:
    """Every route is prefixed with `/api/v1/`, except the documented
    health-endpoint exemption.

    See `docs/api-spec.md` (Base URL): "All API endpoints are prefixed
    with `/api/v1/`."
    """

    def test_every_route_has_api_v1_prefix_or_is_exempt(self) -> None:
        violations = [
            f"Route '{info.path}' is missing the required '/api/v1/' prefix"
            for info in _api_routes()
            if info.path not in _PREFIX_EXEMPT_PATHS
            and not info.path.startswith("/api/v1/")
        ]
        assert not violations, "\n".join(violations)


def _paths_outside_api_prefix(routes: Sequence[BaseRoute]) -> list[str]:
    """Every registered path of `routes`, of any route type, that is
    neither under `_API_PATH_PREFIX` nor a probe."""
    return sorted(
        context.path
        for context in fastapi_routing.iter_route_contexts(routes)
        if context.path is not None
        and context.path not in _PREFIX_EXEMPT_PATHS
        and not context.path.startswith(_API_PATH_PREFIX)
    )


@pytest.mark.unit
class TestServedPathPrefix:
    """Every path the application serves starts with `/api/`, except the
    probes, so that a host shared with the web UI routes only `/api` to the
    API.

    See `docs/api-spec.md` (Base URL) and `docs/deployment.md` (Sentinel
    Host). Unlike `TestRoutePrefixConvention`, this covers the routes that
    are not `APIRoute` instances: the OpenAPI document that FastAPI
    registers and the interactive documentation page.
    """

    def test_every_served_path_is_under_api_or_a_probe(self) -> None:
        assert _paths_outside_api_prefix(app.routes) == []

    def test_framework_default_documentation_paths_are_detected(self) -> None:
        """Self-test: FastAPI's own documentation routes are at the site
        root, and the check reports each of them."""
        assert _paths_outside_api_prefix(FastAPI().routes) == [
            "/docs",
            "/docs/oauth2-redirect",
            "/openapi.json",
            "/redoc",
        ]


@pytest.mark.unit
class TestRouteHttpMethods:
    """No route uses an HTTP method outside the documented set.

    See `docs/api-spec.md` (Mutation Patterns): only PATCH and POST are
    used for modification, GET for reads, DELETE for removal. `PUT` and
    `HEAD` are never used.
    """

    def test_every_route_uses_only_allowed_methods(self) -> None:
        violations: list[str] = []
        for info in _api_routes():
            disallowed = info.methods - _ALLOWED_METHODS
            if disallowed:
                violations.append(
                    f"Route '{info.path}' uses disallowed HTTP method(s) "
                    f"{disallowed} (allowed: {_ALLOWED_METHODS})"
                )
        assert not violations, "\n".join(violations)


@pytest.mark.unit
class TestRouteDocumentation:
    """Every route has OpenAPI documentation.

    See `docs/conventions.md` (FastAPI Conventions): "All endpoints
    must have OpenAPI documentation (summary, description)." FastAPI
    derives `description` from the endpoint's docstring when not set
    explicitly, so a docstring alone satisfies this.
    """

    def test_every_route_has_summary_or_description(self) -> None:
        violations = [
            f"Route '{info.path}' has no OpenAPI summary or description "
            "(add a docstring or explicit summary/description)"
            for info in _api_routes()
            if not (info.route.summary or info.route.description)
        ]
        assert not violations, "\n".join(violations)


@pytest.mark.unit
class TestAuditLogEndpointNaming:
    """Every audit trail retrieval endpoint uses the `/audit-log`
    suffix.

    See `docs/api-spec.md` (Audit Trail Endpoint Naming): "Every audit
    trail retrieval endpoint MUST use the `/audit-log` suffix."
    """

    def test_audit_related_routes_end_with_audit_log_suffix(self) -> None:
        violations = [
            f"Route '{info.path}' references audit trails but does not "
            "end with the required '/audit-log' suffix"
            for info in _api_routes()
            if "audit" in info.path.lower() and not info.path.endswith("/audit-log")
        ]
        assert not violations, "\n".join(violations)


def _user_position_literals(paths: Iterable[str]) -> set[str]:
    """Literal segments at the position of a `{user}` path parameter: the
    segment that follows the same leading segments as the parameter, such
    as `me` in `/api/v1/users/me` beside `/api/v1/users/{user}`. Leading
    path parameters match each other whatever their names, as in routing."""

    def shape(segments: tuple[str, ...]) -> tuple[str, ...]:
        return tuple("{}" if part.startswith("{") else part for part in segments)

    split = [tuple(path.strip("/").split("/")) for path in paths]
    prefixes = {
        shape(segments[:index])
        for segments in split
        for index, segment in enumerate(segments)
        if segment == "{user}"
    }
    return {
        segments[len(prefix)]
        for segments in split
        for prefix in prefixes
        if len(segments) > len(prefix)
        and shape(segments[: len(prefix)]) == prefix
        and not segments[len(prefix)].startswith("{")
    }


@pytest.mark.unit
class TestUserPathReservation:
    """Every literal segment at a `{user}` position is a reserved username.

    See `docs/api-spec.md` (User Identifier Resolution): a literal segment
    there takes precedence over the parameter, so a user holding that
    username could not be addressed by username unless the username is
    reserved (`docs/conventions.md`, Username Format).
    """

    def test_every_literal_segment_at_a_user_position_is_reserved(self) -> None:
        literals = _user_position_literals(info.path for info in _api_routes())

        assert "me" in literals, "the existing `/api/v1/users/me` is not detected"
        unreserved = sorted(literals - RESERVED_USERNAMES)
        assert not unreserved, (
            f"Literal segments {unreserved} sit at a `{{user}}` position but are "
            "not in `app.core.usernames.RESERVED_USERNAMES`"
        )

    def test_detection_covers_nested_positions_and_parameter_names(self) -> None:
        paths = [
            "/api/v1/users/{user}",
            "/api/v1/users/me/audit-log",
            "/api/v1/users/search",
            "/api/v1/admin/users",
            "/api/v1/admin/users/{user}/roles",
            "/api/v1/tickets/{ticket_id}/access/{user}",
            "/api/v1/tickets/{id}/access/bulk",
        ]

        assert _user_position_literals(paths) == {"me", "search", "bulk"}


# docs/api-spec.md (Pagination): the inclusive bounds of each parameter.
_PAGINATION_BOUNDS: Final = {"page": (1, 2_147_483_647), "per_page": (1, 100)}


def _pagination_bound_violations(openapi_schema: dict[str, Any]) -> list[str]:
    """Every operation declaring a `page` query parameter, with each
    pagination parameter whose OpenAPI bounds differ from the contract."""
    violations: list[str] = []
    for path, item in openapi_schema.get("paths", {}).items():
        for method, operation in item.items():
            if not isinstance(operation, dict):
                continue
            parameters = {
                parameter["name"]: parameter.get("schema", {})
                for parameter in operation.get("parameters", [])
                if parameter.get("in") == "query"
            }
            if "page" not in parameters:
                continue
            for name, bounds in _PAGINATION_BOUNDS.items():
                schema = parameters.get(name, {})
                if (schema.get("minimum"), schema.get("maximum")) != bounds:
                    violations.append(f"{method.upper()} {path}: {name} {schema}")
    return violations


@pytest.mark.unit
class TestPaginationParameterBounds:
    """Every paginated operation bounds `page` to 1-2147483647 and
    `per_page` to 1-100, rejecting other values with the global 422.

    See `docs/api-spec.md` (Pagination).
    """

    def test_every_paginated_operation_declares_the_bounds(self) -> None:
        openapi_schema = app.openapi()
        paginated = [
            path
            for path, item in openapi_schema["paths"].items()
            for operation in item.values()
            if isinstance(operation, dict)
            and any(
                parameter.get("in") == "query" and parameter["name"] == "page"
                for parameter in operation.get("parameters", [])
            )
        ]

        assert paginated, "no paginated operation found"
        violations = _pagination_bound_violations(openapi_schema)
        assert not violations, "\n".join(violations)

    def test_detection_reports_missing_and_wrong_bounds(self) -> None:
        def operation(**schemas: dict[str, Any]) -> dict[str, Any]:
            return {
                "parameters": [
                    {"name": name, "in": "query", "schema": schema}
                    for name, schema in schemas.items()
                ]
            }

        document = {
            "paths": {
                "/ok": {
                    "get": operation(
                        page={"minimum": 1, "maximum": 2_147_483_647},
                        per_page={"minimum": 1, "maximum": 100},
                    )
                },
                "/unbounded": {
                    "get": operation(
                        page={"minimum": 1},
                        per_page={"minimum": 1, "maximum": 1000},
                    )
                },
                "/no-per-page": {
                    "get": operation(page={"minimum": 1, "maximum": 2_147_483_647})
                },
                "/unpaginated": {"get": operation(per_page={})},
            }
        }

        assert [
            violation.split(" {")[0]
            for violation in _pagination_bound_violations(document)
        ] == [
            "GET /unbounded: page",
            "GET /unbounded: per_page",
            "GET /no-per-page: per_page",
        ]


@pytest.mark.unit
class TestResponseModelPresence:
    """Every route that returns a body declares a `response_model`.

    See `docs/conventions.md` (FastAPI Conventions): "Use appropriate
    HTTP status codes and response models." A route with status code
    204 (No Content) is exempt — it has no body to model.
    """

    def test_every_body_returning_route_has_a_response_model(self) -> None:
        violations = [
            f"Route '{info.path}' has no response_model (and status "
            f"code {info.route.status_code} is not 204 No Content)"
            for info in _api_routes()
            if info.route.status_code != _NO_BODY_STATUS_CODE
            and info.route.response_model is None
        ]
        assert not violations, "\n".join(violations)


@pytest.mark.unit
class TestResponseEnvelopeFormat:
    """Every route that returns a body wraps it in the standard
    `{"data": ...}` envelope.

    See `docs/api-spec.md` (Response Format): paginated list endpoints
    return `{"data": [...], "meta": {...}}`; single-resource and
    unpaginated list endpoints return `{"data": {...}}`. A route with
    status code 204 (No Content) is exempt — it has no body. The
    `/health` and `/ready` exemption (see `TestRoutePrefixConvention`)
    also applies here — those endpoints are outside the API envelope
    contract by design.
    """

    def test_every_body_returning_route_has_a_data_property(self) -> None:
        openapi_schema = app.openapi()
        violations: list[str] = []
        for info in _api_routes():
            if info.route.status_code == _NO_BODY_STATUS_CODE:
                continue
            if info.path in _PREFIX_EXEMPT_PATHS:
                continue
            schema = _response_schema(openapi_schema, info)
            if schema is None or "data" not in schema.get("properties", {}):
                violations.append(
                    f"Route '{info.path}' response schema does not have "
                    "a top-level 'data' property (required by the "
                    "standard response envelope)"
                )
        assert not violations, "\n".join(violations)


def _schema_branches(
    openapi_schema: dict[str, Any], schema: dict[str, Any]
) -> list[dict[str, Any]]:
    """The resolved alternatives of `schema`: the members of an `anyOf` or
    `oneOf`, at any depth, or `schema` itself."""
    resolved = _resolve_schema_ref(openapi_schema, schema)
    for keyword in ("anyOf", "oneOf"):
        if keyword in resolved:
            return [
                branch
                for alternative in resolved[keyword]
                for branch in _schema_branches(openapi_schema, alternative)
            ]
    return [resolved]


def _is_error_envelope(schema: dict[str, Any]) -> bool:
    """Whether `schema` is the standard error envelope: an object that
    requires string `code` and `detail` members."""
    properties = schema.get("properties", {})
    return {"code", "detail"} <= set(schema.get("required", ())) and all(
        properties.get(name, {}).get("type") == "string" for name in ("code", "detail")
    )


def _is_validation_error_envelope(schema: dict[str, Any]) -> bool:
    """Whether `schema` is the `422 VALIDATION_ERROR` body: the envelope
    plus a required `errors` array."""
    return (
        _is_error_envelope(schema)
        and "errors" in schema.get("required", ())
        and schema["properties"]["errors"].get("type") == "array"
    )


def _documented_operations(
    openapi_schema: dict[str, Any],
) -> Iterable[tuple[str, dict[str, Any]]]:
    """`("METHOD /path", operation)` for every operation of
    `openapi_schema`, except the documented health exemption."""
    for path, path_item in openapi_schema.get("paths", {}).items():
        if path in _PREFIX_EXEMPT_PATHS:
            continue
        for method, operation in path_item.items():
            yield f"{method.upper()} {path}", operation


def _json_schema(response: dict[str, Any]) -> dict[str, Any] | None:
    schema: dict[str, Any] | None = (
        response.get("content", {}).get("application/json", {}).get("schema")
    )
    return schema


def _error_envelope_violations(openapi_schema: dict[str, Any]) -> list[str]:
    """Every documented 4xx or 5xx response whose schema, or one of whose
    alternatives, is not the standard error envelope."""
    violations: list[str] = []
    for operation_name, operation in _documented_operations(openapi_schema):
        for status, response in operation.get("responses", {}).items():
            if not status.startswith(("4", "5")):
                continue
            schema = _json_schema(response)
            if schema is None or not all(
                _is_error_envelope(branch)
                for branch in _schema_branches(openapi_schema, schema)
            ):
                violations.append(
                    f"{operation_name} documents {status} without the standard "
                    "error envelope"
                )
    return violations


def _global_response_violations(openapi_schema: dict[str, Any]) -> list[str]:
    """Every operation that does not document the `422 VALIDATION_ERROR`
    body among its 422 alternatives, or does not document a 500."""
    violations: list[str] = []
    for operation_name, operation in _documented_operations(openapi_schema):
        responses = operation.get("responses", {})
        invalid = _json_schema(responses.get("422", {}))
        if invalid is None or not any(
            _is_validation_error_envelope(branch)
            for branch in _schema_branches(openapi_schema, invalid)
        ):
            violations.append(
                f"{operation_name} does not document the 422 VALIDATION_ERROR "
                "body with its 'errors' array"
            )
        if "500" not in responses:
            violations.append(f"{operation_name} does not document the 500")
    return violations


# A backticked UPPER_SNAKE_CASE token with at least one underscore: how an
# error description names a code (`docs/conventions.md`, FastAPI
# Conventions).
_CODE_PATTERN = re.compile(r"`([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)`")
_REGISTERED_CODES = frozenset(code.value for code in ErrorCode)


def _error_code_naming_violations(openapi_schema: dict[str, Any]) -> list[str]:
    """Every documented 4xx or 5xx response whose description names no
    error code, or names a code that is not registered."""
    violations: list[str] = []
    for operation_name, operation in _documented_operations(openapi_schema):
        for status, response in operation.get("responses", {}).items():
            if not status.startswith(("4", "5")):
                continue
            named = _CODE_PATTERN.findall(response.get("description", ""))
            if not named:
                violations.append(
                    f"{operation_name} documents {status} without naming its "
                    "error codes"
                )
            violations.extend(
                f"{operation_name} documents {status} with the unregistered code {code}"
                for code in named
                if code not in _REGISTERED_CODES
            )
    return violations


@pytest.mark.unit
class TestErrorResponseDocumentation:
    """The OpenAPI document describes the error bodies the application
    returns.

    See `docs/api-spec.md` (Response Format, Global Responses): every
    error response uses the standard envelope, and every `/api/v1`
    operation can return the global `422 VALIDATION_ERROR`, whose body
    carries the `errors` array, and `500 INTERNAL_ERROR`. A route-level
    `422` declaration replaces the shared one (`app/api/openapi.py`), so
    it must keep the validation body among its alternatives. The
    `/health`/`/ready` exemption applies: their probe responses are
    outside the envelope (`docs/features/platform/health-endpoints.md`).
    The schema types `code` as a string, so each description names the
    codes of its status (`docs/api-spec.md`, Derived Responses in the
    OpenAPI Document); the OpenAPI response contract check proves, for
    every response the tests receive, that its code is among them.
    """

    def test_every_documented_error_response_uses_the_envelope(self) -> None:
        violations = _error_envelope_violations(app.openapi())
        assert not violations, "\n".join(violations)

    def test_every_operation_documents_the_global_422_and_500(self) -> None:
        violations = _global_response_violations(app.openapi())
        assert not violations, "\n".join(violations)

    def test_every_documented_error_response_names_registered_codes(self) -> None:
        violations = _error_code_naming_violations(app.openapi())
        assert not violations, "\n".join(violations)

    def test_detection_covers_defaults_unions_and_route_level_overrides(
        self,
    ) -> None:
        """Guards the checkers themselves against passing vacuously."""

        class _NotEnvelope(BaseModel):
            message: str

        test_app = FastAPI()

        @test_app.get("/api/v1/framework-default/{item_id}")
        async def framework_default(item_id: int) -> None:
            """FastAPI's own 422 body, and no 500."""

        @test_app.get(
            "/api/v1/union",
            responses={
                **API_V1_RESPONSES,
                404: {"model": ErrorResponse | _NotEnvelope},
            },
        )
        async def union() -> None:
            """A 404 alternative outside the envelope."""

        @test_app.post(
            "/api/v1/overridden",
            responses={**API_V1_RESPONSES, 422: {"model": ErrorResponse}},
        )
        async def overridden() -> None:
            """A route-level 422 without the validation body."""

        @test_app.get("/api/v1/compliant", responses=API_V1_RESPONSES)
        async def compliant() -> None:
            """The shared declaration."""

        @test_app.get(
            "/api/v1/unnamed",
            responses={
                **API_V1_RESPONSES,
                404: {"model": ErrorResponse, "description": "No such item."},
                409: {
                    "model": ErrorResponse,
                    "description": "`ITEM_VANISHED`: the item is gone.",
                },
            },
        )
        async def unnamed() -> None:
            """A description naming no code, and one naming an unregistered
            code."""

        @test_app.get("/health")
        async def exempt() -> None:
            """The documented health exemption."""

        openapi_schema = test_app.openapi()

        assert _error_envelope_violations(openapi_schema) == [
            "GET /api/v1/framework-default/{item_id} documents 422 without the "
            "standard error envelope",
            "GET /api/v1/union documents 404 without the standard error envelope",
        ]
        assert _global_response_violations(openapi_schema) == [
            "GET /api/v1/framework-default/{item_id} does not document the 422 "
            "VALIDATION_ERROR body with its 'errors' array",
            "GET /api/v1/framework-default/{item_id} does not document the 500",
            "POST /api/v1/overridden does not document the 422 VALIDATION_ERROR "
            "body with its 'errors' array",
        ]
        assert [
            violation
            for violation in _error_code_naming_violations(openapi_schema)
            if "/unnamed" in violation
        ] == [
            "GET /api/v1/unnamed documents 404 without naming its error codes",
            "GET /api/v1/unnamed documents 409 with the unregistered code "
            "ITEM_VANISHED",
        ]


_JSON_SCALAR_TYPES = (bool, int, float)


def _declares_strict(metadata: Iterable[Any]) -> bool:
    return any(isinstance(item, Strict) and item.strict for item in metadata)


def _has_lax_json_scalar(annotation: Any, strict: bool) -> bool:
    """Whether `annotation` contains a `bool`, `int`, or `float` that is
    not validated strictly. `strict` is the strictness inherited from the
    enclosing level: field-level `Field(strict=True)` covers the field's
    own type and its union members, but not collection items, so a
    container resets it and only an item-level `Strict()` annotation
    covers the items. JSON object keys are strings by transport, so only
    mapping values are inspected. `Literal` values are not types and enum
    subclasses are distinct classes, so neither matches.
    """
    origin = get_origin(annotation)
    args = get_args(annotation)
    if origin is Annotated:
        return _has_lax_json_scalar(args[0], strict or _declares_strict(args[1:]))
    if annotation in _JSON_SCALAR_TYPES:
        return not strict
    if origin is Literal:
        return False
    if origin in (Union, UnionType):
        return any(_has_lax_json_scalar(arg, strict) for arg in args)
    if isinstance(origin, type) and issubclass(origin, Mapping):
        args = args[1:]
    return any(_has_lax_json_scalar(arg, False) for arg in args)


def _nested_models(annotation: Any) -> list[type[BaseModel]]:
    """Every `BaseModel` subclass referenced by `annotation`, at any depth."""
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return [annotation]
    return [model for arg in get_args(annotation) for model in _nested_models(arg)]


def _lax_scalar_fields(
    owner: str, field_info: FieldInfo, seen: set[type[BaseModel]]
) -> list[str]:
    """Dotted names of every field reachable from `field_info` whose type
    contains a non-strict JSON scalar, descending into nested request
    models."""
    violations: list[str] = []
    annotation = field_info.annotation
    if _has_lax_json_scalar(annotation, _declares_strict(field_info.metadata)):
        violations.append(owner)
    for model in _nested_models(annotation):
        if model in seen:
            continue
        seen.add(model)
        for name, nested in model.model_fields.items():
            violations.extend(
                _lax_scalar_fields(f"{model.__name__}.{name}", nested, seen)
            )
    return violations


@pytest.mark.unit
class TestStrictJsonBodyScalars:
    """Every `bool`, `int`, or `float` in a JSON request body is strict
    at every nesting level: `Field(strict=True)` on the field, or a
    `Strict()` item annotation inside a collection.

    See `docs/api-spec.md` (JSON Request Body Scalar Types) and
    `docs/conventions.md` (Pydantic Conventions, Strict JSON body
    scalars). Body parameters are collected from every route's
    effective dependency graph, so a body declared by a dependency is
    covered too.
    """

    def test_every_json_body_scalar_field_is_strict(self) -> None:
        violations: list[str] = []
        for info in _api_routes():
            for node in _iter_dependants(info.dependant):
                for param in node.body_params:
                    violations.extend(
                        f"Route '{info.path}': body field '{name}' has a "
                        "non-strict bool/int/float (use Field(strict=True), or "
                        "Annotated[<type>, Strict()] for collection items)"
                        for name in _lax_scalar_fields(
                            param.name, param.field_info, set()
                        )
                    )
        assert not violations, "\n".join(violations)

    def test_detection_covers_optional_collection_and_nested_fields(self) -> None:
        """Guards the checker itself against passing vacuously."""

        class _Inner(BaseModel):
            lax: float
            strict: float = Field(strict=True)

        class _Body(BaseModel):
            flag: bool | None = None
            counts: list[int] = []
            field_strict_counts: list[int] = Field(default=[], strict=True)
            item_strict_counts: list[Annotated[int, Strict()]] = []
            ratios: dict[str, float] = {}
            item_strict_ratios: dict[int, Annotated[float, Strict()]] = {}
            ok: int | None = Field(default=None, strict=True)
            label: str = ""
            choice: Literal[1, 2] = 1
            inner: _Inner | None = None

        violations = _lax_scalar_fields("body", FieldInfo(annotation=_Body), set())

        # `field_strict_counts` is a violation: field-level strictness
        # does not reach collection items.
        assert violations == [
            "_Body.flag",
            "_Body.counts",
            "_Body.field_strict_counts",
            "_Body.ratios",
            "_Inner.lax",
        ]


def _body_models(info: _RouteInfo) -> list[type[BaseModel]]:
    """The models that declare `info`'s JSON request body, collected from
    its effective dependency graph."""
    return [
        model
        for node in _iter_dependants(info.dependant)
        for param in node.body_params
        for model in _nested_models(param.field_info.annotation)
    ]


def _with_nested_models(models: Iterable[type[BaseModel]]) -> list[type[BaseModel]]:
    """`models` and every model their fields reference at any depth, each
    once, in discovery order."""
    found: list[type[BaseModel]] = []
    pending = list(models)
    while pending:
        model = pending.pop(0)
        if model in found:
            continue
        found.append(model)
        for field_info in model.model_fields.values():
            pending.extend(_nested_models(field_info.annotation))
    return found


def _component(document: dict[str, Any], model: type[BaseModel]) -> dict[str, Any]:
    """The OpenAPI component of the request model `model`."""
    schemas: dict[str, Any] = document["components"]["schemas"]
    for name in (model.__name__, f"{model.__name__}-Input"):
        if name in schemas:
            component: dict[str, Any] = schemas[name]
            return component
    raise AssertionError(f"{model.__name__} has no OpenAPI component")


def _admits_null(schema: dict[str, Any], document: dict[str, Any]) -> bool:
    """Whether `schema`, with its `$ref`s resolved in `document`, admits
    JSON `null`."""
    schema = _resolve_schema_ref(document, schema)
    declared = schema.get("type")
    if declared == "null" or (isinstance(declared, list) and "null" in declared):
        return True
    if None in schema.get("enum", ()) or (
        "const" in schema and schema["const"] is None
    ):
        return True
    return any(
        _admits_null(option, document)
        for option in (*schema.get("anyOf", ()), *schema.get("oneOf", ()))
    )


def _validation_accepts_null(model: type[BaseModel], key: str) -> bool:
    """Whether validating `model` with `null` as its only member `key`
    reports no error at `key`. Errors at other members, such as a missing
    required member, and at the whole model are not about this `null`."""
    try:
        model.model_validate({key: None})
    except ValidationError as exc:
        return all(error["loc"][:1] != (key,) for error in exc.errors())
    return True


def _nullability_violations(
    model: type[BaseModel], component: dict[str, Any], document: dict[str, Any]
) -> list[str]:
    """Every member of `model` whose published nullability in `component`
    differs from whether validation accepts `null` for it."""
    violations: list[str] = []
    properties: dict[str, Any] = component.get("properties", {})
    for name, field_info in model.model_fields.items():
        key = field_info.alias or name
        published = _admits_null(properties[key], document)
        accepted = _validation_accepts_null(model, key)
        if published != accepted:
            violations.append(
                f"{model.__name__}.{name}: published "
                f"{'nullable' if published else 'non-nullable'}, but validation "
                f"{'accepts' if accepted else 'rejects'} null"
            )
    return violations


def _optional_members_not_missing(model: type[BaseModel]) -> list[str]:
    """Every optional member of `model` whose default is not `MISSING`."""
    return [
        f"{model.__name__}.{name} does not default to MISSING"
        for name, field_info in model.model_fields.items()
        if not field_info.is_required() and field_info.default is not MISSING
    ]


@pytest.mark.unit
class TestRequestBodyNullability:
    """Every JSON request-body member is published as nullable exactly when
    validation accepts `null` for it, and every optional member of a `PATCH`
    body defaults to `MISSING`.

    See `docs/api-spec.md` (Request Body Nullability and Defaults; Partial
    Update Semantics) and `docs/conventions.md` (Pydantic Conventions,
    Omitted request members; Omitted Values). A `None` default with a
    validator that rejects `null` publishes a member as nullable although
    the request rejects it, and a hand-written schema can hide a `null` that
    the request accepts; both mislead a client generated from the document.
    Body models are collected from every route's effective dependency graph,
    nested models included.
    """

    def test_published_nullability_matches_validation(self) -> None:
        document = app.openapi()
        models = _with_nested_models(
            model for info in _api_routes() for model in _body_models(info)
        )
        assert models, "no JSON request-body model found"

        violations = [
            violation
            for model in models
            for violation in _nullability_violations(
                model, _component(document, model), document
            )
        ]

        assert not violations, "\n".join(violations)

    def test_every_optional_patch_member_defaults_to_missing(self) -> None:
        patch_models = [
            (info.path, model)
            for info in _api_routes()
            if "PATCH" in info.methods
            for model in _body_models(info)
        ]
        assert patch_models, "no PATCH request-body model found"

        violations = sorted(
            {
                f"Route '{path}': {violation}"
                for path, model in patch_models
                for violation in _optional_members_not_missing(model)
            }
        )

        assert not violations, "\n".join(violations)

    def test_nullability_detection_covers_validators_overrides_and_nesting(
        self,
    ) -> None:
        """Guards the checker itself against passing vacuously."""

        class _Inner(BaseModel):
            hidden: Annotated[str | None, WithJsonSchema({"type": "string"})] = None
            count: int = Field(strict=True)

        class _Body(BaseModel):
            nullable: str | None = None
            omittable: str | MISSING = MISSING
            rejected: str | None = None
            required: int = Field(strict=True)
            inner: _Inner | MISSING = MISSING

            @field_validator("rejected", mode="before")
            @classmethod
            def _reject_null(cls, value: Any) -> Any:
                if value is None:
                    raise ValueError("rejected cannot be null.")
                return value

        document = _Body.model_json_schema(mode="validation")
        models = _with_nested_models([_Body])
        components = {_Body: document, _Inner: document["$defs"]["_Inner"]}

        violations = [
            violation
            for model in models
            for violation in _nullability_violations(model, components[model], document)
        ]

        assert models == [_Body, _Inner]
        assert violations == [
            "_Body.rejected: published nullable, but validation rejects null",
            "_Inner.hidden: published non-nullable, but validation accepts null",
        ]

    def test_patch_default_detection_covers_none_and_factories(self) -> None:
        """Guards the checker itself against passing vacuously."""

        class _Patch(BaseModel):
            cleared: int | None = Field(default=None, strict=True)
            listed: list[str] = Field(default_factory=list)
            omittable: str | MISSING = MISSING
            required: str

        assert _optional_members_not_missing(_Patch) == [
            "_Patch.cleared does not default to MISSING",
            "_Patch.listed does not default to MISSING",
        ]


# docs/api-spec.md (Parameter Nullability): the parameter locations it covers.
_NON_NULLABLE_PARAMETER_LOCATIONS: Final = frozenset({"path", "query"})


def _path_and_query_parameters(
    document: dict[str, Any],
) -> Iterable[tuple[str, dict[str, Any]]]:
    """Every path and query parameter of `document`, with its operation."""
    for path, item in document.get("paths", {}).items():
        for method, operation in item.items():
            if not isinstance(operation, dict):
                continue
            for parameter in operation.get("parameters", ()):
                if parameter.get("in") in _NON_NULLABLE_PARAMETER_LOCATIONS:
                    yield f"{method.upper()} {path}", parameter


def _nullable_parameters(document: dict[str, Any]) -> list[str]:
    """Every path and query parameter of `document` whose schema admits
    `null` or whose default is `null`."""
    violations: list[str] = []
    for operation, parameter in _path_and_query_parameters(document):
        schema: dict[str, Any] = parameter.get("schema", {})
        if _admits_null(schema, document) or (
            "default" in schema and schema["default"] is None
        ):
            violations.append(
                f"{operation}: {parameter['in']} parameter {parameter['name']}"
            )
    return violations


@pytest.mark.unit
class TestParameterNullability:
    """No path or query parameter is published as nullable.

    See `docs/api-spec.md` (Parameter Nullability) and `docs/conventions.md`
    (FastAPI Conventions, Optional parameters). A parameter is a string by
    transport, so no request can send `null` for it, but FastAPI publishes the
    `None` default of an optional parameter as `null`; a client generated from
    that document accepts a `null` that only fails, or matches the text
    `null`, at runtime. The check reads the generated document, so it covers
    every parameter, whichever dependency declares it.
    """

    def test_no_parameter_is_published_as_nullable(self) -> None:
        document = app.openapi()
        assert any(
            parameter["in"] == "query"
            for _, parameter in _path_and_query_parameters(document)
        ), "no query parameter found"

        violations = _nullable_parameters(document)

        assert not violations, "\n".join(violations)

    def test_detection_covers_alternatives_type_lists_references_and_defaults(
        self,
    ) -> None:
        """Guards the checker itself against passing vacuously."""

        def parameter(name: str, location: str, schema: Any) -> dict[str, Any]:
            return {"name": name, "in": location, "schema": schema}

        document: dict[str, Any] = {
            "paths": {
                "/items/{item_id}": {
                    "get": {
                        "parameters": [
                            parameter("item_id", "path", {"type": ["string", "null"]}),
                            parameter(
                                "active",
                                "query",
                                {"anyOf": [{"type": "boolean"}, {"type": "null"}]},
                            ),
                            parameter(
                                "state",
                                "query",
                                {"$ref": "#/components/schemas/NullableState"},
                            ),
                            parameter(
                                "search", "query", {"type": "string", "default": None}
                            ),
                            parameter(
                                "page", "query", {"type": "integer", "default": 1}
                            ),
                            parameter(
                                "order", "query", {"$ref": "#/components/schemas/Order"}
                            ),
                            parameter(
                                "trace",
                                "header",
                                {"anyOf": [{"type": "string"}, {"type": "null"}]},
                            ),
                        ]
                    }
                }
            },
            "components": {
                "schemas": {
                    "NullableState": {"enum": ["open", "closed", None]},
                    "Order": {"type": "string", "enum": ["asc", "desc"]},
                }
            },
        }

        assert _nullable_parameters(document) == [
            "GET /items/{item_id}: path parameter item_id",
            "GET /items/{item_id}: query parameter active",
            "GET /items/{item_id}: query parameter state",
            "GET /items/{item_id}: query parameter search",
        ]

    def test_detection_covers_the_schema_fastapi_generates(self) -> None:
        """A plain `FastAPI` application, without the publication of
        `SentinelAPI`, publishes the `None` default of an optional parameter
        as a `null` alternative."""
        plain = FastAPI()

        @plain.get("/items")
        async def items(active: Annotated[bool | None, Query()] = None) -> None:
            """An optional parameter with a `None` default."""

        assert _nullable_parameters(plain.openapi()) == [
            "GET /items: query parameter active"
        ]


def _iter_dependants(dependant: Dependant) -> list[Dependant]:
    """Every `Dependant` node in `dependant`'s tree, including itself.

    Walks nested dependencies (e.g. an authentication dependency that
    itself depends on the database session) so a `get_db` occurrence
    hidden behind another dependency is not missed.
    """
    nodes = [dependant]
    for sub_dependant in dependant.dependencies:
        nodes.extend(_iter_dependants(sub_dependant))
    return nodes


@pytest.mark.unit
class TestTransactionDependencyScope:
    """Every route dependency graph that uses the API transaction
    session (`get_db`) declares it with `scope="function"`, at any
    depth (including a `get_db` occurrence nested under another
    dependency, e.g. authentication).

    See `docs/conventions.md` (API Transaction Dependency Scope):
    FastAPI defaults an unscoped `yield` dependency to
    `scope="request"`, whose post-yield code (commit, rollback,
    post-commit callbacks in `get_db()`) runs *after* the response has
    already been transmitted to the client — breaking the "commits
    before the caller can observe success" guarantee (Caller-Owned
    Service Transactions). `scope="function"` runs that same post-yield
    code before the response is sent, so a commit failure surfaces as a
    real error response instead of an already-decided success one. The
    shared `DatabaseSession` alias (`app/database.py`) pins this scope
    — this test guards against a future endpoint bypassing it via a raw
    `Depends(get_db)`.

    `use_cache` is also checked: a `get_db` occurrence declared with
    `use_cache=False` would open a second, independent session and
    transaction for the same request even if correctly function-scoped,
    splitting the caller-owned transaction the same guarantee requires
    to be singular.
    """

    def test_every_get_db_dependency_is_function_scoped_and_cached(self) -> None:
        violations: list[str] = []
        for info in _api_routes():
            for node in _iter_dependants(info.dependant):
                if node.call is not get_db:
                    continue
                if node.scope != "function":
                    violations.append(
                        f"Route '{info.path}' uses 'get_db' with scope "
                        f"'{node.scope}' (must be 'function' — use the "
                        "'DatabaseSession' alias from 'app.database' "
                        "instead of 'Depends(get_db)')"
                    )
                if not node.use_cache:
                    violations.append(
                        f"Route '{info.path}' uses 'get_db' with "
                        "use_cache=False, which opens a second, "
                        "independent transaction for the same request"
                    )
        assert not violations, "\n".join(violations)


@pytest.mark.unit
class TestTicketConvergenceDrain:
    """Every route that uses the API transaction session also drains its
    Ticket convergence effects after commit.

    See `docs/features/tickets/ticket-service.md` (Ticket Convergence >
    Publication policies): the API transaction dependency is an automatic
    transaction owner, so every request transaction that can register a
    convergence effect must detach and attempt it after `get_db()`
    commits. The drain is mounted on every `/api/v1` router in
    `app/main.py`; this test guards against a router added without it.
    """

    def test_every_get_db_route_has_the_drain_dependency(self) -> None:
        missing = [
            info.path
            for info in _api_routes()
            if any(n.call is get_db for n in _iter_dependants(info.dependant))
            and not any(
                n.call is drain_ticket_convergence_after_commit
                for n in _iter_dependants(info.dependant)
            )
        ]
        assert not missing, (
            "Routes using 'get_db' without 'drain_ticket_convergence_after_commit': "
            f"{missing}"
        )
