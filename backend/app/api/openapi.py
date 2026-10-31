"""OpenAPI documentation of the global and shared responses, and of
parameters without `null`.

`docs/api-spec.md` (Global Responses, Response Applicability Derivation)
derives these responses from an endpoint's access level, method, and query
shape, so endpoint error tables never repeat them. The OpenAPI document, the contract
API clients are generated from, documents them for every operation
(`docs/api-spec.md`, Derived Responses in the OpenAPI Document), from what
produces them (`docs/conventions.md`, FastAPI Conventions):

- `422 VALIDATION_ERROR` and `500 INTERNAL_ERROR` apply to every `/api/v1`
  operation whatever its access level. `API_V1_RESPONSES` declares them once,
  for every router `app.main` includes under `/api/v1`. This also stops
  FastAPI from documenting its own validation-error body, which is not the
  body the application returns (`app.main`, `_validation_error_response`).
- `401 AUTH_NOT_AUTHENTICATED`, `403 AUTH_INSUFFICIENT_PERMISSION`, and the
  shared `400 DATE_RANGE_INVERTED` apply when an operation's dependency graph
  contains the dependency that produces them: authentication, a capability
  check, or both date-range query parameters. `403
  AUTH_CROSS_ORIGIN_REJECTED` applies to every operation whose method is
  unsafe, whatever its access level. `SentinelAPI` adds them to the
  generated document (`document_derived_responses`), so a new endpoint
  documents them without declaring them.

A route that declares a status itself keeps its declaration, because it
describes endpoint-specific codes for that status. For `422`, its schema
must therefore also admit `ValidationErrorResponse`
(`backend/tests/test_api_conventions.py`); for a derived status, the derived
condition is appended to its description.

`SentinelAPI` also publishes every path and query parameter without a `null`
alternative (`docs/api-spec.md`, Parameter Nullability;
`publish_parameters_without_null`). FastAPI publishes the `None` default of an
optional parameter as `null`, which no request can send, because a parameter
is a string by transport.

Finally, it publishes constraints that the shared request handling enforces
outside the parameter schemas (`docs/api-spec.md`, Published Input
Constraints): the Query Parameter Length Limit as the `maxLength` of each
parameter that its dependency inspects
(`publish_query_parameter_length_limit`). An enum filter publishes the values
its parser accepts through `enum_filter_schema`.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from typing import Any, Final

from fastapi import FastAPI
from fastapi import routing as fastapi_routing
from fastapi.dependencies.models import Dependant
from fastapi.routing import APIRoute
from starlette.routing import BaseRoute

from app.api.dependencies import (
    get_current_user,
    require_any_capability,
    require_capability,
)
from app.core.cross_origin import SAFE_METHODS
from app.core.query_limits import (
    MAX_QUERY_STRING_LENGTH,
    enforce_query_parameter_length_limit,
)
from app.core.route_params import declared_string_param_names
from app.schemas.errors import ErrorResponse, ValidationErrorResponse

API_V1_RESPONSES: Final[dict[int | str, dict[str, Any]]] = {
    422: {
        "model": ValidationErrorResponse,
        "description": (
            "`VALIDATION_ERROR`: the request fails validation; `errors` lists "
            "each invalid input."
        ),
    },
    500: {
        "model": ErrorResponse,
        "description": "`INTERNAL_ERROR`: unhandled server error.",
    },
}
"""The responses of every `/api/v1` operation (`docs/api-spec.md`, Global
Response Derivation), passed to `include_router()` by `app.main`."""

_ERROR_RESPONSE_REF: Final = f"#/components/schemas/{ErrorResponse.__name__}"

# The closures `require_capability()` and `require_any_capability()` return
# for each endpoint share these qualified names.
_CAPABILITY_CHECKS: Final = frozenset(
    f"{factory.__qualname__}.<locals>._dependency"
    for factory in (require_capability, require_any_capability)
)


@dataclass(frozen=True)
class DerivedResponse:
    """A derived response: its status, error code, and the condition its
    OpenAPI description states."""

    status: str
    code: str
    condition: str

    @property
    def description(self) -> str:
        return f"`{self.code}`: {self.condition}"


_REQUIRED_AUTHENTICATION: Final = DerivedResponse(
    "401",
    "AUTH_NOT_AUTHENTICATED",
    "no credential was sent, or the credential is invalid.",
)
_CAPABILITY: Final = DerivedResponse(
    "403",
    "AUTH_INSUFFICIENT_PERMISSION",
    "the caller lacks the required capability.",
)
_DATE_RANGE: Final = DerivedResponse(
    "400", "DATE_RANGE_INVERTED", "`from_date` is after `to_date`."
)
_DATE_RANGE_PARAMETERS: Final = frozenset({"from_date", "to_date"})
_CROSS_ORIGIN: Final = DerivedResponse(
    "403",
    "AUTH_CROSS_ORIGIN_REJECTED",
    "a browser sent the request for a page of an origin that is neither the "
    "API's own nor a configured browser client.",
)

_NULL_SCHEMA: Final = {"type": "null"}
# docs/api-spec.md (Parameter Nullability): the parameter locations it covers.
_NON_NULLABLE_PARAMETER_LOCATIONS: Final = frozenset({"path", "query"})


def _dependants(dependant: Dependant) -> Iterator[Dependant]:
    """`dependant` and every dependency nested below it."""
    yield dependant
    for sub_dependant in dependant.dependencies:
        yield from _dependants(sub_dependant)


def dependency_responses(dependant: Dependant) -> list[DerivedResponse]:
    """The global and shared responses an operation with the effective
    dependency graph `dependant` can return, beyond `API_V1_RESPONSES`
    (`docs/api-spec.md`, Global Response Derivation and Query-Shape
    Response Derivation)."""
    nodes = list(_dependants(dependant))
    calls = {node.call for node in nodes}
    responses: list[DerivedResponse] = []
    if get_current_user in calls:
        responses.append(_REQUIRED_AUTHENTICATION)
    if any(getattr(call, "__qualname__", None) in _CAPABILITY_CHECKS for call in calls):
        responses.append(_CAPABILITY)
    query_names = {param.alias for node in nodes for param in node.query_params}
    if query_names >= _DATE_RANGE_PARAMETERS:
        responses.append(_DATE_RANGE)
    return responses


def method_responses(method: str) -> list[DerivedResponse]:
    """The shared responses an operation with the HTTP method `method` can
    return (`docs/api-spec.md`, Method Response Derivation): `403
    AUTH_CROSS_ORIGIN_REJECTED` for every method other than `GET`, `HEAD`,
    or `OPTIONS`."""
    return [] if method in SAFE_METHODS else [_CROSS_ORIGIN]


def document_derived_responses(
    openapi_schema: dict[str, Any], routes: Sequence[BaseRoute]
) -> None:
    """Add to `openapi_schema`, in place, the `dependency_responses()` and
    `method_responses()` of every documented operation of `routes`.

    An operation that already documents the status keeps its schema; the
    derived condition is appended to its description unless the
    description already names the code. Responses are ordered by status.
    """
    paths: dict[str, Any] = openapi_schema.get("paths", {})
    referenced = False
    for context in fastapi_routing.iter_route_contexts(routes):
        if not isinstance(context.original_route, APIRoute):
            continue
        dependency_derived = dependency_responses(context.dependant)
        for method in context.methods or ():
            derived = dependency_derived + method_responses(method)
            if not derived:
                continue
            # A route excluded from the schema has no operation to document.
            operation = paths.get(context.path_format or "", {}).get(method.lower())
            if operation is None:
                continue
            responses: dict[str, Any] = operation.setdefault("responses", {})
            for response in derived:
                existing = responses.get(response.status)
                if existing is None:
                    referenced = True
                    responses[response.status] = {
                        "description": response.description,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": _ERROR_RESPONSE_REF}
                            }
                        },
                    }
                elif f"`{response.code}`" not in existing.get("description", ""):
                    existing["description"] = (
                        f"{existing.get('description', '')} {response.description}"
                    ).strip()
            operation["responses"] = dict(sorted(responses.items()))
    if referenced:
        # Present whenever an `/api/v1` router is included (the `500` of
        # `API_V1_RESPONSES`); added otherwise so the reference resolves.
        openapi_schema.setdefault("components", {}).setdefault(
            "schemas", {}
        ).setdefault(ErrorResponse.__name__, ErrorResponse.model_json_schema())


def _without_null(schema: dict[str, Any]) -> dict[str, Any]:
    """`schema` without its `null` alternative, or `schema` itself when it
    has none. A single remaining alternative replaces the `anyOf`, so the
    result equals the schema generated for the type without `None`, unless
    it shares a keyword with the schema around it; the `anyOf` then stays."""
    alternatives: list[dict[str, Any]] = schema.get("anyOf", [])
    remaining = [option for option in alternatives if option != _NULL_SCHEMA]
    if not remaining or len(remaining) == len(alternatives):
        return schema
    outer = {key: value for key, value in schema.items() if key != "anyOf"}
    if len(remaining) == 1 and not remaining[0].keys() & outer.keys():
        return {**remaining[0], **outer}
    return {**outer, "anyOf": remaining}


def publish_parameters_without_null(openapi_schema: dict[str, Any]) -> None:
    """Remove from `openapi_schema`, in place, the `null` alternative of every
    path and query parameter (`docs/api-spec.md`, Parameter Nullability)."""
    for item in openapi_schema.get("paths", {}).values():
        for operation in item.values():
            if not isinstance(operation, dict):
                continue
            for parameter in operation.get("parameters", ()):
                if parameter.get("in") in _NON_NULLABLE_PARAMETER_LOCATIONS and (
                    "schema" in parameter
                ):
                    parameter["schema"] = _without_null(parameter["schema"])


def enum_filter_schema(values: Iterable[str], *, repeatable: bool) -> dict[str, Any]:
    """The `json_schema_extra` of an enum filter parameter that publishes
    `values`, the values its parser accepts, as the parameter's `enum`
    (`docs/api-spec.md`, Enum Filter Validation; Published Input
    Constraints).

    The parameter keeps its string type, so a value outside `values` is
    still ignored, not rejected; callers pass the mapping or `StrEnum` that
    the parser itself reads, so the two cannot drift. `repeatable` selects
    the schema of a list parameter, whose items carry the `enum`.
    """
    # `str()` of a `StrEnum` member is its value.
    enum = [str(value) for value in values]
    if repeatable:
        return {"items": {"type": "string", "enum": enum}}
    return {"enum": enum}


def _string_schemas(schema: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """The schemas of the strings that a string-shaped parameter carries:
    the items of an array, the alternatives of an `anyOf`, or the schema
    itself, whether a string or a reference to a string enum component,
    such as the enum of a `sort_by` parameter."""
    if schema.get("type") == "array" and isinstance(schema.get("items"), dict):
        yield from _string_schemas(schema["items"])
    elif "anyOf" in schema:
        for alternative in schema["anyOf"]:
            yield from _string_schemas(alternative)
    elif schema.get("type") == "string" or "$ref" in schema:
        yield schema


def publish_query_parameter_length_limit(
    openapi_schema: dict[str, Any], routes: Sequence[BaseRoute]
) -> None:
    """Publish in `openapi_schema`, in place, the Query Parameter Length
    Limit (`docs/api-spec.md`) as the `maxLength` of every string query
    parameter that `enforce_query_parameter_length_limit` inspects: in
    each operation whose dependency graph contains that dependency, the
    parameters that `declared_string_param_names()` finds in the graph. A
    smaller `maxLength` that an endpoint declares itself is kept."""
    paths: dict[str, Any] = openapi_schema.get("paths", {})
    for context in fastapi_routing.iter_route_contexts(routes):
        if not isinstance(context.original_route, APIRoute):
            continue
        calls = {node.call for node in _dependants(context.dependant)}
        if enforce_query_parameter_length_limit not in calls:
            continue
        names = set(declared_string_param_names(context.dependant, "query"))
        for method in context.methods or ():
            operation = paths.get(context.path_format or "", {}).get(method.lower())
            if operation is None:
                continue
            for parameter in operation.get("parameters", ()):
                if parameter.get("in") != "query" or parameter.get("name") not in names:
                    continue
                for schema in _string_schemas(parameter.get("schema", {})):
                    schema["maxLength"] = min(
                        schema.get("maxLength", MAX_QUERY_STRING_LENGTH),
                        MAX_QUERY_STRING_LENGTH,
                    )


class SentinelAPI(FastAPI):
    """FastAPI, whose generated OpenAPI document also describes the
    derived responses (`document_derived_responses`), publishes every
    path and query parameter without `null`
    (`publish_parameters_without_null`), and publishes the query
    parameter length limit (`publish_query_parameter_length_limit`)."""

    def openapi(self) -> dict[str, Any]:
        if self.openapi_schema is None:
            openapi_schema = super().openapi()
            document_derived_responses(openapi_schema, self.routes)
            publish_parameters_without_null(openapi_schema)
            publish_query_parameter_length_limit(openapi_schema, self.routes)
            return openapi_schema
        return self.openapi_schema
