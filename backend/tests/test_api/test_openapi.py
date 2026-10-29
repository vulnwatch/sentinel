"""Tests for the OpenAPI documentation of the global and shared responses,
and of parameters without `null` (`app/api/openapi.py`).

See `docs/api-spec.md` (Global Responses, Response Applicability
Derivation, Parameter Nullability). Most cases build a standalone
`SentinelAPI` whose routes use the real authentication and capability
dependencies and the methods that derive the cross-origin rejection, or
optional parameters with a `None` default; a vacuity guard builds a plain
`FastAPI` instead, and the cases that FastAPI does not generate use a
hand-written document. Only the generated or hand-written document is
inspected, so no request runs. The registered application is
covered by the structural tests in `tests/test_api_conventions.py`, by the
required-authentication `401` check in
`tests/test_api/test_route_authentication.py`, and by the OpenAPI response
contract check over every test request (`tests/support/openapi_contract.py`).
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any

import pytest
from fastapi import APIRouter, Depends, FastAPI, Query
from pydantic import BaseModel

from app.api.dependencies import (
    AuthenticatedPrincipal,
    CurrentUser,
    require_any_capability,
    require_capability,
)
from app.api.openapi import (
    API_V1_RESPONSES,
    SentinelAPI,
    publish_parameters_without_null,
)
from app.core.enums import Capability
from app.schemas.errors import ErrorResponse

_ERROR_REF = {"$ref": "#/components/schemas/ErrorResponse"}
_REQUIRED_401 = (
    "`AUTH_NOT_AUTHENTICATED`: no credential was sent, or the credential is invalid."
)
_403 = "`AUTH_INSUFFICIENT_PERMISSION`: the caller lacks the required capability."
_CROSS_ORIGIN_403 = (
    "`AUTH_CROSS_ORIGIN_REJECTED`: a browser sent the request for a page of an "
    "origin that is neither the API's own nor a configured browser client."
)
_400 = "`DATE_RANGE_INVERTED`: `from_date` is after `to_date`."


def _date_range(
    from_date: Annotated[str | None, Query()] = None,
    to_date: Annotated[str | None, Query()] = None,
) -> None:
    """A query dependency declaring both date-range parameters, as the
    audit-log and list endpoints do."""


def _lower_bound(from_date: Annotated[str | None, Query()] = None) -> None:
    """A query dependency declaring only one of them."""


def _build_app(*, include_v1_responses: bool = True) -> SentinelAPI:
    router = APIRouter(prefix="/api/v1")

    @router.get("/public")
    async def public() -> None:
        """No credential processing."""

    @router.post("/public-action")
    async def public_post() -> None:
        """No credential processing, with an unsafe method."""

    @router.patch("/public-action")
    async def public_patch() -> None:
        """No credential processing, with an unsafe method."""

    @router.delete("/public-action")
    async def public_delete() -> None:
        """No credential processing, with an unsafe method."""

    @router.put("/public-action")
    async def public_put() -> None:
        """No credential processing, with a method no Sentinel endpoint
        uses: the derivation covers every method other than the safe ones."""

    @router.post(
        "/own-403-action",
        responses={
            403: {"model": ErrorResponse, "description": "`AUTH_SESSION_REQUIRED`."}
        },
    )
    async def own_403_action(
        principal: Annotated[
            AuthenticatedPrincipal,
            Depends(require_capability(Capability.MANAGE_USERS)),
        ],
    ) -> None:
        """A route-level 403 on an unsafe method."""

    @router.get("/authenticated")
    async def authenticated(principal: CurrentUser) -> None:
        """`Access: Authenticated`."""

    @router.post("/capability")
    async def capability(
        principal: Annotated[
            AuthenticatedPrincipal,
            Depends(require_capability(Capability.MANAGE_FETCHERS)),
        ],
    ) -> None:
        """`Capability: manage_fetchers`."""

    @router.post("/any-capability")
    async def any_capability(
        principal: Annotated[
            AuthenticatedPrincipal,
            Depends(
                require_any_capability(
                    Capability.TRIAGE_TICKET, Capability.MANAGE_FETCHERS
                )
            ),
        ],
    ) -> None:
        """`Capability: triage_ticket OR manage_fetchers`."""

    @router.get("/date-range", dependencies=[Depends(_date_range)])
    async def date_range() -> None:
        """Both date-range parameters, declared by a dependency."""

    @router.get("/lower-bound", dependencies=[Depends(_lower_bound)])
    async def lower_bound() -> None:
        """Only `from_date`."""

    @router.get("/hidden", include_in_schema=False)
    async def hidden(principal: CurrentUser) -> None:
        """Derives a 401, but has no operation to document it on."""

    @router.get(
        "/own-403",
        responses={
            403: {"model": ErrorResponse, "description": "`AUTH_SESSION_REQUIRED`."}
        },
    )
    async def own_403(
        principal: Annotated[
            AuthenticatedPrincipal,
            Depends(require_capability(Capability.MANAGE_USERS)),
        ],
    ) -> None:
        """A route-level 403 that does not name the derived code."""

    @router.get(
        "/own-400",
        dependencies=[Depends(_date_range)],
        responses={
            400: {
                "model": ErrorResponse,
                "description": "`DATE_RANGE_INVERTED` or `DATE_RANGE_TOO_WIDE`.",
            }
        },
    )
    async def own_400() -> None:
        """A route-level 400 that already names the derived code."""

    test_app = SentinelAPI()
    test_app.include_router(
        router, responses=API_V1_RESPONSES if include_v1_responses else None
    )
    return test_app


def _responses(test_app: SentinelAPI, method: str, path: str) -> dict[str, Any]:
    responses: dict[str, Any] = test_app.openapi()["paths"][f"/api/v1{path}"][method][
        "responses"
    ]
    return responses


def _derived(description: str) -> dict[str, Any]:
    return {
        "description": description,
        "content": {"application/json": {"schema": _ERROR_REF}},
    }


@pytest.mark.unit
class TestDependencyDerivedResponses:
    @pytest.mark.parametrize(
        ("method", "path", "expected"),
        [
            pytest.param("get", "/public", {}, id="public"),
            pytest.param(
                "get", "/authenticated", {"401": _REQUIRED_401}, id="authenticated"
            ),
            pytest.param(
                "post",
                "/capability",
                {"401": _REQUIRED_401, "403": f"{_403} {_CROSS_ORIGIN_403}"},
                id="capability",
            ),
            pytest.param(
                "post",
                "/any-capability",
                {"401": _REQUIRED_401, "403": f"{_403} {_CROSS_ORIGIN_403}"},
                id="any-capability",
            ),
            *(
                pytest.param(
                    method,
                    "/public-action",
                    {"403": _CROSS_ORIGIN_403},
                    id=f"public-{method}",
                )
                for method in ("post", "patch", "delete", "put")
            ),
            pytest.param("get", "/date-range", {"400": _400}, id="date-range"),
            pytest.param("get", "/lower-bound", {}, id="one-date-parameter"),
        ],
    )
    def test_documents_the_responses_of_the_dependency_graph(
        self, method: str, path: str, expected: dict[str, str]
    ) -> None:
        responses = _responses(_build_app(), method, path)

        derived = {
            status: response
            for status, response in responses.items()
            if status not in {"200", "422", "500"}
        }
        assert derived == {
            status: _derived(description) for status, description in expected.items()
        }

    def test_responses_are_ordered_by_status(self) -> None:
        responses = _responses(_build_app(), "post", "/capability")

        assert list(responses) == ["200", "401", "403", "422", "500"]

    def test_route_level_status_keeps_its_schema_and_gains_the_condition(
        self,
    ) -> None:
        responses = _responses(_build_app(), "get", "/own-403")

        assert responses["403"] == {
            "description": f"`AUTH_SESSION_REQUIRED`. {_403}",
            "content": {"application/json": {"schema": _ERROR_REF}},
        }

    def test_route_level_status_on_an_unsafe_method_gains_both_conditions(
        self,
    ) -> None:
        responses = _responses(_build_app(), "post", "/own-403-action")

        assert responses["403"] == {
            "description": f"`AUTH_SESSION_REQUIRED`. {_403} {_CROSS_ORIGIN_403}",
            "content": {"application/json": {"schema": _ERROR_REF}},
        }

    def test_route_level_description_naming_the_code_is_unchanged(self) -> None:
        responses = _responses(_build_app(), "get", "/own-400")

        assert responses["400"]["description"] == (
            "`DATE_RANGE_INVERTED` or `DATE_RANGE_TOO_WIDE`."
        )

    def test_error_schema_is_added_when_nothing_else_references_it(self) -> None:
        schemas = _build_app(include_v1_responses=False).openapi()["components"][
            "schemas"
        ]

        assert schemas["ErrorResponse"]["required"] == ["code", "detail"]

    def test_route_excluded_from_the_schema_is_skipped(self) -> None:
        """Its derived 401 has no operation to go on; generation does not
        fail and adds nothing for it."""
        assert "/api/v1/hidden" not in _build_app().openapi()["paths"]

    def test_error_schema_is_not_added_when_nothing_is_derived(self) -> None:
        router = APIRouter(prefix="/api/v1")

        @router.get("/public")
        async def public() -> None:
            """No credential processing."""

        test_app = SentinelAPI()
        test_app.include_router(router)

        schemas = test_app.openapi().get("components", {}).get("schemas", {})
        assert "ErrorResponse" not in schemas


@pytest.mark.unit
class TestApiV1Responses:
    def test_documents_the_validation_body_and_the_internal_error(self) -> None:
        openapi_schema = _build_app().openapi()
        responses = openapi_schema["paths"]["/api/v1/public"]["get"]["responses"]
        schemas = openapi_schema["components"]["schemas"]

        assert responses["422"]["content"]["application/json"]["schema"] == {
            "$ref": "#/components/schemas/ValidationErrorResponse"
        }
        assert responses["500"]["content"]["application/json"]["schema"] == _ERROR_REF
        assert "HTTPValidationError" not in schemas
        validation = schemas["ValidationErrorResponse"]
        assert validation["required"] == ["code", "detail", "errors"]
        assert validation["properties"]["errors"]["items"] == {
            "$ref": "#/components/schemas/ValidationErrorItem"
        }
        assert schemas["ValidationErrorItem"]["required"] == ["loc", "msg", "type"]


class _Order(StrEnum):
    ASC = "asc"
    DESC = "desc"


class _Note(BaseModel):
    text: str | None = None


def _search(
    search: Annotated[str | None, Query(min_length=2, description="Text.")] = None,
) -> None:
    """An optional parameter declared by a query builder, as the list
    endpoints declare theirs."""


def _build_parameter_app(app_class: type[FastAPI] = SentinelAPI) -> FastAPI:
    router = APIRouter(prefix="/api/v1")

    @router.get("/items/{item_id}", dependencies=[Depends(_search)])
    async def item(
        item_id: str,
        active: Annotated[bool | None, Query()] = None,
        number: Annotated[int | None, Query(ge=1, le=10)] = None,
        order: Annotated[_Order | None, Query()] = None,
        mixed: Annotated[int | str | None, Query()] = None,
        page: Annotated[int, Query(ge=1)] = 1,
    ) -> None:
        """Optional parameters of several types, and two without `None`."""

    @router.post("/notes")
    async def notes(note: _Note) -> None:
        """A request body with a nullable member."""

    test_app = app_class()
    test_app.include_router(router)
    return test_app


def _parameters(test_app: FastAPI, path: str) -> dict[str, Any]:
    """The schema of each parameter of the `GET` operation of `path`."""
    operation = test_app.openapi()["paths"][f"/api/v1{path}"]["get"]
    return {
        parameter["name"]: parameter["schema"] for parameter in operation["parameters"]
    }


def _publish(*parameters: dict[str, Any]) -> list[dict[str, Any]]:
    """`parameters`, as one `GET` operation of a hand-written document, after
    `publish_parameters_without_null`. Its path item also holds a member that
    is not an operation."""
    document: dict[str, Any] = {
        "paths": {
            "/edge": {
                "summary": "A path item member that is not an operation.",
                "get": {"parameters": list(parameters)},
            }
        }
    }

    publish_parameters_without_null(document)

    published: list[dict[str, Any]] = document["paths"]["/edge"]["get"]["parameters"]
    return published


@pytest.mark.unit
class TestParametersWithoutNull:
    """`SentinelAPI` publishes every path and query parameter without the
    `null` alternative that FastAPI generates for a `None` default
    (`docs/api-spec.md`, Parameter Nullability)."""

    def test_fastapi_publishes_a_none_default_as_null(self) -> None:
        """Guards the cases below against passing vacuously."""
        parameters = _parameters(_build_parameter_app(FastAPI), "/items/{item_id}")

        assert parameters["active"] == {
            "anyOf": [{"type": "boolean"}, {"type": "null"}],
            "title": "Active",
        }

    def test_optional_parameter_is_published_as_its_type(self) -> None:
        parameters = _parameters(_build_parameter_app(), "/items/{item_id}")

        assert parameters["active"] == {"type": "boolean", "title": "Active"}
        assert parameters["number"] == {
            "type": "integer",
            "maximum": 10,
            "minimum": 1,
            "title": "Number",
        }
        assert parameters["order"] == {
            "$ref": "#/components/schemas/_Order",
            "title": "Order",
        }
        assert parameters["mixed"] == {
            "anyOf": [{"type": "integer"}, {"type": "string"}],
            "title": "Mixed",
        }
        assert parameters["search"] == {
            "type": "string",
            "minLength": 2,
            "description": "Text.",
            "title": "Search",
        }

    def test_parameters_without_none_are_unchanged(self) -> None:
        parameters = _parameters(_build_parameter_app(), "/items/{item_id}")

        assert parameters["item_id"] == {"type": "string", "title": "Item Id"}
        assert parameters["page"] == {
            "type": "integer",
            "minimum": 1,
            "default": 1,
            "title": "Page",
        }

    def test_nullable_request_body_member_keeps_its_null(self) -> None:
        schemas = _build_parameter_app().openapi()["components"]["schemas"]

        assert schemas["_Note"]["properties"]["text"]["anyOf"] == [
            {"type": "string"},
            {"type": "null"},
        ]

    def test_other_parameters_are_left_as_they_are(self) -> None:
        """Cases that FastAPI does not generate for Sentinel's routes: a
        header parameter, a parameter described by `content`, and one whose
        only alternative is `null`."""
        null = {"type": "null"}
        parameters = _publish(
            {
                "name": "trace",
                "in": "header",
                "schema": {"anyOf": [{"type": "string"}, null]},
            },
            {"name": "described", "in": "query", "content": {}},
            {"name": "only_null", "in": "query", "schema": {"anyOf": [null]}},
        )

        assert [parameter.get("schema") for parameter in parameters] == [
            {"anyOf": [{"type": "string"}, null]},
            None,
            {"anyOf": [null]},
        ]

    def test_remaining_alternative_sharing_a_keyword_stays_in_any_of(
        self,
    ) -> None:
        """Merging the alternative into the schema around it would overwrite
        one of their values, so only the `null` alternative is removed."""
        (parameter,) = _publish(
            {
                "name": "clash",
                "in": "query",
                "schema": {
                    "anyOf": [{"type": "string", "title": "In"}, {"type": "null"}],
                    "title": "Out",
                },
            }
        )

        assert parameter["schema"] == {
            "anyOf": [{"type": "string", "title": "In"}],
            "title": "Out",
        }
