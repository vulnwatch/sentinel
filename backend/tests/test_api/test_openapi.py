"""Tests for the OpenAPI documentation of the global and shared responses,
of parameters without `null`, and of the published input constraints and
value sets (`app/api/openapi.py`).

See `docs/api-spec.md` (Global Responses, Response Applicability
Derivation, Parameter Nullability, Published Input Constraints, Response
Enums). Most cases build a standalone `SentinelAPI` whose routes use the
real authentication, capability, and query-length dependencies and the
methods that derive the cross-origin rejection, or optional parameters with
a `None` default; a vacuity guard builds a plain `FastAPI` instead, and the
cases that FastAPI does not generate use a hand-written document. Only the
generated or hand-written document is inspected, so no request runs. The
value sets that the registered application publishes are checked against
the domain enums in `TestPublishedValueSets`; the registered application is
otherwise covered by the structural tests in `tests/test_api_conventions.py`,
by the required-authentication `401` check in
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
    enum_filter_schema,
    publish_parameters_without_null,
)
from app.core.enums import (
    ApiKeyStatus,
    Capability,
    CatalogPresence,
    CurrentPhase,
    CVEExternalIdentifierSource,
    CVESourceFetchStatus,
    CveState,
    FetcherAuditEventType,
    FetcherRunStatus,
    FetcherRunTriggeredBy,
    IBSRequestState,
    IdentityAuditEventType,
    LifecyclePhaseFilter,
    MilestonePhase,
    ReferenceType,
    Role,
    SettingAuditEventType,
    Severity,
    SSVCAutomatable,
    SSVCExploitation,
    SSVCTechnicalImpact,
    TicketAuditEventType,
    TicketPriority,
    TicketStatus,
    UserType,
)
from app.core.permissions import role_to_wire
from app.core.query_limits import (
    MAX_QUERY_STRING_LENGTH,
    enforce_query_parameter_length_limit,
)
from app.main import app as registered_app
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


def _length_limited_app() -> SentinelAPI:
    """A standalone app that registers the real query-length dependency, as
    `app.main` does for every route."""
    router = APIRouter(prefix="/api/v1")

    @router.get("/search", dependencies=[Depends(_search)])
    async def search(
        tags: Annotated[list[str], Query(default_factory=list)],
        name: Annotated[str | None, Query()] = None,
        code: Annotated[str | None, Query(max_length=20)] = None,
        order: Annotated[_Order, Query()] = _Order.ASC,
        mixed: Annotated[int | str | None, Query()] = None,
        number: Annotated[int | None, Query()] = None,
        flag: Annotated[bool | None, Query()] = None,
    ) -> None:
        """String, list, enum, union, and non-string parameters."""

    @router.get("/items/{item_id}")
    async def item(item_id: str) -> None:
        """A path parameter, which the limit does not cover."""

    test_app = SentinelAPI(dependencies=[Depends(enforce_query_parameter_length_limit)])
    test_app.include_router(router)
    return test_app


@pytest.mark.unit
class TestQueryParameterLengthLimit:
    """`SentinelAPI` publishes the Query Parameter Length Limit as the
    `maxLength` of every parameter that its dependency inspects
    (`docs/api-spec.md`, Query Parameter Length Limit; Published Input
    Constraints)."""

    def test_string_parameters_publish_the_limit(self) -> None:
        parameters = _parameters(_length_limited_app(), "/search")

        assert parameters["name"]["maxLength"] == MAX_QUERY_STRING_LENGTH == 500
        assert parameters["search"]["maxLength"] == 500
        assert parameters["search"]["minLength"] == 2
        assert parameters["tags"]["items"]["maxLength"] == 500
        assert parameters["order"] == {
            "$ref": "#/components/schemas/_Order",
            "default": "asc",
            "maxLength": 500,
        }
        assert parameters["mixed"]["anyOf"] == [
            {"type": "integer"},
            {"type": "string", "maxLength": 500},
        ]

    def test_a_smaller_endpoint_limit_is_kept(self) -> None:
        parameters = _parameters(_length_limited_app(), "/search")

        assert parameters["code"]["maxLength"] == 20

    def test_other_parameters_are_unchanged(self) -> None:
        parameters = _parameters(_length_limited_app(), "/search")

        path_parameters = _parameters(_length_limited_app(), "/items/{item_id}")

        assert "maxLength" not in parameters["number"]
        assert "maxLength" not in parameters["flag"]
        assert "maxLength" not in path_parameters["item_id"]

    def test_operation_without_the_dependency_is_unchanged(self) -> None:
        """The limit is published only where its dependency enforces it."""
        parameters = _parameters(_build_parameter_app(), "/items/{item_id}")

        assert "maxLength" not in parameters["search"]


@pytest.mark.unit
class TestEnumFilterSchema:
    def test_single_value_filter_publishes_an_enum(self) -> None:
        assert enum_filter_schema(_Order, repeatable=False) == {"enum": ["asc", "desc"]}

    def test_repeatable_filter_publishes_the_enum_of_its_items(self) -> None:
        assert enum_filter_schema({"b": 1, "a": 2}, repeatable=True) == {
            "items": {"type": "string", "enum": ["b", "a"]}
        }

    def test_the_parameter_keeps_its_string_type(self) -> None:
        """Published, not enforced: the parameter accepts every string, so its
        parser can ignore a value outside the enum (`docs/api-spec.md`, Enum
        Filter Validation)."""
        router = APIRouter(prefix="/api/v1")

        @router.get("/filtered")
        async def filtered(
            kind: Annotated[
                str | None,
                Query(json_schema_extra=enum_filter_schema(_Order, repeatable=False)),
            ] = None,
        ) -> None:
            """A single-value enum filter."""

        test_app = SentinelAPI()
        test_app.include_router(router)

        assert _parameters(test_app, "/filtered")["kind"] == {
            "type": "string",
            "enum": ["asc", "desc"],
            "title": "Kind",
        }


def _lowercase_values(enum: type[StrEnum]) -> list[str]:
    return [member.value.lower() for member in enum]


def _values(enum: type[StrEnum]) -> list[str]:
    return [member.value for member in enum]


_TICKET_STATUSES = _lowercase_values(TicketStatus)
_SEVERITY_FILTER = [*_lowercase_values(Severity), "unresolved"]

_PUBLISHED_FILTERS = [
    ("/api/v1/users", "role", True, [role_to_wire(role) for role in Role]),
    ("/api/v1/admin/users", "role", True, [role_to_wire(role) for role in Role]),
    ("/api/v1/admin/users", "type", False, _values(UserType)),
    ("/api/v1/api-keys", "status", False, _values(ApiKeyStatus)),
    ("/api/v1/admin/api-keys", "status", False, _values(ApiKeyStatus)),
    (
        "/api/v1/admin/settings/audit-log",
        "event_type",
        True,
        _values(SettingAuditEventType),
    ),
    (
        "/api/v1/fetchers/{fetcher_name}/runs",
        "status",
        False,
        _values(FetcherRunStatus),
    ),
    (
        "/api/v1/fetchers/{fetcher_name}/audit-log",
        "event_type",
        True,
        _values(FetcherAuditEventType),
    ),
    (
        "/api/v1/tickets/{ticket_id}/audit-log",
        "event_type",
        True,
        _values(TicketAuditEventType),
    ),
    ("/api/v1/tickets", "status", True, _TICKET_STATUSES),
    ("/api/v1/tickets", "severity", True, _SEVERITY_FILTER),
    (
        "/api/v1/tickets",
        "priority",
        True,
        [*_lowercase_values(TicketPriority), "unresolved"],
    ),
    ("/api/v1/tickets", "overdue", True, _values(MilestonePhase)),
    ("/api/v1/tickets", "current_phase", True, _values(CurrentPhase)),
    ("/api/v1/cves", "cve_state", False, _lowercase_values(CveState)),
    ("/api/v1/cves", "severity", True, _SEVERITY_FILTER),
    ("/api/v1/cve-sources", "status", False, _values(CVESourceFetchStatus)),
    ("/api/v1/packages", "ticket_status", True, _TICKET_STATUSES),
    (
        "/api/v1/tickets/{ticket_id}/references",
        "type",
        False,
        _values(ReferenceType),
    ),
    (
        "/api/v1/tickets/{ticket_id}/submission-requests",
        "state",
        False,
        _values(IBSRequestState),
    ),
    (
        "/api/v1/tickets/{ticket_id}/release-requests",
        "state",
        False,
        _values(IBSRequestState),
    ),
    ("/api/v1/products", "catalog_presence", True, _values(CatalogPresence)),
    ("/api/v1/products", "lifecycle_phase", True, _values(LifecyclePhaseFilter)),
]
"""Every enum filter of the registered application, except the identity
audit logs (`tests/test_api/test_identity_audit.py`), with the values its
specification lists, filter-only values (`unresolved`, `unavailable`)
included."""

_RESPONSE_ENUMS = [
    ("CurrentUserData", "roles", "RoleValue"),
    ("UserDirectoryData", "roles", "RoleValue"),
    ("UserRoleAssignmentData", "role", "RoleValue"),
    ("UserData", "source", "UserType"),
    ("AdminIdentityAuditEventData", "event_type", "IdentityAuditEventType"),
    (
        "SelfIdentityAuditEventData",
        "event_type",
        "SelfIdentityAuditEventTypeValue",
    ),
    ("SettingAuditEventData", "event_type", "SettingAuditEventType"),
    ("FetcherLastRunData", "status", "FetcherRunStatus"),
    ("FetcherLastRunData", "triggered_by", "FetcherRunTriggeredBy"),
    ("FetcherRunListItemData", "status", "FetcherRunStatus"),
    ("FetcherRunListItemData", "triggered_by", "FetcherRunTriggeredBy"),
    ("FetcherRunDetailData", "status", "FetcherRunStatus"),
    ("FetcherRunDetailData", "triggered_by", "FetcherRunTriggeredBy"),
    ("FetcherTimelinePointData", "status", "FetcherRunStatus"),
    ("FetcherAuditEventData", "event_type", "FetcherAuditEventType"),
    ("TicketAuditEventData", "event_type", "TicketAuditEventType"),
    ("CVESSVCResponse", "exploitation", "SSVCExploitation"),
    ("CVESSVCResponse", "automatable", "SSVCAutomatable"),
    ("CVESSVCResponse", "technical_impact", "SSVCTechnicalImpact"),
    (
        "CVEExternalIdentifierResponse",
        "source",
        "CVEExternalIdentifierSourceValue",
    ),
    ("SystemSettingsData", "default_cvss_version", "DefaultCVSSVersionValue"),
    (
        "CVSSRecalculationTriggerData",
        "default_cvss_version",
        "DefaultCVSSVersionValue",
    ),
    (
        "DefaultCVSSVersionImpactData",
        "observed_default_cvss_version",
        "DefaultCVSSVersionValue",
    ),
    (
        "DefaultCVSSVersionImpactData",
        "proposed_default_cvss_version",
        "DefaultCVSSVersionValue",
    ),
]

_COMPONENT_VALUES: dict[str, list[str]] = {
    "RoleValue": [role_to_wire(role) for role in Role],
    "UserType": _values(UserType),
    "IdentityAuditEventType": _values(IdentityAuditEventType),
    "SettingAuditEventType": _values(SettingAuditEventType),
    "FetcherRunStatus": _values(FetcherRunStatus),
    "FetcherRunTriggeredBy": _values(FetcherRunTriggeredBy),
    "FetcherAuditEventType": _values(FetcherAuditEventType),
    "TicketAuditEventType": _values(TicketAuditEventType),
    "SSVCExploitation": _values(SSVCExploitation),
    "SSVCAutomatable": _values(SSVCAutomatable),
    "SSVCTechnicalImpact": _values(SSVCTechnicalImpact),
    "CVEExternalIdentifierSourceValue": _lowercase_values(CVEExternalIdentifierSource),
    "DefaultCVSSVersionValue": ["3.1", "4.0"],
}
"""The values of each response enum component, computed from the domain
enums (`SelfIdentityAuditEventTypeValue` is checked in
`tests/test_api/test_identity_audit.py`)."""


def _registered_parameter(path: str, name: str) -> dict[str, Any]:
    operation = registered_app.openapi()["paths"][path]["get"]
    (parameter,) = [p for p in operation["parameters"] if p["name"] == name]
    schema: dict[str, Any] = parameter["schema"]
    return schema


@pytest.mark.unit
class TestPublishedValueSets:
    """The registered application publishes the closed value sets of its
    filters and response fields (`docs/api-spec.md`, Response Enums; Enum
    Filter Validation; Published Input Constraints)."""

    @pytest.mark.parametrize(
        ("path", "name", "repeatable", "values"),
        [
            pytest.param(path, name, repeatable, values, id=f"{path}:{name}")
            for path, name, repeatable, values in _PUBLISHED_FILTERS
        ],
    )
    def test_enum_filter_publishes_its_values_on_a_string_parameter(
        self, path: str, name: str, repeatable: bool, values: list[str]
    ) -> None:
        """Published, not enforced: the parameter stays a string, so an
        invalid value is still ignored (each endpoint's own tests)."""
        schema = _registered_parameter(path, name)

        if repeatable:
            assert schema["type"] == "array"
            schema = schema["items"]
        assert schema["type"] == "string"
        assert schema["enum"] == values

    @pytest.mark.parametrize(
        ("component", "field", "enum"),
        [
            pytest.param(component, field, enum, id=f"{component}.{field}")
            for component, field, enum in _RESPONSE_ENUMS
        ],
    )
    def test_response_field_references_its_enum(
        self, component: str, field: str, enum: str
    ) -> None:
        schemas = registered_app.openapi()["components"]["schemas"]
        schema = schemas[component]["properties"][field]

        if schema.get("type") == "array":
            schema = schema["items"]
        assert schema["$ref"] == f"#/components/schemas/{enum}"

    @pytest.mark.parametrize(
        ("component", "values"),
        [
            pytest.param(name, values, id=name)
            for name, values in _COMPONENT_VALUES.items()
        ],
    )
    def test_enum_component_lists_the_domain_values(
        self, component: str, values: list[str]
    ) -> None:
        schemas = registered_app.openapi()["components"]["schemas"]

        assert schemas[component]["enum"] == values
