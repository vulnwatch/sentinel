"""End-to-end tests for Calculate CVSS Base Score
(`GET /api/v1/cvss/base-score`, `backend/app/api/v1/cvss.py`).

See docs/features/tickets/cvss-scoring.md (Calculate CVSS Base Score; Input
Rules; Stable Parsed Result; Shared Assessment Item; Required Tests >
Persistence and API Tests), docs/api-spec.md (Query Parameter Length Limit;
Published Input Constraints; Inadmissible Characters in Request Input;
Response Applicability Derivation), and docs/features/identity/rbac.md
(Endpoint Permission Map).

The parser matrix is proven by tests/test_services/test_cvss.py. These
tests cover the HTTP contract: the parity of the calculation with the SUSE
upsert for representative strings that each exercise a step of the
operation, the absence of side effects, the read-only profile, the missing
parameter, the route inventory, and OpenAPI. The `401` of a request without
a credential is proven for this route by the route-wide test of
tests/test_api/test_route_authentication.py.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any, Final

import pytest
import pytest_asyncio
from fastapi import routing as fastapi_routing
from fastapi.routing import APIRoute
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import Role, TicketStatus
from app.main import app
from app.models.cve import CVE
from app.models.cve_cvss_assessment import CVECVSSAssessment
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.user import User

Factory = Callable[..., Awaitable[Any]]

_PATH: Final = "/api/v1/cvss/base-score"
_UPSERT_PATH: Final = "/api/v1/cves/{cve_id}/cvss/suse"
_INVALID_VECTOR: Final = {
    "code": "CVSS_INVALID_VECTOR",
    "detail": "Invalid CVSS vector.",
}
_DERIVED_FIELDS: Final = (
    "cvss_version",
    "score",
    "severity",
    "vector_string",
    "metrics",
)
"""The fields of the Shared Assessment Item that the vector determines."""

V20 = "AV:N/AC:L/Au:N/C:C/I:C/A:C"
V30 = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V31_REORDERED = "CVSS:3.1/A:H/I:H/C:H/S:U/UI:N/PR:N/AC:L/AV:N"
V31_MEDIUM = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N"
V40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
V40_REORDERED = "CVSS:4.0/SA:N/SI:N/SC:N/VA:H/VI:H/VC:H/UI:N/PR:N/AT:N/AC:L/AV:N"
V3_CRITICAL_METRICS = {
    "attack_vector": "network",
    "attack_complexity": "low",
    "privileges_required": "none",
    "user_interaction": "none",
    "scope": "unchanged",
    "confidentiality_impact": "high",
    "integrity_impact": "high",
    "availability_impact": "high",
}


def _padded(vector: str, length: int) -> str:
    """`vector` with outer whitespace up to `length` received characters."""
    padding = length - len(vector)
    return " " * (padding // 2) + vector + "\t" * (padding - padding // 2)


@pytest.fixture
async def default_setting(system_setting_factory: Factory) -> SystemSetting:
    """The persisted `default_cvss_version` that the SUSE upsert reads (the
    test schema has none)."""
    setting: SystemSetting = await system_setting_factory(
        key="default_cvss_version", value="3.1"
    )
    return setting


@pytest_asyncio.fixture
async def va_user(
    _authenticated_user_and_client: tuple[User, AsyncClient],
    user_role_factory: Factory,
) -> User:
    """`authenticated_client`'s user holding `vulnerability_analyst`, so that
    the same client can also call the SUSE upsert."""
    user = _authenticated_user_and_client[0]
    await user_role_factory(user_id=user.id, role=Role.VULNERABILITY_ANALYST.value)
    return user


# ---------------------------------------------------------------------------
# Parity with Set or Update SUSE CVSS Assessment
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestParityWithTheSUSEUpsert:
    """For one received string, the calculation returns what the upsert
    stores, or rejects it with the upsert's status and code
    (cvss-scoring.md, Calculate CVSS Base Score > Parity with the SUSE
    upsert). Each string exercises one step of the operation."""

    @pytest.mark.parametrize(
        ("value", "rejection"),
        [
            # The response discriminator, for every accepted version.
            pytest.param(V20, None, id="v2.0"),
            pytest.param(V30, None, id="v3.0"),
            pytest.param(V31_MEDIUM, None, id="v3.1"),
            pytest.param(V40, None, id="v4.0"),
            # Query decoding and trimming.
            pytest.param(f" \t{V40_REORDERED}\n ", None, id="other-order-and-padding"),
            # No minimum length.
            pytest.param("", "CVSS_INVALID_VECTOR", id="empty"),
            # No case folding.
            pytest.param(
                V31.replace("CVSS:", "cvss:"), "CVSS_INVALID_VECTOR", id="case"
            ),
            # The strict parser, never the External Base Reduction.
            pytest.param(
                V31.removeprefix("CVSS:3.1/"), "CVSS_INVALID_VECTOR", id="no-prefix"
            ),
            pytest.param(f"{V40}/E:P", "CVSS_INVALID_VECTOR", id="non-base-metric"),
            # Rule 1 at the query parameter, and the shared constraint.
            pytest.param(_padded(V31_REORDERED, 200), None, id="200-characters"),
            pytest.param(
                _padded(V31_REORDERED, 201), "VALIDATION_ERROR", id="201-characters"
            ),
            pytest.param(f"{V31}\x00", "VALIDATION_ERROR", id="inadmissible-character"),
        ],
    )
    async def test_calculation_matches_the_upsert(
        self,
        value: str,
        rejection: str | None,
        authenticated_client: AsyncClient,
        va_user: User,
        default_setting: SystemSetting,
        cve_factory: Factory,
    ) -> None:
        cve: CVE = await cve_factory()

        upsert = await authenticated_client.post(
            _UPSERT_PATH.format(cve_id=cve.cve_id), json={"vector_string": value}
        )
        calculation = await authenticated_client.get(
            _PATH, params={"vector_string": value}
        )

        if rejection is None:
            assert (upsert.status_code, calculation.status_code) == (201, 200)
            item = upsert.json()["data"]
            assert calculation.json() == {
                "data": {field: item[field] for field in _DERIVED_FIELDS}
            }
            return
        assert calculation.status_code == upsert.status_code == 422
        assert calculation.json()["code"] == upsert.json()["code"] == rejection
        upsert_errors = upsert.json().get("errors", [])
        calculation_errors = calculation.json().get("errors", [])
        assert [e["loc"] for e in calculation_errors] == [
            ["query", "vector_string"] for _ in upsert_errors
        ]
        assert [e["loc"] for e in upsert_errors] == [
            ["body", "vector_string"] for _ in upsert_errors
        ]
        assert [(e["type"], e["msg"]) for e in calculation_errors] == [
            (e["type"], e["msg"]) for e in upsert_errors
        ]
        if rejection == "CVSS_INVALID_VECTOR":
            assert calculation.json() == _INVALID_VECTOR


# ---------------------------------------------------------------------------
# The calculation alone
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestCalculateBaseScore:
    async def test_role_less_caller_receives_the_canonical_result(
        self, authenticated_client: AsyncClient
    ) -> None:
        """The read-only profile suffices, and undeclared parameters named
        like derived fields cannot enter the result."""
        response = await authenticated_client.get(
            _PATH,
            params={
                "vector_string": f"  {V31_REORDERED}\t",
                "score": "0.0",
                "cvss_version": "2.0",
                "severity": "low",
            },
        )

        assert response.status_code == 200
        assert response.json() == {
            "data": {
                "cvss_version": "3.1",
                "score": 9.8,
                "severity": "critical",
                "vector_string": V31,
                "metrics": V3_CRITICAL_METRICS,
            }
        }

    async def test_missing_parameter_is_a_validation_error(
        self, authenticated_client: AsyncClient
    ) -> None:
        response = await authenticated_client.get(_PATH)

        assert response.status_code == 422
        payload = response.json()
        assert payload["code"] == "VALIDATION_ERROR"
        assert [(e["loc"], e["type"]) for e in payload["errors"]] == [
            (["query", "vector_string"], "missing")
        ]

    async def test_calculation_changes_no_assessment_cve_ticket_or_audit_event(
        self,
        authenticated_client: AsyncClient,
        va_user: User,
        db_session: AsyncSession,
        cve_factory: Factory,
        ticket_factory: Factory,
        cve_cvss_assessment_factory: Factory,
    ) -> None:
        """A calculation for a vector that a SUSE upsert would make effective
        on this CVE neither stores it nor assigns, moves, or audits the
        Ticket, and neither does a rejected one."""
        cve: CVE = await cve_factory(severity="Critical")
        ticket: Ticket = await ticket_factory(
            status=TicketStatus.NEW.value, cve_id=cve.id
        )
        await cve_cvss_assessment_factory(cve_id=cve.id, provider_name="NVD")
        before = await self._state(db_session, cve, ticket)

        accepted = await authenticated_client.get(
            _PATH, params={"vector_string": V31_MEDIUM}
        )
        rejected = await authenticated_client.get(
            _PATH, params={"vector_string": f"{V31}/E:H"}
        )

        assert (accepted.status_code, rejected.status_code) == (200, 422)
        assert await self._state(db_session, cve, ticket) == before

    @staticmethod
    async def _state(
        db: AsyncSession, cve: CVE, ticket: Ticket
    ) -> tuple[list[tuple[str, str]], str | None, tuple[Any, ...], int]:
        assessments = [
            (row.provider_name, row.vector_string)
            for row in await db.execute(
                select(CVECVSSAssessment.provider_name, CVECVSSAssessment.vector_string)
                .where(CVECVSSAssessment.cve_id == cve.id)
                .order_by(CVECVSSAssessment.provider_name)
            )
        ]
        severity = (
            await db.execute(select(CVE.severity).where(CVE.id == cve.id))
        ).scalar_one()
        ticket_state = (
            await db.execute(
                select(Ticket.status, Ticket.assignee_id, Ticket.priority_auto).where(
                    Ticket.id == ticket.id
                )
            )
        ).one()
        events = (
            await db.execute(select(func.count()).select_from(TicketAuditEvent))
        ).scalar_one()
        return assessments, severity, tuple(ticket_state), events


# ---------------------------------------------------------------------------
# Route inventory and OpenAPI contract
# ---------------------------------------------------------------------------


def _schemas() -> dict[str, Any]:
    schemas: dict[str, Any] = app.openapi()["components"]["schemas"]
    return schemas


def _operation() -> dict[str, Any]:
    operation: dict[str, Any] = app.openapi()["paths"][_PATH]["get"]
    return operation


def _ref_name(schema: dict[str, Any]) -> str:
    ref: str = schema["$ref"]
    return ref.rsplit("/", 1)[1]


@pytest.mark.unit
class TestRouteInventory:
    def test_only_get_is_registered_under_the_cvss_prefix(self) -> None:
        """Route discovery uses `iter_route_contexts()` — see
        `tests/test_api_conventions.py` for why `app.routes` alone does not
        expose routes included via `include_router()`."""
        routes = {
            (context.path, method)
            for context in fastapi_routing.iter_route_contexts(app.routes)
            if isinstance(context.original_route, APIRoute)
            and context.path is not None
            and context.path.startswith("/api/v1/cvss")
            for method in (context.methods or set()) - {"HEAD", "OPTIONS"}
        }

        assert routes == {(_PATH, "GET")}


@pytest.mark.unit
class TestOpenApiContract:
    def test_operation_has_summary_description_tag_and_no_body(self) -> None:
        operation = _operation()

        assert operation["summary"]
        assert operation["description"]
        assert operation["tags"] == ["CVSS"]
        assert "requestBody" not in operation

    def test_vector_string_is_a_required_query_string_of_at_most_200(self) -> None:
        (parameter,) = _operation()["parameters"]

        assert (parameter["name"], parameter["in"], parameter["required"]) == (
            "vector_string",
            "query",
            True,
        )
        schema = parameter["schema"]
        assert (schema["type"], schema["maxLength"]) == ("string", 200)
        assert "minLength" not in schema
        assert "pattern" not in schema
        assert "CVSS_INVALID_VECTOR" in parameter["description"]

    def test_responses_are_those_of_an_authenticated_read_with_its_422(
        self,
    ) -> None:
        """`Access: Authenticated` on a path without scoped responses derives
        `401`, `422`, and `500`; the endpoint adds `CVSS_INVALID_VECTOR` to
        its `422` (docs/api-spec.md, Response Applicability Derivation)."""
        responses = _operation()["responses"]

        assert set(responses) == {"200", "401", "422", "500"}
        invalid = responses["422"]["content"]["application/json"]["schema"]
        assert sorted(_ref_name(member) for member in invalid["anyOf"]) == [
            "ErrorResponse",
            "ValidationErrorResponse",
        ]
        assert "`CVSS_INVALID_VECTOR`" in responses["422"]["description"]
        assert "`VALIDATION_ERROR`" in responses["422"]["description"]

    def test_response_is_the_envelope_of_the_version_discriminated_result(
        self,
    ) -> None:
        schema = _operation()["responses"]["200"]["content"]["application/json"]
        envelope = _schemas()[_ref_name(schema["schema"])]

        assert _ref_name(schema["schema"]) == "CVSSBaseScoreResponse"
        assert (set(envelope["properties"]), envelope["required"]) == (
            {"data"},
            ["data"],
        )
        union = _schemas()[_ref_name(envelope["properties"]["data"])]
        assert union["discriminator"]["propertyName"] == "cvss_version"
        members = {
            version: _schemas()[_ref_name({"$ref": ref})]
            for version, ref in union["discriminator"]["mapping"].items()
        }
        assert set(members) == {"2.0", "3.0", "3.1", "4.0"}
        for member in members.values():
            assert list(member["properties"]) == list(_DERIVED_FIELDS)
            assert member["required"] == list(_DERIVED_FIELDS)
