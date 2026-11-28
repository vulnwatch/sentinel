"""End-to-end tests for the caller's own Ticket audit events endpoint
(`backend/app/api/v1/ticket_audit.py`, `GET /api/v1/users/me/tickets/audit-log`).

See docs/features/tickets/ticket-audit-log.md (API > List My Ticket
Events; Testing Requirement 32) for the endpoint contract, docs/api-spec.md
(Pagination, Enum Filter Validation, Date Range Interpretation, Undeclared
Query Parameters, User References in Responses) for the shared responses,
and docs/features/platform/testing-strategy.md (Ticket Accessibility;
Actor Identities). Ordering, projection, filter, and independent-session
race coverage lives in tests/test_services/test_ticket_audit_log_own_events.py;
these tests cover the HTTP contract.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock

import pytest
from httpx import AsyncClient
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import Role, TicketAuditEventType
from app.core.identifiers import format_ticket_id
from app.main import app
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.user import User
from app.models.user_role import UserRole
from app.services import ticket_audit_log

Factory = Callable[..., Awaitable[Any]]

_PATH = "/api/v1/users/me/tickets/audit-log"
_BASE_TIME = datetime(2026, 3, 15, 10, 30, tzinfo=UTC)
_UNAUTHENTICATED = {
    "code": "AUTH_NOT_AUTHENTICATED",
    "detail": "Authentication required",
}
_TRACK = {"track": "SUSE:SLE-15-SP6:Update", "package": "fictional-package"}


def _reference(user: User) -> dict[str, Any]:
    return {
        "id": str(user.id),
        "username": user.username,
        "full_name": user.full_name,
        "active": user.active,
        "bot": user.bot,
        "avatar_url": user.avatar_url,
    }


@pytest.fixture
def authenticated_user(
    _authenticated_user_and_client: tuple[User, AsyncClient],
) -> User:
    """The role-less `User` behind `authenticated_client`."""
    return _authenticated_user_and_client[0]


@pytest.mark.e2e
class TestAuthentication:
    @pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer invalid-token"}])
    async def test_missing_or_invalid_credential_returns_401_before_the_read(
        self,
        headers: dict[str, str],
        client: AsyncClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        lister = AsyncMock()
        monkeypatch.setattr(ticket_audit_log, "list_own_ticket_events", lister)

        response = await client.get(_PATH, headers=headers)

        assert response.status_code == 401
        assert response.json() == _UNAUTHENTICATED
        lister.assert_not_awaited()


@pytest.mark.e2e
class TestListMyTicketEventsEndpoint:
    async def test_returns_the_callers_events_with_their_ticket_fields(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        ticket_factory: Factory,
        cve_factory: Factory,
        user_factory: Factory,
        ticket_audit_event_factory: Factory,
    ) -> None:
        """A role-less caller lists the events that they recorded while they
        held a role, each with their own complete user reference
        (testing-strategy.md, Actor Identities)."""
        cve = await cve_factory(cve_id="CVE-2026-1234")
        with_cve: Ticket = await ticket_factory(cve_id=cve.id)
        without_cve: Ticket = await ticket_factory()
        other: User = await user_factory()
        newer = await ticket_audit_event_factory(
            ticket_id=with_cve.id,
            event_type="track_status_changed",
            user_id=authenticated_user.id,
            old_value="ANALYSIS",
            new_value="AFFECTED",
            detail=_TRACK,
            created_at=_BASE_TIME,
        )
        older = await ticket_audit_event_factory(
            ticket_id=without_cve.id,
            event_type="ticket_created",
            user_id=authenticated_user.id,
            comment="Ticket created manually",
            created_at=_BASE_TIME.replace(hour=9),
        )
        await ticket_audit_event_factory(ticket_id=with_cve.id, created_at=_BASE_TIME)
        await ticket_audit_event_factory(
            ticket_id=with_cve.id, user_id=other.id, created_at=_BASE_TIME
        )

        response = await authenticated_client.get(_PATH)

        assert response.status_code == 200
        assert response.json() == {
            "data": [
                {
                    "id": str(newer.id),
                    "ticket_id": format_ticket_id(with_cve.sequence_id),
                    "cve_id": "CVE-2026-1234",
                    "is_confidential": False,
                    "event_type": "track_status_changed",
                    "old_value": "ANALYSIS",
                    "new_value": "AFFECTED",
                    "comment": None,
                    "detail": _TRACK,
                    "created_at": "2026-03-15T10:30:00Z",
                    "actor": _reference(authenticated_user),
                },
                {
                    "id": str(older.id),
                    "ticket_id": format_ticket_id(without_cve.sequence_id),
                    "cve_id": None,
                    "is_confidential": False,
                    "event_type": "ticket_created",
                    "old_value": None,
                    "new_value": None,
                    "comment": "Ticket created manually",
                    "detail": None,
                    "created_at": "2026-03-15T09:30:00Z",
                    "actor": _reference(authenticated_user),
                },
            ],
            "meta": {"total": 2, "page": 1, "per_page": 20},
        }
        assert str(with_cve.id) not in response.text

    async def test_caller_without_events_gets_an_empty_page(
        self,
        authenticated_client: AsyncClient,
        ticket_factory: Factory,
        user_factory: Factory,
        ticket_audit_event_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        await ticket_audit_event_factory(ticket_id=ticket.id)
        await ticket_audit_event_factory(
            ticket_id=ticket.id, user_id=(await user_factory()).id
        )

        response = await authenticated_client.get(_PATH)

        assert response.status_code == 200
        assert response.json() == {
            "data": [],
            "meta": {"total": 0, "page": 1, "per_page": 20},
        }

    async def test_filters_are_forwarded(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        ticket_factory: Factory,
        ticket_audit_event_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        match = await ticket_audit_event_factory(
            ticket_id=ticket.id,
            event_type="status_change",
            user_id=authenticated_user.id,
            new_value="Fixed 100%",
            created_at=_BASE_TIME,
        )
        for overrides in (
            {"event_type": "assignment"},
            {"new_value": "Fixed 1000"},
            {"created_at": _BASE_TIME.replace(day=14)},
        ):
            await ticket_audit_event_factory(
                ticket_id=ticket.id,
                **{
                    "event_type": "status_change",
                    "user_id": authenticated_user.id,
                    "new_value": "Fixed 100%",
                    "created_at": _BASE_TIME,
                    **overrides,
                },
            )

        response = await authenticated_client.get(
            _PATH,
            params={
                "event_type": ["status_change", "bogus"],
                "search": " 100% ",
                "from_date": "2026-03-15",
                "to_date": "2026-03-15",
            },
        )

        assert response.status_code == 200
        assert [item["id"] for item in response.json()["data"]] == [str(match.id)]
        assert response.json()["meta"]["total"] == 1

    async def test_all_invalid_event_types_return_an_empty_page(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        ticket_factory: Factory,
        ticket_audit_event_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        await ticket_audit_event_factory(
            ticket_id=ticket.id, user_id=authenticated_user.id
        )

        response = await authenticated_client.get(
            _PATH, params={"event_type": ["bogus", "status_change,assignment"]}
        )

        assert response.status_code == 200
        assert response.json() == {
            "data": [],
            "meta": {"total": 0, "page": 1, "per_page": 20},
        }

    async def test_pagination_and_page_beyond_the_last(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        ticket_factory: Factory,
        ticket_audit_event_factory: Factory,
    ) -> None:
        for _ in range(3):
            ticket: Ticket = await ticket_factory()
            await ticket_audit_event_factory(
                ticket_id=ticket.id,
                user_id=authenticated_user.id,
                created_at=_BASE_TIME,
            )

        first = await authenticated_client.get(_PATH, params={"page": 1, "per_page": 2})
        second = await authenticated_client.get(
            _PATH, params={"page": 2, "per_page": 2}
        )
        beyond = await authenticated_client.get(
            _PATH, params={"page": 3, "per_page": 2}
        )

        ids = [item["id"] for page in (first, second) for item in page.json()["data"]]
        assert ids == sorted(ids, reverse=True)
        assert len(set(ids)) == 3
        assert beyond.json() == {
            "data": [],
            "meta": {"total": 3, "page": 3, "per_page": 2},
        }

    @pytest.mark.parametrize(
        "params",
        [
            {"page": 0},
            {"page": 2_147_483_648},
            {"per_page": 0},
            {"per_page": 101},
            {"page": "abc"},
            {"from_date": "15/03/2026"},
            {"to_date": "1710498600"},
            {"search": "x" * 501},
            {"event_type": "x" * 501},
        ],
    )
    async def test_invalid_query_returns_422(
        self, params: dict[str, Any], authenticated_client: AsyncClient
    ) -> None:
        response = await authenticated_client.get(_PATH, params=params)

        assert response.status_code == 422
        assert response.json()["code"] == "VALIDATION_ERROR"

    async def test_boundary_query_values_are_accepted(
        self, authenticated_client: AsyncClient
    ) -> None:
        response = await authenticated_client.get(
            _PATH,
            params={"page": 2_147_483_647, "per_page": 100, "search": "x" * 500},
        )

        assert response.status_code == 200
        assert response.json()["meta"] == {
            "total": 0,
            "page": 2_147_483_647,
            "per_page": 100,
        }

    async def test_inverted_date_range_returns_400(
        self, authenticated_client: AsyncClient
    ) -> None:
        response = await authenticated_client.get(
            _PATH, params={"from_date": "2026-03-16", "to_date": "2026-03-15"}
        )

        assert response.status_code == 400
        assert response.json()["code"] == "DATE_RANGE_INVERTED"

    async def test_undeclared_parameters_are_ignored(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        ticket_factory: Factory,
        user_factory: Factory,
        ticket_audit_event_factory: Factory,
    ) -> None:
        """`actor` is not declared: a supplied value neither selects another
        user's events nor system events (`docs/api-spec.md`, Undeclared
        Query Parameters)."""
        ticket: Ticket = await ticket_factory()
        other: User = await user_factory(username="fictional.other")
        own = await ticket_audit_event_factory(
            ticket_id=ticket.id, user_id=authenticated_user.id
        )
        await ticket_audit_event_factory(ticket_id=ticket.id, user_id=other.id)
        await ticket_audit_event_factory(ticket_id=ticket.id)

        for params in (
            {"actor": "fictional.other"},
            {"actor": str(other.id)},
            {"actor": "system"},
            {"sort_by": "created_at", "sort_order": "asc"},
        ):
            response = await authenticated_client.get(_PATH, params=params)
            assert response.status_code == 200, params
            assert [item["id"] for item in response.json()["data"]] == [str(own.id)]


@pytest.mark.e2e
class TestTicketVisibility:
    async def test_invisible_confidential_ticket_is_neither_listed_nor_counted(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        ticket_factory: Factory,
        ticket_audit_event_factory: Factory,
    ) -> None:
        public: Ticket = await ticket_factory()
        hidden: Ticket = await ticket_factory(is_confidential=True)
        own = await ticket_audit_event_factory(
            ticket_id=public.id, user_id=authenticated_user.id
        )
        await ticket_audit_event_factory(
            ticket_id=hidden.id, user_id=authenticated_user.id
        )

        response = await authenticated_client.get(_PATH)

        assert response.status_code == 200
        assert [item["id"] for item in response.json()["data"]] == [str(own.id)]
        assert response.json()["meta"]["total"] == 1
        assert format_ticket_id(hidden.sequence_id) not in response.text

    @pytest.mark.parametrize(
        "branch", ["va_scope", "admin_scope", "grant", "maintainer"]
    )
    async def test_each_visibility_branch_lists_the_confidential_ticket(
        self,
        branch: str,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        ticket_factory: Factory,
        user_role_factory: Factory,
        ticket_access_grant_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_maintainer_factory: Factory,
        ticket_audit_event_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory(is_confidential=True)
        await ticket_audit_event_factory(
            ticket_id=ticket.id, user_id=authenticated_user.id
        )
        if branch == "va_scope":
            await user_role_factory(
                user_id=authenticated_user.id, role=Role.VULNERABILITY_ANALYST.value
            )
        elif branch == "admin_scope":
            await user_role_factory(
                user_id=authenticated_user.id, role=Role.ADMIN.value
            )
        elif branch == "grant":
            await ticket_access_grant_factory(
                ticket_id=ticket.id, user_id=authenticated_user.id
            )
        else:
            package = await ticket_package_factory(ticket_id=ticket.id)
            await ticket_package_maintainer_factory(
                ticket_package_id=package.id, user_id=authenticated_user.id
            )

        response = await authenticated_client.get(_PATH)

        assert response.status_code == 200
        (item,) = response.json()["data"]
        assert item["ticket_id"] == format_ticket_id(ticket.sequence_id)
        assert item["is_confidential"] is True

    async def test_restricted_analyst_without_a_path_does_not_list_the_ticket(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        ticket_factory: Factory,
        user_role_factory: Factory,
        ticket_audit_event_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory(is_confidential=True)
        await ticket_audit_event_factory(
            ticket_id=ticket.id, user_id=authenticated_user.id
        )
        await user_role_factory(
            user_id=authenticated_user.id, role=Role.RESTRICTED_ANALYST.value
        )

        response = await authenticated_client.get(_PATH)

        assert response.status_code == 200
        assert response.json()["meta"]["total"] == 0

    async def test_access_lost_during_the_request_hides_the_events(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        ticket_factory: Factory,
        ticket_access_grant_factory: Factory,
        ticket_audit_event_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The route relies on the service's own protected selection: a
        grant revoked after the caller was resolved hides its events."""
        ticket: Ticket = await ticket_factory(is_confidential=True)
        await ticket_access_grant_factory(
            ticket_id=ticket.id, user_id=authenticated_user.id
        )
        await ticket_audit_event_factory(
            ticket_id=ticket.id, user_id=authenticated_user.id
        )
        original = ticket_audit_log.list_own_ticket_events

        async def _revoke_then_list(db: AsyncSession, **kwargs: Any) -> Any:
            await db.execute(
                delete(TicketAccessGrant).where(
                    TicketAccessGrant.ticket_id == ticket.id
                )
            )
            return await original(db, **kwargs)

        monkeypatch.setattr(
            ticket_audit_log, "list_own_ticket_events", _revoke_then_list
        )

        response = await authenticated_client.get(_PATH)

        assert response.status_code == 200
        assert response.json()["meta"]["total"] == 0

    async def test_role_removed_during_the_request_applies_to_the_next_request(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        ticket_factory: Factory,
        user_role_factory: Factory,
        ticket_audit_event_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        ticket: Ticket = await ticket_factory(is_confidential=True)
        await ticket_audit_event_factory(
            ticket_id=ticket.id, user_id=authenticated_user.id
        )
        await user_role_factory(
            user_id=authenticated_user.id, role=Role.VULNERABILITY_ANALYST.value
        )
        original = ticket_audit_log.list_own_ticket_events

        async def _remove_role_then_list(db: AsyncSession, **kwargs: Any) -> Any:
            await db.execute(
                delete(UserRole).where(UserRole.user_id == authenticated_user.id)
            )
            return await original(db, **kwargs)

        monkeypatch.setattr(
            ticket_audit_log, "list_own_ticket_events", _remove_role_then_list
        )
        in_flight = await authenticated_client.get(_PATH)
        monkeypatch.setattr(ticket_audit_log, "list_own_ticket_events", original)
        next_request = await authenticated_client.get(_PATH)

        assert in_flight.json()["meta"]["total"] == 1
        assert next_request.json()["meta"]["total"] == 0


@pytest.mark.unit
class TestOpenApiContract:
    def test_declares_exactly_the_specified_query_parameters(self) -> None:
        operation = app.openapi()["paths"][_PATH]["get"]
        parameters = {param["name"]: param for param in operation["parameters"]}

        assert set(parameters) == {
            "event_type",
            "search",
            "from_date",
            "to_date",
            "page",
            "per_page",
        }
        assert all(param["in"] == "query" for param in parameters.values())
        assert parameters["event_type"]["schema"]["items"]["enum"] == [
            member.value for member in TicketAuditEventType
        ]

    def test_declares_no_not_found_response(self) -> None:
        responses = app.openapi()["paths"][_PATH]["get"]["responses"]

        assert "404" not in responses
        assert "403" not in responses
        assert "DATE_RANGE_INVERTED" in responses["400"]["description"]

    def test_item_carries_the_ticket_fields_and_a_non_null_actor(self) -> None:
        schema = app.openapi()
        operation = schema["paths"][_PATH]["get"]
        body = operation["responses"]["200"]["content"]["application/json"]["schema"]
        components = schema["components"]["schemas"]
        response = components[body["$ref"].rsplit("/", 1)[-1]]
        item_ref = response["properties"]["data"]["items"]["$ref"]
        item = components[item_ref.rsplit("/", 1)[-1]]

        assert set(response["properties"]) == {"data", "meta"}
        assert set(item["properties"]) == {
            "id",
            "ticket_id",
            "cve_id",
            "is_confidential",
            "event_type",
            "old_value",
            "new_value",
            "comment",
            "detail",
            "created_at",
            "actor",
        }
        assert item["properties"]["actor"]["$ref"] == (
            "#/components/schemas/UserReference"
        )
        assert item["properties"]["is_confidential"]["type"] == "boolean"
        assert set(item["required"]) >= {"cve_id", "is_confidential", "actor"}
