"""End-to-end tests for the Ticket actors endpoint
(`backend/app/api/v1/ticket_audit.py`).

See docs/features/tickets/ticket-audit-log.md (API > List Ticket Actors;
Testing Requirement 31) for the endpoint contract, docs/api-spec.md
(Ticket Accessibility Check, Ticket Identifier Resolution, Undeclared
Query Parameters, User References in Responses) for the shared
responses, and docs/features/platform/testing-strategy.md (Ticket
Accessibility; Actor Identities). Ordering, projection, and
independent-session race coverage lives in
tests/test_services/test_ticket_audit_log.py; these tests cover the HTTP
contract.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any
from unittest.mock import AsyncMock

import pytest
from httpx import AsyncClient
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import Role
from app.core.identifiers import format_ticket_id
from app.main import app
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.user import User
from app.models.user_role import UserRole
from app.services import ticket_audit_log, ticket_service

Factory = Callable[..., Awaitable[Any]]

_PATH = "/api/v1/tickets/{ticket_id}/actors"
_NOT_FOUND = {"code": "TICKET_NOT_FOUND", "detail": "Ticket not found."}
_UNAUTHENTICATED = {
    "code": "AUTH_NOT_AUTHENTICATED",
    "detail": "Authentication required",
}


def _url(ticket: Ticket | str) -> str:
    locator = (
        ticket if isinstance(ticket, str) else format_ticket_id(ticket.sequence_id)
    )
    return f"/api/v1/tickets/{locator}/actors"


def _reference(user: User) -> dict[str, Any]:
    return {
        "id": str(user.id),
        "username": user.username,
        "full_name": user.full_name,
        "active": user.active,
        "bot": user.bot,
    }


@pytest.fixture
def authenticated_user(
    _authenticated_user_and_client: tuple[User, AsyncClient],
) -> User:
    """The role-less `User` behind `authenticated_client`."""
    return _authenticated_user_and_client[0]


def _spy_lookups(monkeypatch: pytest.MonkeyPatch) -> tuple[AsyncMock, AsyncMock]:
    """Replace both Ticket lookups reachable from the route with spies."""
    resolver, lister = AsyncMock(), AsyncMock()
    monkeypatch.setattr(ticket_service, "resolve_ticket_locator", resolver)
    monkeypatch.setattr(ticket_audit_log, "list_ticket_actors", lister)
    return resolver, lister


@pytest.mark.e2e
class TestAuthentication:
    async def test_request_without_credential_returns_401_before_lookup(
        self, client: AsyncClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        resolver, lister = _spy_lookups(monkeypatch)

        for locator in ("SNTL-1", "not-a-ticket"):
            response = await client.get(_url(locator))
            assert response.status_code == 401
            assert response.json() == _UNAUTHENTICATED

        resolver.assert_not_awaited()
        lister.assert_not_awaited()

    async def test_invalid_credential_returns_401_before_lookup(
        self, client: AsyncClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        resolver, lister = _spy_lookups(monkeypatch)

        response = await client.get(
            _url("SNTL-1"), headers={"Authorization": "Bearer invalid-token"}
        )

        assert response.status_code == 401
        assert response.json() == _UNAUTHENTICATED
        resolver.assert_not_awaited()
        lister.assert_not_awaited()


@pytest.mark.e2e
class TestListTicketActorsEndpoint:
    async def test_returns_each_actor_once_as_a_user_reference(
        self,
        authenticated_client: AsyncClient,
        ticket_factory: Factory,
        user_factory: Factory,
        ticket_audit_event_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        analyst: User = await user_factory(
            username="fictional.analyst", full_name="Fictional Analyst"
        )
        # An inactive bot actor: `active` and `bot` differ, so each marker
        # provably comes from its own column of the current User row.
        scanner: User = await user_factory(
            username="fictional.scanner", active=False, bot=True
        )
        for actor, event_type in (
            (scanner, "reference_added"),
            (analyst, "assignment"),
            (analyst, "status_change"),
        ):
            await ticket_audit_event_factory(
                ticket_id=ticket.id, event_type=event_type, user_id=actor.id
            )
        await ticket_audit_event_factory(
            ticket_id=ticket.id, event_type="status_change"
        )

        response = await authenticated_client.get(_url(ticket))

        assert response.status_code == 200
        assert response.json() == {
            "data": [
                {
                    "id": str(analyst.id),
                    "username": "fictional.analyst",
                    "full_name": "Fictional Analyst",
                    "active": True,
                    "bot": False,
                },
                {
                    "id": str(scanner.id),
                    "username": "fictional.scanner",
                    "full_name": None,
                    "active": False,
                    "bot": True,
                },
            ]
        }
        assert str(ticket.id) not in response.text

    async def test_roleless_reader_sees_the_administrator_actor(
        self,
        authenticated_client: AsyncClient,
        ticket_factory: Factory,
        user_factory: Factory,
        user_role_factory: Factory,
        ticket_audit_event_factory: Factory,
    ) -> None:
        """A `track_status_changed` to `FIXED` through `admin_ticket_ops`
        names the administrator to a reader without that capability
        (`docs/features/identity/rbac.md`, Actor Identities)."""
        ticket: Ticket = await ticket_factory()
        admin: User = await user_factory(
            username="fictional.admin", full_name="Fictional Admin"
        )
        await user_role_factory(user_id=admin.id, role=Role.ADMIN.value)
        await ticket_audit_event_factory(
            ticket_id=ticket.id,
            event_type="track_status_changed",
            user_id=admin.id,
            old_value="AFFECTED",
            new_value="FIXED",
            detail={"track": "SUSE:SLE-15-SP6:Update", "package": "fictional-package"},
        )

        response = await authenticated_client.get(_url(ticket))

        assert response.status_code == 200
        assert response.json() == {"data": [_reference(admin)]}

    @pytest.mark.parametrize("system_events", [0, 2])
    async def test_ticket_without_a_user_attributed_event_returns_an_empty_list(
        self,
        system_events: int,
        authenticated_client: AsyncClient,
        ticket_factory: Factory,
        ticket_audit_event_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        for _ in range(system_events):
            await ticket_audit_event_factory(ticket_id=ticket.id)

        response = await authenticated_client.get(_url(ticket))

        assert response.status_code == 200
        assert response.json() == {"data": []}

    async def test_undeclared_query_parameters_are_ignored(
        self,
        authenticated_client: AsyncClient,
        ticket_factory: Factory,
        user_factory: Factory,
        ticket_audit_event_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        first: User = await user_factory(username="fictional.a")
        second: User = await user_factory(username="fictional.b")
        for actor in (second, first):
            await ticket_audit_event_factory(ticket_id=ticket.id, user_id=actor.id)

        response = await authenticated_client.get(
            _url(ticket),
            params={
                "sort_by": "username",
                "sort_order": "desc",
                "page": 2,
                "per_page": 1,
                "actor": "system",
            },
        )

        assert response.status_code == 200
        assert response.json() == {"data": [_reference(first), _reference(second)]}


@pytest.mark.e2e
class TestTicketAccessibility:
    async def test_every_not_found_cause_returns_the_identical_response(
        self,
        authenticated_client: AsyncClient,
        ticket_factory: Factory,
        user_factory: Factory,
        ticket_audit_event_factory: Factory,
    ) -> None:
        visible: Ticket = await ticket_factory()
        confidential: Ticket = await ticket_factory(is_confidential=True)
        actor: User = await user_factory()
        await ticket_audit_event_factory(ticket_id=confidential.id, user_id=actor.id)
        visible_id = format_ticket_id(visible.sequence_id)
        locators = [
            visible_id.lower(),
            "Sntl-" + visible_id.removeprefix("SNTL-"),
            f"%20{visible_id}",
            f"{visible_id}%20",
            f"SNTL-0{visible.sequence_id}",
            "SNTL-0",
            "SNTL-2147483648",
            "SNTL-99999999999999999999",
            "SNTL-",
            str(visible.id),
            "SNTL-2147483647",
            format_ticket_id(confidential.sequence_id),
        ]

        responses = [await authenticated_client.get(_url(loc)) for loc in locators]

        for locator, response in zip(locators, responses, strict=True):
            assert response.status_code == 404, locator
            assert response.json() == _NOT_FOUND, locator
            assert response.headers["content-type"] == "application/json"
        assert len({response.content for response in responses}) == 1

    @pytest.mark.parametrize(
        "branch", ["va_scope", "admin_scope", "grant", "maintainer"]
    )
    async def test_each_visibility_branch_allows_the_read(
        self,
        branch: str,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        ticket_factory: Factory,
        user_factory: Factory,
        user_role_factory: Factory,
        ticket_access_grant_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_maintainer_factory: Factory,
        ticket_audit_event_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory(is_confidential=True)
        actor: User = await user_factory()
        await ticket_audit_event_factory(ticket_id=ticket.id, user_id=actor.id)
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

        response = await authenticated_client.get(_url(ticket))

        assert response.status_code == 200
        assert response.json() == {"data": [_reference(actor)]}

    async def test_restricted_analyst_without_path_gets_404(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        ticket_factory: Factory,
        user_role_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory(is_confidential=True)
        await user_role_factory(
            user_id=authenticated_user.id, role=Role.RESTRICTED_ANALYST.value
        )

        response = await authenticated_client.get(_url(ticket))

        assert response.status_code == 404
        assert response.json() == _NOT_FOUND

    async def test_access_lost_after_the_preliminary_boundary_is_404(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        ticket_factory: Factory,
        user_factory: Factory,
        ticket_access_grant_factory: Factory,
        ticket_audit_event_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The route relies on the service's own protected selection, not
        on the preliminary `require_accessible_ticket` decision."""
        ticket: Ticket = await ticket_factory(is_confidential=True)
        await ticket_access_grant_factory(
            ticket_id=ticket.id, user_id=authenticated_user.id
        )
        actor: User = await user_factory()
        await ticket_audit_event_factory(ticket_id=ticket.id, user_id=actor.id)
        original = ticket_audit_log.list_ticket_actors

        async def _revoke_then_list(db: AsyncSession, **kwargs: Any) -> Any:
            await db.execute(
                delete(TicketAccessGrant).where(
                    TicketAccessGrant.ticket_id == ticket.id
                )
            )
            return await original(db, **kwargs)

        monkeypatch.setattr(ticket_audit_log, "list_ticket_actors", _revoke_then_list)

        response = await authenticated_client.get(_url(ticket))

        assert response.status_code == 404
        assert response.json() == _NOT_FOUND

    async def test_role_removed_during_the_request_applies_to_the_next_request(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        ticket_factory: Factory,
        user_factory: Factory,
        user_role_factory: Factory,
        ticket_audit_event_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        ticket: Ticket = await ticket_factory(is_confidential=True)
        actor: User = await user_factory()
        await ticket_audit_event_factory(ticket_id=ticket.id, user_id=actor.id)
        await user_role_factory(
            user_id=authenticated_user.id, role=Role.VULNERABILITY_ANALYST.value
        )
        original = ticket_audit_log.list_ticket_actors

        async def _remove_role_then_list(db: AsyncSession, **kwargs: Any) -> Any:
            await db.execute(
                delete(UserRole).where(UserRole.user_id == authenticated_user.id)
            )
            return await original(db, **kwargs)

        monkeypatch.setattr(
            ticket_audit_log, "list_ticket_actors", _remove_role_then_list
        )
        in_flight = await authenticated_client.get(_url(ticket))
        monkeypatch.setattr(ticket_audit_log, "list_ticket_actors", original)
        next_request = await authenticated_client.get(_url(ticket))

        assert in_flight.status_code == 200
        assert in_flight.json() == {"data": [_reference(actor)]}
        assert next_request.status_code == 404


@pytest.mark.unit
class TestOpenApiContract:
    def test_operation_is_published_without_query_parameters(self) -> None:
        operation = app.openapi()["paths"][_PATH]["get"]
        (path_param,) = operation["parameters"]

        assert path_param["in"] == "path"
        assert path_param["name"] == "ticket_id"
        assert path_param["schema"]["type"] == "string"
        assert "format" not in path_param["schema"]
        assert "pattern" not in path_param["schema"]
        assert "SNTL-" in path_param["description"]

    def test_declares_the_404_response(self) -> None:
        responses = app.openapi()["paths"][_PATH]["get"]["responses"]

        assert "TICKET_NOT_FOUND" in responses["404"]["description"]
        assert "403" not in responses

    def test_response_is_an_unpaginated_list_of_user_references(self) -> None:
        schema = app.openapi()
        operation = schema["paths"][_PATH]["get"]
        body = operation["responses"]["200"]["content"]["application/json"]["schema"]
        response = schema["components"]["schemas"][body["$ref"].rsplit("/", 1)[-1]]

        assert set(response["properties"]) == {"data"}
        assert response["properties"]["data"]["items"] == {
            "$ref": "#/components/schemas/UserReference"
        }
