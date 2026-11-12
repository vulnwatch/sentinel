"""End-to-end tests: every user representation carries `avatar_url` from the
current User record.

Owning specification: docs/features/identity/user-avatars.md (Avatar URL —
Field; Testing Requirements, item 8), with docs/api-spec.md (User References
in Responses), docs/features/identity/user-management.md (Get User; Get User
(Admin)), and docs/features/identity/authentication.md (Get Current User).

The `null` value is asserted by the exact-response tests of each endpoint.
These tests store a picture URL on every referenced user and prove that each
representation returns it exactly as stored, in particular the ones that the
services project from selected columns rather than from the ORM object: the
Ticket detail and list (`assignee`, `priority_override_by`), the access
grants, the package tree (`maintainers`), the Ticket audit log and actors,
and the CNA audit log. Every URL is fictional.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import Role
from app.core.identifiers import format_ticket_id
from app.models.cna import CNA
from app.models.cna_audit_event import CNAAuditEvent
from app.models.ticket import Ticket
from app.models.user import User
from tests.support.ticket_api import user_reference

Factory = Callable[..., Awaitable[Any]]

_HOST = "https://avatars.slack-edge.com/2026-01-15/"


def _picture(n: int) -> str:
    """A distinct fictional picture URL."""
    return f"{_HOST}100000000000{n}_0f1c7e0000000000000{n}_192.jpg"


@pytest.fixture
def caller(_authenticated_user_and_client: tuple[User, AsyncClient]) -> User:
    """The administrator behind `admin_client`."""
    return _authenticated_user_and_client[0]


@pytest.fixture
async def pictured(user_factory: Factory) -> Callable[[int], Awaitable[User]]:
    async def _create(n: int) -> User:
        user: User = await user_factory(avatar_url=_picture(n))
        return user

    return _create


@pytest.mark.e2e
class TestUserReferences:
    async def test_ticket_detail_and_list_carry_the_stored_url(
        self,
        admin_client: AsyncClient,
        ticket_factory: Factory,
        pictured: Callable[[int], Awaitable[User]],
    ) -> None:
        assignee, setter = await pictured(1), await pictured(2)
        ticket: Ticket = await ticket_factory(
            assignee_id=assignee.id,
            priority_override="P2",
            priority_override_by_id=setter.id,
        )
        ticket_id = format_ticket_id(ticket.sequence_id)

        detail = (await admin_client.get(f"/api/v1/tickets/{ticket_id}")).json()
        listed = (await admin_client.get("/api/v1/tickets")).json()["data"]

        [item] = [entry for entry in listed if entry["ticket_id"] == ticket_id]
        for data in (detail["data"], item):
            assert data["assignee"] == user_reference(assignee)
            assert data["assignee"]["avatar_url"] == _picture(1)
            assert data["priority_override_by"] == user_reference(setter)
            assert data["priority_override_by"]["avatar_url"] == _picture(2)

    async def test_access_grants_carry_the_stored_url(
        self,
        admin_client: AsyncClient,
        ticket_factory: Factory,
        ticket_access_grant_factory: Factory,
        pictured: Callable[[int], Awaitable[User]],
    ) -> None:
        grantee, grantor = await pictured(1), await pictured(2)
        ticket: Ticket = await ticket_factory(is_confidential=True)
        await ticket_access_grant_factory(
            ticket_id=ticket.id, user_id=grantee.id, granted_by_id=grantor.id
        )

        response = await admin_client.get(
            f"/api/v1/tickets/{format_ticket_id(ticket.sequence_id)}/access"
        )

        assert response.status_code == 200
        [grant] = response.json()["data"]
        assert grant["user"] == user_reference(grantee)
        assert grant["granted_by"] == user_reference(grantor)
        assert (grant["user"]["avatar_url"], grant["granted_by"]["avatar_url"]) == (
            _picture(1),
            _picture(2),
        )

    async def test_package_maintainers_carry_the_stored_url(
        self,
        admin_client: AsyncClient,
        ticket_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_maintainer_factory: Factory,
        pictured: Callable[[int], Awaitable[User]],
    ) -> None:
        maintainer = await pictured(1)
        ticket: Ticket = await ticket_factory()
        package = await ticket_package_factory(ticket_id=ticket.id)
        await ticket_package_maintainer_factory(
            ticket_package_id=package.id, user_id=maintainer.id
        )

        response = await admin_client.get(
            f"/api/v1/tickets/{format_ticket_id(ticket.sequence_id)}/packages"
        )

        assert response.status_code == 200
        [entry] = response.json()["data"]
        assert entry["maintainers"] == [user_reference(maintainer)]
        assert entry["maintainers"][0]["avatar_url"] == _picture(1)

    async def test_ticket_audit_log_and_actors_carry_the_stored_url(
        self,
        admin_client: AsyncClient,
        ticket_factory: Factory,
        ticket_audit_event_factory: Factory,
        pictured: Callable[[int], Awaitable[User]],
    ) -> None:
        actor = await pictured(1)
        ticket: Ticket = await ticket_factory()
        await ticket_audit_event_factory(ticket_id=ticket.id, user_id=actor.id)
        ticket_id = format_ticket_id(ticket.sequence_id)

        events = await admin_client.get(f"/api/v1/tickets/{ticket_id}/audit-log")
        actors = await admin_client.get(f"/api/v1/tickets/{ticket_id}/actors")

        assert [event["actor"] for event in events.json()["data"]] == [
            user_reference(actor)
        ]
        assert actors.json()["data"] == [user_reference(actor)]
        assert actors.json()["data"][0]["avatar_url"] == _picture(1)

    async def test_cna_audit_log_carries_the_stored_url(
        self,
        admin_client: AsyncClient,
        db_session: AsyncSession,
        cna_factory: Factory,
        pictured: Callable[[int], Awaitable[User]],
    ) -> None:
        actor = await pictured(1)
        cna: CNA = await cna_factory()
        db_session.add(
            CNAAuditEvent(
                cna_id=cna.id,
                user_id=actor.id,
                event_type="auto_ignore_enabled",
                detail={"cna_name": "Example"},
            )
        )
        await db_session.flush()

        response = await admin_client.get(
            "/api/v1/admin/cnas/audit-log", params={"cna": str(cna.org_id)}
        )

        assert response.status_code == 200
        [event] = response.json()["data"]
        assert event["actor"] == user_reference(actor)


@pytest.mark.e2e
class TestUserProfiles:
    async def test_directory_entry_carries_the_stored_url(
        self, admin_client: AsyncClient, pictured: Callable[[int], Awaitable[User]]
    ) -> None:
        user = await pictured(1)

        response = await admin_client.get(f"/api/v1/users/{user.id}")

        assert response.status_code == 200
        assert response.json()["data"]["avatar_url"] == _picture(1)

    async def test_complete_profile_carries_its_own_manager_and_assigner_urls(
        self,
        admin_client: AsyncClient,
        user_factory: Factory,
        user_role_factory: Factory,
        pictured: Callable[[int], Awaitable[User]],
    ) -> None:
        manager, assigner = await pictured(2), await pictured(3)
        user: User = await user_factory(avatar_url=_picture(1), manager_id=manager.id)
        await user_role_factory(
            user_id=user.id, role=Role.ADMIN.value, assigned_by=assigner.id
        )

        response = await admin_client.get(f"/api/v1/admin/users/{user.id}")

        assert response.status_code == 200
        data = response.json()["data"]
        assert data["avatar_url"] == _picture(1)
        assert data["manager"]["avatar_url"] == _picture(2)
        assert data["roles"][0]["assigned_by"] == user_reference(assigner)

    async def test_current_user_carries_the_stored_url(
        self,
        admin_client: AsyncClient,
        caller: User,
        db_session: AsyncSession,
    ) -> None:
        caller.avatar_url = _picture(1)
        await db_session.flush()

        response = await admin_client.get("/api/v1/users/me")

        assert response.status_code == 200
        assert response.json()["data"]["avatar_url"] == _picture(1)
