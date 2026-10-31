"""End-to-end tests for identity audit log endpoints
(`backend/app/api/v1/identity_audit.py`).

See `docs/features/identity/identity-audit-log.md` (API) for the
authoritative endpoint contracts under test. Filter/date/ordering
combination coverage for the underlying query lives in
`tests/test_services/test_identity_audit_log.py` — these tests focus on
the HTTP/route contract (status codes, envelopes, error mapping,
authentication/authorization, and actor representation).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from datetime import UTC, datetime
from typing import get_args
from uuid import uuid4

import pytest
from httpx import AsyncClient

from app.api.v1.identity_audit import (
    _ADMIN_EVENT_TYPES,
    _SELF_EVENT_TYPES,
    _parse_event_types,
)
from app.core.enums import IdentityAuditEventType, Role
from app.main import app
from app.models.identity_audit_event import IdentityAuditEvent
from app.models.user import User
from app.models.user_role import UserRole
from app.schemas.identity_audit import SelfIdentityAuditEventTypeValue


@pytest.fixture
def authenticated_user(
    _authenticated_user_and_client: tuple[User, AsyncClient],
) -> User:
    """The `User` behind `authenticated_client` (`conftest.py`).

    Both fixtures depend on the same session-cached
    `_authenticated_user_and_client()` call within one test, so this
    always identifies the same user `authenticated_client` authenticates
    as. Mirrors the non-underscore alias pattern in
    `tests/test_api/test_api_keys.py`, adapted to expose only the user.
    """
    return _authenticated_user_and_client[0]


# ---------------------------------------------------------------------------
# Pure helpers (`app.api.v1.identity_audit`)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestParseEventTypes:
    def test_absent_is_valid_with_no_filter(self) -> None:
        assert _parse_event_types([], _ADMIN_EVENT_TYPES) == (True, [])

    def test_all_valid_values_are_kept(self) -> None:
        is_valid, event_types = _parse_event_types(
            ["role_added", "role_removed"], _ADMIN_EVENT_TYPES
        )
        assert is_valid is True
        assert set(event_types) == {
            IdentityAuditEventType.ROLE_ADDED,
            IdentityAuditEventType.ROLE_REMOVED,
        }

    def test_mixed_valid_and_invalid_keeps_only_valid(self) -> None:
        is_valid, event_types = _parse_event_types(
            ["role_added", "not-a-real-type"], _ADMIN_EVENT_TYPES
        )
        assert is_valid is True
        assert event_types == [IdentityAuditEventType.ROLE_ADDED]

    def test_all_invalid_is_rejected(self) -> None:
        assert _parse_event_types(["not-a-real-type"], _ADMIN_EVENT_TYPES) == (
            False,
            [],
        )

    def test_role_mapping_event_type_is_invalid_for_the_self_log(self) -> None:
        """The self log never contains role mapping events
        (`identity-audit-log.md`, List My Identity Audit Events), so its
        filter ignores their values; the admin log accepts them."""
        values = ["role_mapping_created", "role_mapping_deleted"]

        assert _parse_event_types(values, _SELF_EVENT_TYPES) == (False, [])
        assert _parse_event_types(values, _ADMIN_EVENT_TYPES) == (
            True,
            [
                IdentityAuditEventType.ROLE_MAPPING_CREATED,
                IdentityAuditEventType.ROLE_MAPPING_DELETED,
            ],
        )


@pytest.mark.unit
class TestEventTypeValueSets:
    """The event types each log returns and its filter accepts and publishes
    (`docs/api-spec.md`, Response Enums; Published Input Constraints)."""

    def test_admin_log_accepts_every_identity_event_type(self) -> None:
        assert list(_ADMIN_EVENT_TYPES) == [
            member.value for member in IdentityAuditEventType
        ]

    def test_self_log_accepts_every_type_except_role_mapping_events(self) -> None:
        expected = [
            member.value
            for member in IdentityAuditEventType
            if member
            not in {
                IdentityAuditEventType.ROLE_MAPPING_CREATED,
                IdentityAuditEventType.ROLE_MAPPING_DELETED,
            }
        ]

        assert list(get_args(SelfIdentityAuditEventTypeValue.__value__)) == expected
        assert list(_SELF_EVENT_TYPES) == expected

    @pytest.mark.parametrize(
        ("path", "component", "values"),
        [
            pytest.param(
                "/api/v1/admin/identity/audit-log",
                "IdentityAuditEventType",
                _ADMIN_EVENT_TYPES,
                id="admin",
            ),
            pytest.param(
                "/api/v1/users/me/audit-log",
                "SelfIdentityAuditEventTypeValue",
                _SELF_EVENT_TYPES,
                id="self",
            ),
        ],
    )
    def test_response_and_filter_publish_the_event_types_of_the_log(
        self, path: str, component: str, values: Mapping[str, object]
    ) -> None:
        document = app.openapi()
        (parameter,) = [
            parameter
            for parameter in document["paths"][path]["get"]["parameters"]
            if parameter["name"] == "event_type"
        ]

        assert parameter["schema"]["type"] == "array"
        assert parameter["schema"]["items"]["enum"] == list(values)
        assert document["components"]["schemas"][component]["enum"] == list(values)


# ---------------------------------------------------------------------------
# GET /api/v1/users/me/audit-log
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestListMyIdentityAuditEvents:
    async def test_unauthenticated_returns_401(self, client: AsyncClient) -> None:
        response = await client.get("/api/v1/users/me/audit-log")
        assert response.status_code == 401
        assert response.json()["code"] == "AUTH_NOT_AUTHENTICATED"

    async def test_jwt_session_returns_own_events(
        self,
        authenticated_client: AsyncClient,
    ) -> None:
        response = await authenticated_client.get("/api/v1/users/me/audit-log")
        assert response.status_code == 200

    async def test_only_returns_events_targeting_the_caller(
        self,
        authenticated_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
        identity_audit_event_factory: Callable[..., Awaitable[IdentityAuditEvent]],
    ) -> None:
        other_user = await user_factory(username="otherusertarget")
        await identity_audit_event_factory(
            event_type="user_created", target_user_id=other_user.id
        )

        response = await authenticated_client.get("/api/v1/users/me/audit-log")

        assert response.status_code == 200
        assert response.json()["meta"]["total"] == 0

    async def test_system_actor_renders_as_null(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        identity_audit_event_factory: Callable[..., Awaitable[IdentityAuditEvent]],
    ) -> None:
        await identity_audit_event_factory(
            event_type="user_created",
            user_id=None,
            target_user_id=authenticated_user.id,
        )

        response = await authenticated_client.get("/api/v1/users/me/audit-log")

        assert response.json()["data"][0]["actor"] is None

    async def test_own_action_renders_the_callers_user_reference(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        identity_audit_event_factory: Callable[..., Awaitable[IdentityAuditEvent]],
    ) -> None:
        await identity_audit_event_factory(
            event_type="api_key_created",
            user_id=authenticated_user.id,
            target_user_id=authenticated_user.id,
            new_value="key",
        )

        response = await authenticated_client.get("/api/v1/users/me/audit-log")

        assert response.json()["data"][0]["actor"] == {
            "id": str(authenticated_user.id),
            "username": authenticated_user.username,
            "full_name": authenticated_user.full_name,
            "active": True,
            "bot": False,
        }

    async def test_administrator_action_names_the_administrator_to_a_roleless_caller(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        user_factory: Callable[..., Awaitable[User]],
        user_role_factory: Callable[..., Awaitable[UserRole]],
        identity_audit_event_factory: Callable[..., Awaitable[IdentityAuditEvent]],
    ) -> None:
        """The caller holds no role, so lacks `manage_users`; the actor is
        still the administrator's complete user reference
        (`docs/features/identity/rbac.md`, Actor Identities)."""
        admin = await user_factory(
            username="fictional.admin", full_name="Fictional Admin", active=False
        )
        await user_role_factory(user_id=admin.id, role=Role.ADMIN.value)
        await identity_audit_event_factory(
            event_type="password_reset",
            user_id=admin.id,
            target_user_id=authenticated_user.id,
        )

        response = await authenticated_client.get("/api/v1/users/me/audit-log")

        assert response.status_code == 200
        assert response.json()["data"][0]["actor"] == {
            "id": str(admin.id),
            "username": "fictional.admin",
            "full_name": "Fictional Admin",
            "active": False,
            "bot": False,
        }

    async def test_null_target_events_are_excluded(
        self,
        authenticated_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
        identity_audit_event_factory: Callable[..., Awaitable[IdentityAuditEvent]],
    ) -> None:
        actor = await user_factory()
        await identity_audit_event_factory(
            event_type="role_mapping_created",
            user_id=actor.id,
            target_user_id=None,
        )

        response = await authenticated_client.get("/api/v1/users/me/audit-log")

        assert response.json()["meta"]["total"] == 0

    async def test_actor_and_target_user_query_params_are_ignored(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        identity_audit_event_factory: Callable[..., Awaitable[IdentityAuditEvent]],
    ) -> None:
        await identity_audit_event_factory(
            event_type="user_created",
            user_id=None,
            target_user_id=authenticated_user.id,
        )

        response = await authenticated_client.get(
            "/api/v1/users/me/audit-log",
            params={"actor": "system", "target_user": str(uuid4())},
        )

        assert response.status_code == 200
        assert response.json()["meta"]["total"] == 1

    async def test_repeatable_event_type_filter(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        identity_audit_event_factory: Callable[..., Awaitable[IdentityAuditEvent]],
    ) -> None:
        await identity_audit_event_factory(
            event_type="role_added", target_user_id=authenticated_user.id
        )
        await identity_audit_event_factory(
            event_type="role_removed", target_user_id=authenticated_user.id
        )
        await identity_audit_event_factory(
            event_type="username_changed", target_user_id=authenticated_user.id
        )

        response = await authenticated_client.get(
            "/api/v1/users/me/audit-log",
            params=[("event_type", "role_added"), ("event_type", "role_removed")],
        )

        assert response.json()["meta"]["total"] == 2

    async def test_all_invalid_event_types_return_empty_result(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        identity_audit_event_factory: Callable[..., Awaitable[IdentityAuditEvent]],
    ) -> None:
        await identity_audit_event_factory(
            event_type="user_created", target_user_id=authenticated_user.id
        )

        response = await authenticated_client.get(
            "/api/v1/users/me/audit-log",
            params=[("event_type", "not-a-real-type")],
        )

        assert response.status_code == 200
        assert response.json()["meta"]["total"] == 0

    async def test_page_below_one_returns_422(
        self, authenticated_client: AsyncClient
    ) -> None:
        response = await authenticated_client.get(
            "/api/v1/users/me/audit-log", params={"page": 0}
        )
        assert response.status_code == 422

    async def test_per_page_out_of_range_returns_422(
        self, authenticated_client: AsyncClient
    ) -> None:
        response = await authenticated_client.get(
            "/api/v1/users/me/audit-log", params={"per_page": 101}
        )
        assert response.status_code == 422

    async def test_malformed_date_returns_422(
        self, authenticated_client: AsyncClient
    ) -> None:
        response = await authenticated_client.get(
            "/api/v1/users/me/audit-log", params={"from_date": "not-a-date"}
        )
        assert response.status_code == 422

    async def test_inverted_date_range_returns_400(
        self, authenticated_client: AsyncClient
    ) -> None:
        response = await authenticated_client.get(
            "/api/v1/users/me/audit-log",
            params={"from_date": "2025-01-16", "to_date": "2025-01-15"},
        )
        assert response.status_code == 400
        assert response.json()["code"] == "DATE_RANGE_INVERTED"

    async def test_page_beyond_last_page_returns_empty_with_correct_total(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        identity_audit_event_factory: Callable[..., Awaitable[IdentityAuditEvent]],
    ) -> None:
        await identity_audit_event_factory(
            event_type="user_created", target_user_id=authenticated_user.id
        )

        response = await authenticated_client.get(
            "/api/v1/users/me/audit-log", params={"page": 2}
        )

        assert response.status_code == 200
        assert response.json()["data"] == []
        assert response.json()["meta"]["total"] == 1

    async def test_fixed_newest_first_ordering(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        identity_audit_event_factory: Callable[..., Awaitable[IdentityAuditEvent]],
    ) -> None:
        older = await identity_audit_event_factory(
            event_type="user_created",
            target_user_id=authenticated_user.id,
            created_at=datetime(2026, 5, 1, tzinfo=UTC),
        )
        newer = await identity_audit_event_factory(
            event_type="username_changed",
            target_user_id=authenticated_user.id,
            created_at=datetime(2026, 5, 2, tzinfo=UTC),
        )

        response = await authenticated_client.get("/api/v1/users/me/audit-log")

        ids = [item["id"] for item in response.json()["data"]]
        assert ids == [str(newer.id), str(older.id)]

    async def test_self_event_exact_item_shape(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        identity_audit_event_factory: Callable[..., Awaitable[IdentityAuditEvent]],
    ) -> None:
        await identity_audit_event_factory(
            event_type="user_created", target_user_id=authenticated_user.id
        )

        response = await authenticated_client.get("/api/v1/users/me/audit-log")

        item = response.json()["data"][0]
        assert set(item.keys()) == {
            "id",
            "event_type",
            "old_value",
            "new_value",
            "detail",
            "created_at",
            "actor",
        }


# ---------------------------------------------------------------------------
# GET /api/v1/admin/identity/audit-log
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestListIdentityAuditEvents:
    async def test_unauthenticated_returns_401(self, client: AsyncClient) -> None:
        response = await client.get("/api/v1/admin/identity/audit-log")
        assert response.status_code == 401
        assert response.json()["code"] == "AUTH_NOT_AUTHENTICATED"

    async def test_ordinary_user_returns_403(
        self, authenticated_client: AsyncClient
    ) -> None:
        response = await authenticated_client.get("/api/v1/admin/identity/audit-log")
        assert response.status_code == 403
        assert response.json()["code"] == "AUTH_INSUFFICIENT_PERMISSION"

    async def test_admin_can_list_events(self, admin_client: AsyncClient) -> None:
        response = await admin_client.get("/api/v1/admin/identity/audit-log")
        assert response.status_code == 200

    async def test_full_actor_and_target_representations(
        self,
        admin_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
        identity_audit_event_factory: Callable[..., Awaitable[IdentityAuditEvent]],
    ) -> None:
        actor = await user_factory(username="adminfullactor")
        target = await user_factory(username="adminfulltarget")
        await identity_audit_event_factory(
            event_type="role_added",
            user_id=actor.id,
            target_user_id=target.id,
            new_value="admin",
        )

        response = await admin_client.get("/api/v1/admin/identity/audit-log")

        item = response.json()["data"][0]
        assert item["actor"]["username"] == "adminfullactor"
        assert item["target_user"]["username"] == "adminfulltarget"

    async def test_system_actor_renders_as_null(
        self,
        admin_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
        identity_audit_event_factory: Callable[..., Awaitable[IdentityAuditEvent]],
    ) -> None:
        target = await user_factory()
        await identity_audit_event_factory(
            event_type="user_created", user_id=None, target_user_id=target.id
        )

        response = await admin_client.get("/api/v1/admin/identity/audit-log")

        assert response.json()["data"][0]["actor"] is None

    async def test_null_target_configuration_event_renders_as_null(
        self,
        admin_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
        identity_audit_event_factory: Callable[..., Awaitable[IdentityAuditEvent]],
    ) -> None:
        actor = await user_factory()
        await identity_audit_event_factory(
            event_type="role_mapping_created",
            user_id=actor.id,
            target_user_id=None,
        )

        response = await admin_client.get("/api/v1/admin/identity/audit-log")

        assert response.json()["data"][0]["target_user"] is None

    async def test_event_type_filter(
        self,
        admin_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
        identity_audit_event_factory: Callable[..., Awaitable[IdentityAuditEvent]],
    ) -> None:
        target = await user_factory()
        await identity_audit_event_factory(
            event_type="role_added", target_user_id=target.id
        )
        await identity_audit_event_factory(
            event_type="username_changed", target_user_id=target.id
        )

        response = await admin_client.get(
            "/api/v1/admin/identity/audit-log",
            params=[("event_type", "role_added")],
        )

        assert response.json()["meta"]["total"] == 1

    async def test_all_invalid_event_types_return_empty_result(
        self,
        admin_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
        identity_audit_event_factory: Callable[..., Awaitable[IdentityAuditEvent]],
    ) -> None:
        target = await user_factory()
        await identity_audit_event_factory(
            event_type="user_created", target_user_id=target.id
        )

        response = await admin_client.get(
            "/api/v1/admin/identity/audit-log",
            params=[("event_type", "not-a-real-type")],
        )

        assert response.status_code == 200
        assert response.json()["data"] == []
        assert response.json()["meta"]["total"] == 0

    async def test_actor_filter_by_uuid(
        self,
        admin_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
        identity_audit_event_factory: Callable[..., Awaitable[IdentityAuditEvent]],
    ) -> None:
        actor = await user_factory()
        target = await user_factory()
        await identity_audit_event_factory(
            event_type="role_added", user_id=actor.id, target_user_id=target.id
        )

        response = await admin_client.get(
            "/api/v1/admin/identity/audit-log", params={"actor": str(actor.id)}
        )

        assert response.json()["meta"]["total"] == 1

    async def test_actor_filter_by_username(
        self,
        admin_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
        identity_audit_event_factory: Callable[..., Awaitable[IdentityAuditEvent]],
    ) -> None:
        actor = await user_factory(username="filterbyusernameactor")
        target = await user_factory()
        await identity_audit_event_factory(
            event_type="role_added", user_id=actor.id, target_user_id=target.id
        )

        response = await admin_client.get(
            "/api/v1/admin/identity/audit-log",
            params={"actor": "filterbyusernameactor"},
        )

        assert response.json()["meta"]["total"] == 1

    async def test_actor_filter_system_literal(
        self,
        admin_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
        identity_audit_event_factory: Callable[..., Awaitable[IdentityAuditEvent]],
    ) -> None:
        target = await user_factory()
        await identity_audit_event_factory(
            event_type="user_created", user_id=None, target_user_id=target.id
        )
        actor = await user_factory()
        await identity_audit_event_factory(
            event_type="role_added", user_id=actor.id, target_user_id=target.id
        )

        response = await admin_client.get(
            "/api/v1/admin/identity/audit-log", params={"actor": "system"}
        )

        assert response.json()["meta"]["total"] == 1
        assert response.json()["data"][0]["actor"] is None

    async def test_target_user_filter_by_username(
        self,
        admin_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
        identity_audit_event_factory: Callable[..., Awaitable[IdentityAuditEvent]],
    ) -> None:
        target = await user_factory(username="filtertargetadmin")
        other_target = await user_factory()
        await identity_audit_event_factory(
            event_type="user_created", target_user_id=target.id
        )
        await identity_audit_event_factory(
            event_type="user_created", target_user_id=other_target.id
        )

        response = await admin_client.get(
            "/api/v1/admin/identity/audit-log",
            params={"target_user": "filtertargetadmin"},
        )

        assert response.json()["meta"]["total"] == 1

    async def test_target_user_filter_by_uuid(
        self,
        admin_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
        identity_audit_event_factory: Callable[..., Awaitable[IdentityAuditEvent]],
    ) -> None:
        target = await user_factory()
        other_target = await user_factory()
        await identity_audit_event_factory(
            event_type="user_created", target_user_id=target.id
        )
        await identity_audit_event_factory(
            event_type="user_created", target_user_id=other_target.id
        )

        response = await admin_client.get(
            "/api/v1/admin/identity/audit-log",
            params={"target_user": str(target.id)},
        )

        assert response.json()["meta"]["total"] == 1

    async def test_unknown_actor_returns_empty_result_not_404(
        self, admin_client: AsyncClient
    ) -> None:
        response = await admin_client.get(
            "/api/v1/admin/identity/audit-log", params={"actor": "no-such-actor"}
        )
        assert response.status_code == 200
        assert response.json()["meta"]["total"] == 0

    async def test_unknown_target_user_returns_empty_result_not_404(
        self, admin_client: AsyncClient
    ) -> None:
        response = await admin_client.get(
            "/api/v1/admin/identity/audit-log",
            params={"target_user": "no-such-target"},
        )
        assert response.status_code == 200
        assert response.json()["meta"]["total"] == 0

    async def test_page_below_one_returns_422(self, admin_client: AsyncClient) -> None:
        response = await admin_client.get(
            "/api/v1/admin/identity/audit-log", params={"page": 0}
        )
        assert response.status_code == 422

    async def test_per_page_out_of_range_returns_422(
        self, admin_client: AsyncClient
    ) -> None:
        response = await admin_client.get(
            "/api/v1/admin/identity/audit-log", params={"per_page": 101}
        )
        assert response.status_code == 422

    async def test_malformed_date_returns_422(self, admin_client: AsyncClient) -> None:
        response = await admin_client.get(
            "/api/v1/admin/identity/audit-log", params={"to_date": "garbage"}
        )
        assert response.status_code == 422

    async def test_inverted_date_range_returns_400(
        self, admin_client: AsyncClient
    ) -> None:
        response = await admin_client.get(
            "/api/v1/admin/identity/audit-log",
            params={"from_date": "2025-01-16", "to_date": "2025-01-15"},
        )
        assert response.status_code == 400
        assert response.json()["code"] == "DATE_RANGE_INVERTED"

    async def test_page_beyond_last_page_returns_empty_with_correct_total(
        self,
        admin_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
        identity_audit_event_factory: Callable[..., Awaitable[IdentityAuditEvent]],
    ) -> None:
        target = await user_factory()
        await identity_audit_event_factory(
            event_type="user_created", target_user_id=target.id
        )

        response = await admin_client.get(
            "/api/v1/admin/identity/audit-log", params={"page": 2}
        )

        assert response.status_code == 200
        assert response.json()["data"] == []
        assert response.json()["meta"]["total"] == 1

    async def test_fixed_newest_first_ordering(
        self,
        admin_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
        identity_audit_event_factory: Callable[..., Awaitable[IdentityAuditEvent]],
    ) -> None:
        target = await user_factory()
        older = await identity_audit_event_factory(
            event_type="user_created",
            target_user_id=target.id,
            created_at=datetime(2026, 5, 1, tzinfo=UTC),
        )
        newer = await identity_audit_event_factory(
            event_type="username_changed",
            target_user_id=target.id,
            created_at=datetime(2026, 5, 2, tzinfo=UTC),
        )

        response = await admin_client.get("/api/v1/admin/identity/audit-log")

        ids = [item["id"] for item in response.json()["data"]]
        assert ids == [str(newer.id), str(older.id)]

    async def test_admin_event_exact_item_shape(
        self,
        admin_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
        identity_audit_event_factory: Callable[..., Awaitable[IdentityAuditEvent]],
    ) -> None:
        actor = await user_factory()
        target = await user_factory()
        await identity_audit_event_factory(
            event_type="role_added",
            user_id=actor.id,
            target_user_id=target.id,
            new_value="admin",
        )

        response = await admin_client.get("/api/v1/admin/identity/audit-log")

        item = response.json()["data"][0]
        assert set(item.keys()) == {
            "id",
            "event_type",
            "old_value",
            "new_value",
            "detail",
            "created_at",
            "actor",
            "target_user",
        }

    async def test_no_mutation_methods_are_exposed(
        self, admin_client: AsyncClient
    ) -> None:
        response = await admin_client.post("/api/v1/admin/identity/audit-log")
        assert response.status_code == 405
