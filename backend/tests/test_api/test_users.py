"""End-to-end tests for the user directory, current-user, administrator
user read, and ticket-independent admin user mutation endpoints
(`backend/app/api/v1/users.py`).

See `docs/features/identity/user-management.md` (Directory API endpoints,
Admin API endpoints) and `docs/features/identity/authentication.md`
(Get Current User) for the authoritative endpoint contracts under test.
Filter/sort/pagination combination coverage and lifecycle/audit/rollback
coverage for the underlying `user_service` functions already lives in
`tests/test_services/test_user_service.py` — these tests focus on the
HTTP/route contract (status codes, envelopes, error mapping,
authentication/authorization, identifier resolution, and response field
shape) and do not duplicate that service-level coverage.
"""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import AsyncGenerator, Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
import pytest_asyncio
import redis.asyncio as redis_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api import dependencies
from app.api.dependencies import SESSION_COOKIE_NAME
from app.api.v1.users import _parse_role_filters, _parse_user_type
from app.config import settings
from app.core.enums import Role, SessionCreationReason, UserType
from app.core.exceptions import UserNotFoundError
from app.core.jwt import issue_token
from app.database import get_db
from app.main import app
from app.models.api_key import ApiKey
from app.models.identity_audit_event import IdentityAuditEvent
from app.models.session import Session
from app.models.user import User
from app.models.user_role import UserRole
from app.services import api_key_service, user_service
from app.services.session_service import create_session
from tests.support.ticket_api import UNAUTHENTICATED

# ---------------------------------------------------------------------------
# Shared helpers and fixtures
# ---------------------------------------------------------------------------


def _make_api_key_credential() -> tuple[str, str]:
    """Return `(plaintext_token, sha256_hex_digest)` for a synthetic key.

    Mirrors the identical helper in `tests/test_api/test_api_keys.py`
    and `tests/test_api/test_dependencies.py`.
    """
    token = "stl_ak_" + secrets.token_hex(16)
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return token, digest


async def _audit_events_for(
    db_session: AsyncSession, target_user_id: object
) -> list[IdentityAuditEvent]:
    """All `IdentityAuditEvent` rows targeting `target_user_id`.

    Mirrors the identical helper in `tests/test_api/test_api_keys.py`.
    """
    rows = await db_session.execute(
        select(IdentityAuditEvent).where(
            IdentityAuditEvent.target_user_id == target_user_id
        )
    )
    return list(rows.scalars().all())


@pytest.fixture
def authenticated_user_and_client(
    _authenticated_user_and_client: tuple[User, AsyncClient],
) -> tuple[User, AsyncClient]:
    """Non-underscore-prefixed alias for `conftest.py`'s
    `_authenticated_user_and_client`, mirroring
    `tests/test_api/test_api_keys.py`."""
    return _authenticated_user_and_client


@pytest_asyncio.fixture
async def admin_user_and_client(
    _authenticated_user_and_client: tuple[User, AsyncClient],
    user_role_factory: Callable[..., Awaitable[UserRole]],
) -> tuple[User, AsyncClient]:
    """Like `admin_client`, but also exposes the underlying admin
    `User` — needed to assert actor identity in audit events.
    Mirrors the identical fixture in `tests/test_api/test_api_keys.py`.
    """
    user, client = _authenticated_user_and_client
    await user_role_factory(user_id=user.id, role=Role.ADMIN.value)
    return user, client


@pytest_asyncio.fixture
async def admin_commit_client(
    db_session: AsyncSession,
    user_factory: Callable[..., Awaitable[User]],
    user_role_factory: Callable[..., Awaitable[UserRole]],
    redis_client: redis_asyncio.Redis,
) -> AsyncGenerator[tuple[User, AsyncClient]]:
    """An admin-authenticated client whose `get_db` override performs a
    real commit and executes post-commit callbacks.

    The shared `client`/`admin_client` fixtures keep one rollback-owned
    test transaction and never call `session.commit()`, so callbacks
    registered via `register_post_commit_callback()` (the password-reset
    endpoint's session-cache purge and lockout-counter clear) never run
    under them. This fixture mirrors `test_api/test_auth.py`'s
    `auth_client` to make those side effects observable. Depends on
    `redis_client` so the cleared/purged keys are visible on the
    test-isolated Redis database.
    """
    admin = await user_factory()
    await user_role_factory(user_id=admin.id, role=Role.ADMIN.value)
    created = await create_session(
        db_session,
        admin,
        SessionCreationReason.LOCAL_LOGIN,
        expected_password_hash=None,
    )
    assert created is not None

    async def _override_get_db() -> AsyncGenerator[AsyncSession]:
        try:
            yield db_session
            await db_session.commit()
        except Exception:
            await db_session.rollback()
            raise
        else:
            callbacks = db_session.info.pop("post_commit_callbacks", [])
            for callback in callbacks:
                await callback()

    app.dependency_overrides[get_db] = _override_get_db
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as commit_client:
            commit_client.cookies.set(SESSION_COOKIE_NAME, created.token)
            yield admin, commit_client
    finally:
        app.dependency_overrides.pop(get_db, None)


# ---------------------------------------------------------------------------
# Pure helpers (`app.api.v1.users`)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestParseUserType:
    def test_absent_is_valid_with_no_filter(self) -> None:
        assert _parse_user_type(None) == (True, None)

    def test_valid_local_is_accepted(self) -> None:
        assert _parse_user_type("local") == (True, UserType.LOCAL)

    def test_valid_external_is_accepted(self) -> None:
        assert _parse_user_type("external") == (True, UserType.EXTERNAL)

    def test_invalid_value_is_rejected(self) -> None:
        assert _parse_user_type("bogus") == (False, None)


@pytest.mark.unit
class TestParseRoleFilters:
    def test_absent_is_valid_with_no_filter(self) -> None:
        assert _parse_role_filters([]) == (True, [])

    def test_all_valid_values_are_kept(self) -> None:
        is_valid, roles = _parse_role_filters(["admin", "restricted_analyst"])
        assert is_valid is True
        assert set(roles) == {Role.ADMIN, Role.RESTRICTED_ANALYST}

    def test_mixed_valid_and_invalid_keeps_only_valid(self) -> None:
        is_valid, roles = _parse_role_filters(["admin", "not-a-real-role"])
        assert is_valid is True
        assert roles == [Role.ADMIN]

    def test_all_invalid_is_rejected(self) -> None:
        assert _parse_role_filters(["not-a-real-role"]) == (False, [])


# ---------------------------------------------------------------------------
# Field sets of the two audiences
# (`docs/features/identity/user-management.md`, Access Level Requirements)
# ---------------------------------------------------------------------------

_DIRECTORY_ENTRY_FIELDS = {
    "id",
    "username",
    "email",
    "full_name",
    "active",
    "bot",
    "roles",
}

_COMPLETE_PROFILE_FIELDS = {
    "id",
    "username",
    "email",
    "full_name",
    "active",
    "bot",
    "source",
    "external_id",
    "manager",
    "roles",
    "last_login_at",
    "created_at",
    "updated_at",
}


async def _profile_rich_user(
    user_factory: Callable[..., Awaitable[User]],
    user_role_factory: Callable[..., Awaitable[UserRole]],
) -> User:
    """An external user with a manager and roles from two origins: every
    field that only the complete user profile returns has a non-null
    value, so a directory leak of any of them is observable."""
    manager = await user_factory(username="richmanager")
    user = await user_factory(
        username="richprofile",
        external_id=uuid4(),
        password_hash=None,
        manager_id=manager.id,
    )
    await user_role_factory(user_id=user.id, role=Role.VULNERABILITY_ANALYST.value)
    await user_role_factory(
        user_id=user.id,
        role=Role.VULNERABILITY_ANALYST.value,
        group_name="O SUSE Security",
    )
    await user_role_factory(user_id=user.id, role=Role.ADMIN.value)
    return user


# ---------------------------------------------------------------------------
# GET /api/v1/users
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestListUsers:
    async def test_request_without_credential_returns_401(
        self, client: AsyncClient
    ) -> None:
        """See `docs/features/identity/user-management.md` (Directory API
        endpoints): every caller must be authenticated."""
        response = await client.get("/api/v1/users")
        assert response.status_code == 401
        assert response.json() == UNAUTHENTICATED

    async def test_empty_result_has_correct_envelope(
        self, authenticated_client: AsyncClient
    ) -> None:
        # The authenticated caller is itself a user; the search matches none.
        response = await authenticated_client.get(
            "/api/v1/users", params={"search": "no-such-user"}
        )
        assert response.status_code == 200
        body = response.json()
        assert body["data"] == []
        assert body["meta"] == {"total": 0, "page": 1, "per_page": 20}

    async def test_item_is_exactly_the_directory_entry(
        self,
        authenticated_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        await user_factory(username="jdoe", email="jdoe@example.com")

        response = await authenticated_client.get(
            "/api/v1/users", params={"search": "jdoe"}
        )

        item = response.json()["data"][0]
        assert set(item.keys()) == _DIRECTORY_ENTRY_FIELDS
        assert item["email"] == "jdoe@example.com"

    async def test_administrator_caller_receives_only_directory_entries(
        self,
        admin_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
        user_role_factory: Callable[..., Awaitable[UserRole]],
    ) -> None:
        """The audience is set by the endpoint, not by the caller's
        capabilities: `manage_users` reads the complete profile only
        through `GET /api/v1/admin/users`."""
        await _profile_rich_user(user_factory, user_role_factory)

        response = await admin_client.get(
            "/api/v1/users", params={"search": "richprofile"}
        )

        assert response.status_code == 200
        [item] = response.json()["data"]
        assert set(item.keys()) == _DIRECTORY_ENTRY_FIELDS

    async def test_roles_are_distinct_plain_values_in_wire_order(
        self,
        authenticated_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
        user_role_factory: Callable[..., Awaitable[UserRole]],
    ) -> None:
        """A role held from a manual and an external origin appears once,
        and the origin is never returned (`rbac.md`, Deterministic
        ordering)."""
        await _profile_rich_user(user_factory, user_role_factory)

        response = await authenticated_client.get(
            "/api/v1/users", params={"search": "richprofile"}
        )

        [item] = response.json()["data"]
        assert item["roles"] == ["admin", "vulnerability_analyst"]

    async def test_user_without_roles_has_empty_roles(
        self,
        authenticated_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        await user_factory(username="norolesuser")

        response = await authenticated_client.get(
            "/api/v1/users", params={"search": "norolesuser"}
        )

        [item] = response.json()["data"]
        assert item["roles"] == []

    async def test_search_matches_email(
        self,
        authenticated_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        await user_factory(username="mailsearch", email="unique.mailbox@example.com")

        response = await authenticated_client.get(
            "/api/v1/users", params={"search": "unique.mailbox"}
        )

        assert [item["username"] for item in response.json()["data"]] == ["mailsearch"]

    async def test_search_below_minimum_length_returns_422(
        self, authenticated_client: AsyncClient
    ) -> None:
        response = await authenticated_client.get(
            "/api/v1/users", params={"search": "j"}
        )
        assert response.status_code == 422

    async def test_invalid_active_boolean_returns_422(
        self, authenticated_client: AsyncClient
    ) -> None:
        response = await authenticated_client.get(
            "/api/v1/users", params={"active": "maybe"}
        )
        assert response.status_code == 422

    async def test_page_below_one_returns_422(
        self, authenticated_client: AsyncClient
    ) -> None:
        response = await authenticated_client.get("/api/v1/users", params={"page": 0})
        assert response.status_code == 422

    async def test_per_page_out_of_range_returns_422(
        self, authenticated_client: AsyncClient
    ) -> None:
        response = await authenticated_client.get(
            "/api/v1/users", params={"per_page": 101}
        )
        assert response.status_code == 422

    async def test_invalid_sort_by_returns_422(
        self, authenticated_client: AsyncClient
    ) -> None:
        response = await authenticated_client.get(
            "/api/v1/users", params={"sort_by": "password"}
        )
        assert response.status_code == 422

    async def test_sort_by_created_at_returns_422(
        self, authenticated_client: AsyncClient
    ) -> None:
        """The directory sorts only on fields its entry returns; creation
        time is sortable only on `GET /api/v1/admin/users`."""
        response = await authenticated_client.get(
            "/api/v1/users", params={"sort_by": "created_at"}
        )
        assert response.status_code == 422
        assert response.json()["code"] == "VALIDATION_ERROR"

    @pytest.mark.parametrize(
        ("sort_by", "sort_order", "expected"),
        [
            ("username", "asc", ["sortalpha", "sortbravo"]),
            ("email", "desc", ["sortalpha", "sortbravo"]),
            ("full_name", "asc", ["sortbravo", "sortalpha"]),
        ],
    )
    async def test_directory_sort_fields_are_applied(
        self,
        authenticated_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
        sort_by: str,
        sort_order: str,
        expected: list[str],
    ) -> None:
        await user_factory(
            username="sortalpha", email="sortz@example.com", full_name="Zed Sort"
        )
        await user_factory(
            username="sortbravo", email="sorta@example.com", full_name="Abe Sort"
        )

        response = await authenticated_client.get(
            "/api/v1/users",
            params={"search": "sort", "sort_by": sort_by, "sort_order": sort_order},
        )

        assert response.status_code == 200
        assert [item["username"] for item in response.json()["data"]] == expected

    async def test_invalid_sort_order_returns_422(
        self, authenticated_client: AsyncClient
    ) -> None:
        response = await authenticated_client.get(
            "/api/v1/users", params={"sort_order": "ascending"}
        )
        assert response.status_code == 422

    @pytest.mark.parametrize("type_value", ["local", "external", "bogus"])
    async def test_type_parameter_is_ignored(
        self,
        authenticated_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
        type_value: str,
    ) -> None:
        """The directory declares no authentication-type filter, so an
        undeclared `type` is ignored (`docs/api-spec.md`, Undeclared Query
        Parameters): it neither narrows the result nor reveals which
        accounts are local or external."""
        await user_factory(username="ignoredtypelocal")
        await user_factory(
            username="ignoredtypeexternal", external_id=uuid4(), password_hash=None
        )

        response = await authenticated_client.get(
            "/api/v1/users", params={"search": "ignoredtype", "type": type_value}
        )

        assert response.status_code == 200
        assert {item["username"] for item in response.json()["data"]} == {
            "ignoredtypelocal",
            "ignoredtypeexternal",
        }

    async def test_all_invalid_role_values_return_empty_result(
        self,
        authenticated_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        await user_factory()

        response = await authenticated_client.get(
            "/api/v1/users", params=[("role", "not-a-real-role")]
        )

        assert response.status_code == 200
        assert response.json()["meta"]["total"] == 0

    async def test_repeatable_role_filter_uses_or_semantics(
        self,
        authenticated_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
        user_role_factory: Callable[..., Awaitable[UserRole]],
    ) -> None:
        admin_user = await user_factory(username="repeatadmin")
        await user_role_factory(user_id=admin_user.id, role=Role.ADMIN.value)
        analyst_user = await user_factory(username="repeatanalyst")
        await user_role_factory(
            user_id=analyst_user.id, role=Role.VULNERABILITY_ANALYST.value
        )
        await user_factory(username="repeatnorole")

        response = await authenticated_client.get(
            "/api/v1/users",
            params=[("role", "admin"), ("role", "vulnerability_analyst")],
        )

        assert response.status_code == 200
        usernames = {item["username"] for item in response.json()["data"]}
        assert usernames == {"repeatadmin", "repeatanalyst"}

    async def test_active_role_filters_select_active_vulnerability_analysts(
        self,
        authenticated_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
        user_role_factory: Callable[..., Awaitable[UserRole]],
    ) -> None:
        """The assignment-picker query of the design note: active users
        holding `vulnerability_analyst`."""
        eligible = await user_factory(username="pickeractiveva")
        await user_role_factory(
            user_id=eligible.id, role=Role.VULNERABILITY_ANALYST.value
        )
        inactive = await user_factory(username="pickerinactiveva", active=False)
        await user_role_factory(
            user_id=inactive.id, role=Role.VULNERABILITY_ANALYST.value
        )
        await user_factory(username="pickernorole")

        response = await authenticated_client.get(
            "/api/v1/users",
            params={
                "role": "vulnerability_analyst",
                "active": "true",
                "search": "picker",
            },
        )

        assert [item["username"] for item in response.json()["data"]] == [
            "pickeractiveva"
        ]

    @pytest.mark.parametrize(
        ("has_role", "expected"),
        [("true", {"hasroledirectoryva"}), ("false", {"hasroledirectorynone"})],
    )
    async def test_has_role_filter_is_applied(
        self,
        authenticated_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
        user_role_factory: Callable[..., Awaitable[UserRole]],
        has_role: str,
        expected: set[str],
    ) -> None:
        with_role = await user_factory(username="hasroledirectoryva")
        await user_role_factory(user_id=with_role.id)
        await user_factory(username="hasroledirectorynone")

        response = await authenticated_client.get(
            "/api/v1/users",
            params={"search": "hasroledirectory", "has_role": has_role},
        )

        assert response.status_code == 200
        assert {item["username"] for item in response.json()["data"]} == expected

    async def test_page_beyond_result_set_returns_empty_data_with_correct_total(
        self,
        authenticated_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        await user_factory()

        response = await authenticated_client.get("/api/v1/users", params={"page": 2})

        assert response.status_code == 200
        body = response.json()
        assert body["data"] == []
        # The created user and the authenticated caller.
        assert body["meta"]["total"] == 2

    async def test_valid_jwt_authentication_is_accepted(
        self,
        authenticated_user_and_client: tuple[User, AsyncClient],
    ) -> None:
        """See `docs/features/identity/user-management.md` (Directory API
        endpoints): a role-less caller with a valid session reads the
        directory."""
        _user, client = authenticated_user_and_client

        response = await client.get("/api/v1/users")

        assert response.status_code == 200

    async def test_valid_api_key_authentication_is_accepted(
        self,
        client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        user = await user_factory()
        token, digest = _make_api_key_credential()
        key = await api_key_factory(user_id=user.id, key_hash=digest)
        touch_mock = AsyncMock()
        monkeypatch.setattr(dependencies._last_used_debouncer, "touch", touch_mock)

        response = await client.get(
            "/api/v1/users", headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        touch_mock.assert_awaited_once()
        assert touch_mock.await_args is not None
        assert touch_mock.await_args.args[0] == key.id

    async def test_invalid_selected_credential_returns_401(
        self, client: AsyncClient
    ) -> None:
        """A selected but rejected credential is never silently ignored
        — see `docs/api-spec.md` (Authentication and Authorization)."""
        response = await client.get(
            "/api/v1/users",
            headers={"Authorization": "Bearer not-a-real-token"},
        )

        assert response.status_code == 401
        assert response.json() == {
            "code": "AUTH_NOT_AUTHENTICATED",
            "detail": "Authentication required",
        }

    async def test_eligible_jwt_triggers_sliding_refresh(
        self,
        client: AsyncClient,
        session_factory: Callable[..., Awaitable[Session]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        """Proves browser activity on this read participates in sliding
        session refresh end-to-end — see
        `docs/features/identity/authentication.md` (Token refresh)."""
        session = await session_factory()
        old_iat = datetime.now(UTC) - timedelta(hours=settings.jwt_expiry_hours * 0.6)
        issued = issue_token(
            user_id=session.user_id,
            session_id=session.id,
            issued_at=old_iat,
            session_deadline=session.expires_at,
            jwt_expiry_hours=settings.jwt_expiry_hours,
            secret_key=settings.jwt_secret_key.get_secret_value(),
        )

        response = await client.get(
            "/api/v1/users", headers={"Authorization": f"Bearer {issued.token}"}
        )

        assert response.status_code == 200
        assert "set-cookie" in response.headers
        assert response.headers["set-cookie"].startswith(f"{SESSION_COOKIE_NAME}=")


# ---------------------------------------------------------------------------
# GET /api/v1/users/{user}
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestGetUser:
    async def test_request_without_credential_returns_401(
        self,
        client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        """See `docs/features/identity/user-management.md` (Directory API
        endpoints): every caller must be authenticated."""
        user = await user_factory(username="nocredentialtarget")

        response = await client.get(f"/api/v1/users/{user.username}")

        assert response.status_code == 401
        assert response.json() == UNAUTHENTICATED

    async def test_resolves_by_uuid(
        self,
        authenticated_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        user = await user_factory(username="byuuidtest")

        response = await authenticated_client.get(f"/api/v1/users/{user.id}")

        assert response.status_code == 200
        assert response.json()["data"]["username"] == "byuuidtest"

    async def test_bot_account_entry_carries_the_marker(
        self,
        authenticated_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        bot = await user_factory(username="scannerentry", bot=True)

        response = await authenticated_client.get(f"/api/v1/users/{bot.id}")

        assert response.status_code == 200
        assert response.json()["data"]["bot"] is True

    async def test_resolves_by_exact_username(
        self,
        authenticated_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        user = await user_factory(username="byusernametest")

        response = await authenticated_client.get(f"/api/v1/users/{user.username}")

        assert response.status_code == 200
        assert response.json()["data"]["id"] == str(user.id)

    async def test_missing_uuid_returns_404_user_not_found(
        self, authenticated_client: AsyncClient
    ) -> None:
        response = await authenticated_client.get(f"/api/v1/users/{uuid4()}")
        assert response.status_code == 404
        assert response.json()["code"] == "USER_NOT_FOUND"

    async def test_missing_username_returns_404_user_not_found(
        self, authenticated_client: AsyncClient
    ) -> None:
        response = await authenticated_client.get("/api/v1/users/no-such-user")
        assert response.status_code == 404
        assert response.json()["code"] == "USER_NOT_FOUND"

    async def test_returns_exactly_the_directory_entry(
        self,
        authenticated_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
        user_role_factory: Callable[..., Awaitable[UserRole]],
    ) -> None:
        user = await _profile_rich_user(user_factory, user_role_factory)

        response = await authenticated_client.get(f"/api/v1/users/{user.username}")

        assert response.status_code == 200
        assert response.json()["data"] == {
            "id": str(user.id),
            "username": "richprofile",
            "email": user.email,
            "full_name": None,
            "active": True,
            "bot": False,
            "roles": ["admin", "vulnerability_analyst"],
        }

    async def test_administrator_caller_receives_the_directory_entry(
        self,
        admin_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
        user_role_factory: Callable[..., Awaitable[UserRole]],
    ) -> None:
        user = await _profile_rich_user(user_factory, user_role_factory)

        response = await admin_client.get(f"/api/v1/users/{user.id}")

        assert response.status_code == 200
        assert set(response.json()["data"].keys()) == _DIRECTORY_ENTRY_FIELDS

    async def test_full_name_null_is_returned_verbatim(
        self,
        authenticated_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        user = await user_factory(username="nofullname", full_name=None)

        response = await authenticated_client.get(f"/api/v1/users/{user.username}")

        assert response.json()["data"]["full_name"] is None

    async def test_inactive_user_is_resolved(
        self,
        authenticated_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        user = await user_factory(username="inactivedirectory", active=False)

        response = await authenticated_client.get(f"/api/v1/users/{user.username}")

        assert response.status_code == 200
        assert response.json()["data"]["active"] is False

    async def test_valid_jwt_authentication_is_accepted(
        self,
        authenticated_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        """See `docs/features/identity/user-management.md` (Directory API
        endpoints): a role-less caller with a valid session reads another
        user's directory entry."""
        _actor, client = authenticated_user_and_client
        target = await user_factory(username="jwttargetuser")

        response = await client.get(f"/api/v1/users/{target.username}")

        assert response.status_code == 200

    async def test_valid_api_key_authentication_is_accepted(
        self,
        client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        actor = await user_factory()
        target = await user_factory(username="apikeytargetuser")
        token, digest = _make_api_key_credential()
        key = await api_key_factory(user_id=actor.id, key_hash=digest)
        touch_mock = AsyncMock()
        monkeypatch.setattr(dependencies._last_used_debouncer, "touch", touch_mock)

        response = await client.get(
            f"/api/v1/users/{target.username}",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200
        touch_mock.assert_awaited_once()
        assert touch_mock.await_args is not None
        assert touch_mock.await_args.args[0] == key.id

    async def test_invalid_selected_credential_returns_401(
        self,
        client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        """A selected but rejected credential is never silently ignored
        — see `docs/api-spec.md` (Authentication and Authorization)."""
        target = await user_factory(username="rejectedcredentialtarget")

        response = await client.get(
            f"/api/v1/users/{target.username}",
            headers={"Authorization": "Bearer not-a-real-token"},
        )

        assert response.status_code == 401
        assert response.json() == {
            "code": "AUTH_NOT_AUTHENTICATED",
            "detail": "Authentication required",
        }

    async def test_eligible_jwt_triggers_sliding_refresh(
        self,
        client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
        session_factory: Callable[..., Awaitable[Session]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        """Proves browser activity on this read participates in sliding
        session refresh end-to-end — see
        `docs/features/identity/authentication.md` (Token refresh)."""
        target = await user_factory(username="refreshtargetuser")
        session = await session_factory()
        old_iat = datetime.now(UTC) - timedelta(hours=settings.jwt_expiry_hours * 0.6)
        issued = issue_token(
            user_id=session.user_id,
            session_id=session.id,
            issued_at=old_iat,
            session_deadline=session.expires_at,
            jwt_expiry_hours=settings.jwt_expiry_hours,
            secret_key=settings.jwt_secret_key.get_secret_value(),
        )

        response = await client.get(
            f"/api/v1/users/{target.username}",
            headers={"Authorization": f"Bearer {issued.token}"},
        )

        assert response.status_code == 200
        assert "set-cookie" in response.headers
        assert response.headers["set-cookie"].startswith(f"{SESSION_COOKIE_NAME}=")


# ---------------------------------------------------------------------------
# GET /api/v1/admin/users
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestListUsersAdmin:
    async def test_request_without_credential_returns_401(
        self, client: AsyncClient
    ) -> None:
        response = await client.get("/api/v1/admin/users")
        assert response.status_code == 401
        assert response.json() == UNAUTHENTICATED

    async def test_role_less_caller_returns_403(
        self, authenticated_client: AsyncClient
    ) -> None:
        response = await authenticated_client.get("/api/v1/admin/users")
        assert response.status_code == 403
        assert response.json() == {
            "code": "AUTH_INSUFFICIENT_PERMISSION",
            "detail": "Insufficient permissions",
        }

    @pytest.mark.parametrize(
        "role", [Role.VULNERABILITY_ANALYST, Role.RESTRICTED_ANALYST]
    )
    async def test_caller_without_manage_users_returns_403(
        self,
        authenticated_user_and_client: tuple[User, AsyncClient],
        user_role_factory: Callable[..., Awaitable[UserRole]],
        role: Role,
    ) -> None:
        user, client = authenticated_user_and_client
        await user_role_factory(user_id=user.id, role=role.value)

        response = await client.get("/api/v1/admin/users")

        assert response.status_code == 403
        assert response.json()["code"] == "AUTH_INSUFFICIENT_PERMISSION"

    async def test_item_is_the_complete_user_profile(
        self,
        admin_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
        user_role_factory: Callable[..., Awaitable[UserRole]],
    ) -> None:
        user = await _profile_rich_user(user_factory, user_role_factory)

        response = await admin_client.get(
            "/api/v1/admin/users", params={"search": "richprofile"}
        )

        assert response.status_code == 200
        [item] = response.json()["data"]
        assert set(item.keys()) == _COMPLETE_PROFILE_FIELDS
        assert item["source"] == "external"
        assert item["external_id"] == str(user.external_id)
        assert item["manager"]["username"] == "richmanager"
        assert [(role["role"], role["group_name"]) for role in item["roles"]] == [
            ("admin", "_manual"),
            ("vulnerability_analyst", "O SUSE Security"),
            ("vulnerability_analyst", "_manual"),
        ]
        assert item["last_login_at"] is None

    async def test_datetimes_end_with_z(
        self,
        admin_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        await user_factory(username="zsuffixuser")

        response = await admin_client.get(
            "/api/v1/admin/users", params={"search": "zsuffixuser"}
        )

        [item] = response.json()["data"]
        assert item["created_at"].endswith("Z")
        assert item["updated_at"].endswith("Z")

    @pytest.mark.parametrize(
        ("type_value", "expected"),
        [
            ("local", {"adminlisttypelocal"}),
            ("external", {"adminlisttypeexternal"}),
            ("bogus", set()),
        ],
    )
    async def test_type_filter_is_applied(
        self,
        admin_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
        type_value: str,
        expected: set[str],
    ) -> None:
        """An invalid single-value enum filter yields an empty result
        (`docs/api-spec.md`, Enum Filter Validation)."""
        await user_factory(username="adminlisttypelocal")
        await user_factory(
            username="adminlisttypeexternal", external_id=uuid4(), password_hash=None
        )

        response = await admin_client.get(
            "/api/v1/admin/users",
            params={"search": "adminlisttype", "type": type_value},
        )

        assert response.status_code == 200
        assert {item["username"] for item in response.json()["data"]} == expected

    async def test_sort_by_created_at_is_accepted(
        self,
        admin_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        first = await user_factory(username="createdorderfirst")
        second = await user_factory(username="createdordersecond")

        response = await admin_client.get(
            "/api/v1/admin/users",
            params={
                "search": "createdorder",
                "sort_by": "created_at",
                "sort_order": "desc",
            },
        )

        assert response.status_code == 200
        assert [item["id"] for item in response.json()["data"]] == [
            str(second.id),
            str(first.id),
        ]

    async def test_invalid_sort_by_returns_422(self, admin_client: AsyncClient) -> None:
        response = await admin_client.get(
            "/api/v1/admin/users", params={"sort_by": "last_login_at"}
        )
        assert response.status_code == 422
        assert response.json()["code"] == "VALIDATION_ERROR"

    async def test_search_below_minimum_length_returns_422(
        self, admin_client: AsyncClient
    ) -> None:
        response = await admin_client.get("/api/v1/admin/users", params={"search": "j"})
        assert response.status_code == 422
        assert response.json()["code"] == "VALIDATION_ERROR"

    @pytest.mark.parametrize(
        ("has_role", "expected"),
        [("true", {"hasroleadminva"}), ("false", {"hasroleadminnone"})],
    )
    async def test_has_role_filter_is_applied(
        self,
        admin_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
        user_role_factory: Callable[..., Awaitable[UserRole]],
        has_role: str,
        expected: set[str],
    ) -> None:
        with_role = await user_factory(username="hasroleadminva")
        await user_role_factory(user_id=with_role.id)
        await user_factory(username="hasroleadminnone")

        response = await admin_client.get(
            "/api/v1/admin/users",
            params={"search": "hasroleadmin", "has_role": has_role},
        )

        assert response.status_code == 200
        assert {item["username"] for item in response.json()["data"]} == expected

    async def test_all_invalid_role_values_return_empty_result(
        self, admin_client: AsyncClient
    ) -> None:
        response = await admin_client.get(
            "/api/v1/admin/users", params=[("role", "not-a-real-role")]
        )

        assert response.status_code == 200
        assert response.json()["meta"]["total"] == 0

    async def test_role_and_active_filters_combine_with_and(
        self,
        admin_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
        user_role_factory: Callable[..., Awaitable[UserRole]],
    ) -> None:
        active_admin = await user_factory(username="andfilteractive")
        await user_role_factory(user_id=active_admin.id, role=Role.ADMIN.value)
        inactive_admin = await user_factory(username="andfilterinactive", active=False)
        await user_role_factory(user_id=inactive_admin.id, role=Role.ADMIN.value)

        response = await admin_client.get(
            "/api/v1/admin/users",
            params={"search": "andfilter", "role": "admin", "active": "false"},
        )

        assert [item["username"] for item in response.json()["data"]] == [
            "andfilterinactive"
        ]

    async def test_manage_users_api_key_is_accepted(
        self,
        client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
        user_role_factory: Callable[..., Awaitable[UserRole]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Unlike Create User (Admin), the administrator reads are not
        restricted to JWT sessions."""
        admin = await user_factory()
        await user_role_factory(user_id=admin.id, role=Role.ADMIN.value)
        token, digest = _make_api_key_credential()
        await api_key_factory(user_id=admin.id, key_hash=digest)
        monkeypatch.setattr(dependencies._last_used_debouncer, "touch", AsyncMock())

        response = await client.get(
            "/api/v1/admin/users", headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200


# ---------------------------------------------------------------------------
# GET /api/v1/admin/users/{user}
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestGetUserAdmin:
    async def test_request_without_credential_returns_401(
        self,
        client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        user = await user_factory(username="adminnocredential")

        response = await client.get(f"/api/v1/admin/users/{user.username}")

        assert response.status_code == 401
        assert response.json() == UNAUTHENTICATED

    async def test_caller_without_manage_users_returns_403(
        self,
        authenticated_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
        user_role_factory: Callable[..., Awaitable[UserRole]],
    ) -> None:
        actor, client = authenticated_user_and_client
        await user_role_factory(user_id=actor.id, role=Role.VULNERABILITY_ANALYST.value)
        target = await user_factory(username="adminforbiddentarget")

        response = await client.get(f"/api/v1/admin/users/{target.username}")

        assert response.status_code == 403
        assert response.json()["code"] == "AUTH_INSUFFICIENT_PERMISSION"

    async def test_missing_user_without_manage_users_returns_403(
        self, authenticated_client: AsyncClient
    ) -> None:
        """The capability check precedes user resolution, so a caller
        without `manage_users` cannot probe for existence."""
        response = await authenticated_client.get("/api/v1/admin/users/no-such-user")
        assert response.status_code == 403

    async def test_resolves_by_uuid(
        self,
        admin_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        user = await user_factory(username="adminbyuuid")

        response = await admin_client.get(f"/api/v1/admin/users/{user.id}")

        assert response.status_code == 200
        assert response.json()["data"]["username"] == "adminbyuuid"

    async def test_resolves_by_exact_username(
        self,
        admin_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        user = await user_factory(username="adminbyusername")

        response = await admin_client.get(f"/api/v1/admin/users/{user.username}")

        assert response.status_code == 200
        assert response.json()["data"]["id"] == str(user.id)

    async def test_missing_uuid_returns_404_user_not_found(
        self, admin_client: AsyncClient
    ) -> None:
        response = await admin_client.get(f"/api/v1/admin/users/{uuid4()}")
        assert response.status_code == 404
        assert response.json()["code"] == "USER_NOT_FOUND"

    async def test_missing_username_returns_404_user_not_found(
        self, admin_client: AsyncClient
    ) -> None:
        response = await admin_client.get("/api/v1/admin/users/no-such-user")
        assert response.status_code == 404
        assert response.json()["code"] == "USER_NOT_FOUND"

    async def test_manager_and_roles_are_fully_rendered(
        self,
        admin_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
        user_role_factory: Callable[..., Awaitable[UserRole]],
    ) -> None:
        manager = await user_factory(username="managerforprofile")
        user = await user_factory(username="profiletarget", manager_id=manager.id)
        await user_role_factory(user_id=user.id, role=Role.ADMIN.value)

        response = await admin_client.get(f"/api/v1/admin/users/{user.username}")

        data = response.json()["data"]
        assert set(data.keys()) == _COMPLETE_PROFILE_FIELDS
        assert data["manager"] == {
            "id": str(manager.id),
            "username": "managerforprofile",
            "full_name": manager.full_name,
            "active": True,
            "bot": False,
            "email": manager.email,
        }
        assert data["roles"] == [
            {
                "role": "admin",
                "group_name": "_manual",
                "assigned_by": None,
                "created_at": data["roles"][0]["created_at"],
            }
        ]

    async def test_bot_marker_of_the_user_and_its_manager_are_current(
        self,
        admin_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        manager = await user_factory(username="botmanager", bot=True)
        user = await user_factory(username="botprofile", manager_id=manager.id)

        response = await admin_client.get(f"/api/v1/admin/users/{user.username}")

        data = response.json()["data"]
        assert data["bot"] is False
        assert data["manager"]["bot"] is True

    async def test_external_user_has_external_source(
        self,
        admin_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        external_id = uuid4()
        user = await user_factory(
            username="externaltest", external_id=external_id, password_hash=None
        )

        response = await admin_client.get(f"/api/v1/admin/users/{user.username}")

        data = response.json()["data"]
        assert data["source"] == "external"
        assert data["external_id"] == str(external_id)

    async def test_local_user_has_local_source(
        self,
        admin_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        user = await user_factory(username="localsourcetest")

        response = await admin_client.get(f"/api/v1/admin/users/{user.username}")

        data = response.json()["data"]
        assert data["source"] == "local"
        assert data["external_id"] is None

    async def test_last_login_at_is_null_before_the_first_login(
        self,
        admin_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        user = await user_factory(username="neverloggedin")

        response = await admin_client.get(f"/api/v1/admin/users/{user.username}")

        assert response.json()["data"]["last_login_at"] is None

    async def test_last_login_at_after_a_login_returns_the_login_time(
        self,
        admin_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        """Every Session creation records `last_login_at`
        (`docs/features/identity/authentication.md`, `last_login_at`
        field); the complete profile returns it."""
        user = await user_factory(username="loggedinonce")
        created = await create_session(
            db_session,
            user,
            SessionCreationReason.LOCAL_LOGIN,
            expected_password_hash=None,
        )
        assert created is not None
        assert user.last_login_at is not None

        response = await admin_client.get(f"/api/v1/admin/users/{user.username}")

        returned = response.json()["data"]["last_login_at"]
        assert returned.endswith("Z")
        assert datetime.fromisoformat(returned) == user.last_login_at

    async def test_manage_users_api_key_is_accepted(
        self,
        client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
        user_role_factory: Callable[..., Awaitable[UserRole]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        admin = await user_factory()
        await user_role_factory(user_id=admin.id, role=Role.ADMIN.value)
        target = await user_factory(username="adminapikeytarget")
        token, digest = _make_api_key_credential()
        await api_key_factory(user_id=admin.id, key_hash=digest)
        monkeypatch.setattr(dependencies._last_used_debouncer, "touch", AsyncMock())

        response = await client.get(
            f"/api/v1/admin/users/{target.username}",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200
        assert response.json()["data"]["username"] == "adminapikeytarget"


# ---------------------------------------------------------------------------
# GET /api/v1/users/me
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestGetCurrentUserProfile:
    async def test_unauthenticated_returns_401(self, client: AsyncClient) -> None:
        response = await client.get("/api/v1/users/me")
        assert response.status_code == 401
        assert response.json()["code"] == "AUTH_NOT_AUTHENTICATED"

    async def test_jwt_session_returns_own_profile(
        self, authenticated_user_and_client: tuple[User, AsyncClient]
    ) -> None:
        user, client = authenticated_user_and_client

        response = await client.get("/api/v1/users/me")

        assert response.status_code == 200
        data = response.json()["data"]
        assert data["id"] == str(user.id)
        assert data["username"] == user.username

    async def test_exact_concise_schema(
        self, authenticated_user_and_client: tuple[User, AsyncClient]
    ) -> None:
        _user, client = authenticated_user_and_client

        response = await client.get("/api/v1/users/me")

        data = response.json()["data"]
        assert set(data.keys()) == {
            "id",
            "username",
            "email",
            "full_name",
            "roles",
            "active",
            "bot",
        }

    async def test_bot_account_reads_its_own_marker(
        self,
        authenticated_user_and_client: tuple[User, AsyncClient],
        db_session: AsyncSession,
    ) -> None:
        user, client = authenticated_user_and_client
        user.bot = True
        await db_session.flush()

        response = await client.get("/api/v1/users/me")

        assert response.status_code == 200
        assert response.json()["data"]["bot"] is True

    async def test_roles_are_distinct_and_wire_sorted(
        self,
        authenticated_user_and_client: tuple[User, AsyncClient],
        user_role_factory: Callable[..., Awaitable[UserRole]],
    ) -> None:
        user, client = authenticated_user_and_client
        await user_role_factory(
            user_id=user.id, role=Role.VULNERABILITY_ANALYST.value, group_name="_manual"
        )
        await user_role_factory(
            user_id=user.id,
            role=Role.VULNERABILITY_ANALYST.value,
            group_name="O SUSE Security",
        )
        await user_role_factory(user_id=user.id, role=Role.ADMIN.value)

        response = await client.get("/api/v1/users/me")

        assert response.json()["data"]["roles"] == ["admin", "vulnerability_analyst"]

    async def test_api_key_authentication_is_accepted(
        self,
        client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        user = await user_factory(username="apikeyprofile")
        token, digest = _make_api_key_credential()
        await api_key_factory(user_id=user.id, key_hash=digest)
        monkeypatch.setattr(
            api_key_service, "update_last_used_at", AsyncMock(return_value=True)
        )

        response = await client.get(
            "/api/v1/users/me", headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        assert response.json()["data"]["username"] == "apikeyprofile"

    async def test_has_no_full_profile_only_fields(
        self, authenticated_user_and_client: tuple[User, AsyncClient]
    ) -> None:
        _user, client = authenticated_user_and_client

        response = await client.get("/api/v1/users/me")

        data = response.json()["data"]
        assert "source" not in data
        assert "external_id" not in data
        assert "manager" not in data

    async def test_static_route_takes_precedence_over_dynamic_username_route(
        self,
        client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        """The username `me` is reserved, so a user literally named `me`
        can only exist through a direct insert that bypasses the service;
        even then it must not capture the static `/users/me` route, which
        still wins."""
        await user_factory(username="me")

        response = await client.get("/api/v1/users/me")

        assert response.status_code == 401


# ---------------------------------------------------------------------------
# POST /api/v1/admin/users
# ---------------------------------------------------------------------------


def _create_payload(**overrides: object) -> dict[str, object]:
    defaults: dict[str, object] = {
        "username": "newadminuser",
        "email": "newadminuser@example.com",
        "full_name": "New Admin User",
        "password": "a-fictional-password-value",
    }
    defaults.update(overrides)
    return defaults


@pytest.mark.e2e
class TestCreateUserAdmin:
    async def test_unauthenticated_returns_401(self, client: AsyncClient) -> None:
        response = await client.post("/api/v1/admin/users", json=_create_payload())
        assert response.status_code == 401
        assert response.json()["code"] == "AUTH_NOT_AUTHENTICATED"

    async def test_ordinary_user_returns_403(
        self, authenticated_client: AsyncClient
    ) -> None:
        response = await authenticated_client.post(
            "/api/v1/admin/users", json=_create_payload()
        )
        assert response.status_code == 403
        assert response.json()["code"] == "AUTH_INSUFFICIENT_PERMISSION"

    async def test_admin_api_key_returns_403_session_required(
        self,
        client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
        user_role_factory: Callable[..., Awaitable[UserRole]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """This endpoint mints a new credential (a password), so it must
        not be reachable with an API key even for an admin — see
        `docs/features/identity/authentication.md` (Session-Only
        Authentication Dependency)."""
        admin = await user_factory(username="adminwithapikey")
        await user_role_factory(user_id=admin.id, role=Role.ADMIN.value)
        token, digest = _make_api_key_credential()
        await api_key_factory(user_id=admin.id, key_hash=digest)
        monkeypatch.setattr(
            api_key_service, "update_last_used_at", AsyncMock(return_value=True)
        )

        response = await client.post(
            "/api/v1/admin/users",
            json=_create_payload(),
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 403
        assert response.json()["code"] == "AUTH_SESSION_REQUIRED"

    async def test_creates_local_user_and_returns_201(
        self, admin_user_and_client: tuple[User, AsyncClient]
    ) -> None:
        _admin, client = admin_user_and_client

        response = await client.post(
            "/api/v1/admin/users",
            json=_create_payload(
                username="janedoe", email="Jane.Doe@Example.com  ".strip()
            ),
        )

        assert response.status_code == 201
        data = response.json()["data"]
        assert data["username"] == "janedoe"
        assert data["active"] is True
        assert data["source"] == "local"
        assert "password" not in data
        assert "password_hash" not in data

    async def test_omitted_full_name_and_roles_are_accepted(
        self, admin_user_and_client: tuple[User, AsyncClient]
    ) -> None:
        _admin, client = admin_user_and_client
        payload = _create_payload(username="minimalcreate", email="minimal@example.com")
        del payload["full_name"]

        response = await client.post("/api/v1/admin/users", json=payload)

        assert response.status_code == 201
        data = response.json()["data"]
        assert data["full_name"] is None
        assert data["roles"] == []

    async def test_creates_a_bot_account_without_a_bot_changed_event(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        db_session: AsyncSession,
    ) -> None:
        _admin, client = admin_user_and_client

        response = await client.post(
            "/api/v1/admin/users",
            json=_create_payload(
                username="scanner", email="scanner@example.com", bot=True
            ),
        )

        assert response.status_code == 201
        data = response.json()["data"]
        assert data["bot"] is True
        events = await _audit_events_for(db_session, data["id"])
        assert [event.event_type for event in events] == ["user_created"]

    async def test_omitted_bot_creates_a_person_account(
        self, admin_user_and_client: tuple[User, AsyncClient]
    ) -> None:
        _admin, client = admin_user_and_client

        response = await client.post(
            "/api/v1/admin/users",
            json=_create_payload(username="person", email="person@example.com"),
        )

        assert response.status_code == 201
        assert response.json()["data"]["bot"] is False

    @pytest.mark.parametrize("value", [None, "true", 1], ids=["null", "string", "int"])
    async def test_null_or_non_boolean_bot_returns_422_without_a_user(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        db_session: AsyncSession,
        value: object,
    ) -> None:
        _admin, client = admin_user_and_client

        response = await client.post(
            "/api/v1/admin/users",
            json=_create_payload(
                username="invalidbot", email="invalidbot@example.com", bot=value
            ),
        )

        assert response.status_code == 422
        assert response.json()["code"] == "VALIDATION_ERROR"
        created = await db_session.scalar(
            select(User).where(User.username == "invalidbot")
        )
        assert created is None

    async def test_assigns_initial_manual_roles(
        self, admin_user_and_client: tuple[User, AsyncClient]
    ) -> None:
        _admin, client = admin_user_and_client

        response = await client.post(
            "/api/v1/admin/users",
            json=_create_payload(
                username="withroles",
                email="withroles@example.com",
                roles=["admin", "vulnerability_analyst"],
            ),
        )

        assert response.status_code == 201
        roles = {entry["role"] for entry in response.json()["data"]["roles"]}
        assert roles == {"admin", "vulnerability_analyst"}
        assert all(
            entry["group_name"] == "_manual"
            for entry in response.json()["data"]["roles"]
        )

    async def test_creates_user_created_and_role_added_audit_events(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        db_session: AsyncSession,
    ) -> None:
        admin, client = admin_user_and_client

        response = await client.post(
            "/api/v1/admin/users",
            json=_create_payload(
                username="audituser",
                email="audituser@example.com",
                roles=["admin"],
            ),
        )

        created_id = response.json()["data"]["id"]
        events = await _audit_events_for(db_session, created_id)
        event_types = {event.event_type for event in events}
        assert event_types == {"user_created", "role_added"}
        for event in events:
            assert event.user_id == admin.id

    async def test_duplicate_username_returns_409(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        _admin, client = admin_user_and_client
        await user_factory(username="dupeusername")

        response = await client.post(
            "/api/v1/admin/users",
            json=_create_payload(
                username="dupeusername", email="uniqueemail@example.com"
            ),
        )

        assert response.status_code == 409
        assert response.json()["code"] == "USER_ALREADY_EXISTS"

    async def test_duplicate_email_returns_409(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        _admin, client = admin_user_and_client
        await user_factory(email="dupeemail@example.com")

        response = await client.post(
            "/api/v1/admin/users",
            json=_create_payload(
                username="uniqueusername", email="dupeemail@example.com"
            ),
        )

        assert response.status_code == 409
        assert response.json()["code"] == "USER_ALREADY_EXISTS"

    async def test_password_outside_policy_returns_domain_422(
        self, admin_user_and_client: tuple[User, AsyncClient]
    ) -> None:
        _admin, client = admin_user_and_client

        response = await client.post(
            "/api/v1/admin/users", json=_create_payload(password="short")
        )

        assert response.status_code == 422
        assert response.json()["code"] == "USER_PASSWORD_POLICY_VIOLATION"

    async def test_missing_password_returns_generic_validation_error(
        self, admin_user_and_client: tuple[User, AsyncClient]
    ) -> None:
        _admin, client = admin_user_and_client
        payload = _create_payload()
        del payload["password"]

        response = await client.post("/api/v1/admin/users", json=payload)

        assert response.status_code == 422
        assert response.json()["code"] == "VALIDATION_ERROR"

    async def test_explicit_null_username_returns_422(
        self, admin_user_and_client: tuple[User, AsyncClient]
    ) -> None:
        _admin, client = admin_user_and_client

        response = await client.post(
            "/api/v1/admin/users", json=_create_payload(username=None)
        )

        assert response.status_code == 422
        assert response.json()["code"] == "VALIDATION_ERROR"

    async def test_malformed_username_returns_422(
        self, admin_user_and_client: tuple[User, AsyncClient]
    ) -> None:
        _admin, client = admin_user_and_client

        response = await client.post(
            "/api/v1/admin/users", json=_create_payload(username="1-bad-start")
        )

        assert response.status_code == 422
        assert response.json()["code"] == "VALIDATION_ERROR"

    async def test_reserved_username_returns_422(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        db_session: AsyncSession,
    ) -> None:
        _admin, client = admin_user_and_client

        response = await client.post(
            "/api/v1/admin/users",
            json=_create_payload(username="me", email="reserved-me@example.com"),
        )

        assert response.status_code == 422
        assert response.json()["code"] == "VALIDATION_ERROR"
        rows = await db_session.execute(
            select(User).where(User.email == "reserved-me@example.com")
        )
        assert rows.scalars().all() == []

    async def test_malformed_email_returns_422(
        self, admin_user_and_client: tuple[User, AsyncClient]
    ) -> None:
        _admin, client = admin_user_and_client

        response = await client.post(
            "/api/v1/admin/users", json=_create_payload(email="not-an-email")
        )

        assert response.status_code == 422
        assert response.json()["code"] == "VALIDATION_ERROR"

    async def test_unknown_role_returns_422(
        self, admin_user_and_client: tuple[User, AsyncClient]
    ) -> None:
        _admin, client = admin_user_and_client

        response = await client.post(
            "/api/v1/admin/users",
            json=_create_payload(roles=["not-a-real-role"]),
        )

        assert response.status_code == 422
        assert response.json()["code"] == "VALIDATION_ERROR"

    async def test_duplicate_role_values_returns_422(
        self, admin_user_and_client: tuple[User, AsyncClient]
    ) -> None:
        _admin, client = admin_user_and_client

        response = await client.post(
            "/api/v1/admin/users",
            json=_create_payload(roles=["admin", "admin"]),
        )

        assert response.status_code == 422
        assert response.json()["code"] == "VALIDATION_ERROR"


# ---------------------------------------------------------------------------
# PATCH /api/v1/admin/users/{user}
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestUpdateUserAdmin:
    async def test_unauthenticated_returns_401(self, client: AsyncClient) -> None:
        response = await client.patch(
            "/api/v1/admin/users/someuser", json={"email": "new@example.com"}
        )
        assert response.status_code == 401

    async def test_ordinary_user_returns_403(
        self, authenticated_client: AsyncClient
    ) -> None:
        response = await authenticated_client.patch(
            "/api/v1/admin/users/someuser", json={"email": "new@example.com"}
        )
        assert response.status_code == 403

    async def test_missing_uuid_returns_404(
        self, admin_user_and_client: tuple[User, AsyncClient]
    ) -> None:
        _admin, client = admin_user_and_client
        response = await client.patch(
            f"/api/v1/admin/users/{uuid4()}", json={"email": "new@example.com"}
        )
        assert response.status_code == 404
        assert response.json()["code"] == "USER_NOT_FOUND"

    async def test_missing_username_returns_404(
        self, admin_user_and_client: tuple[User, AsyncClient]
    ) -> None:
        _admin, client = admin_user_and_client
        response = await client.patch(
            "/api/v1/admin/users/no-such-user", json={"email": "new@example.com"}
        )
        assert response.status_code == 404
        assert response.json()["code"] == "USER_NOT_FOUND"

    async def test_resolves_by_uuid_and_username_to_same_target(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        _admin, client = admin_user_and_client
        target = await user_factory(username="patchtargetuser")

        by_uuid = await client.patch(
            f"/api/v1/admin/users/{target.id}",
            json={"full_name": "Updated By UUID"},
        )
        by_username = await client.patch(
            f"/api/v1/admin/users/{target.username}",
            json={"full_name": "Updated By Username"},
        )

        assert by_uuid.status_code == 200
        assert by_username.status_code == 200
        assert by_uuid.json()["data"]["id"] == by_username.json()["data"]["id"]

    async def test_empty_body_returns_422(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        _admin, client = admin_user_and_client
        target = await user_factory(username="emptybodytarget")

        response = await client.patch(f"/api/v1/admin/users/{target.id}", json={})

        assert response.status_code == 422
        assert response.json()["code"] == "VALIDATION_ERROR"

    async def test_explicit_null_email_returns_422(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        _admin, client = admin_user_and_client
        target = await user_factory(username="nullemailtarget")

        response = await client.patch(
            f"/api/v1/admin/users/{target.id}", json={"email": None}
        )

        assert response.status_code == 422
        body = response.json()
        assert body["code"] == "VALIDATION_ERROR"
        assert [error["loc"] for error in body["errors"]] == [["body", "email"]]

    async def test_explicit_null_full_name_clears_it(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        _admin, client = admin_user_and_client
        target = await user_factory(
            username="clearfullnametarget", full_name="Old Name"
        )

        response = await client.patch(
            f"/api/v1/admin/users/{target.id}", json={"full_name": None}
        )

        assert response.status_code == 200
        assert response.json()["data"]["full_name"] is None

    async def test_updates_email_and_creates_audit_event(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
        db_session: AsyncSession,
    ) -> None:
        admin, client = admin_user_and_client
        target = await user_factory(username="emailupdatetarget")

        response = await client.patch(
            f"/api/v1/admin/users/{target.id}",
            json={"email": "Updated.Email@Example.com"},
        )

        assert response.status_code == 200
        assert response.json()["data"]["email"] == "updated.email@example.com"
        events = await _audit_events_for(db_session, target.id)
        assert len(events) == 1
        assert events[0].event_type == "email_changed"
        assert events[0].user_id == admin.id

    async def test_updates_both_email_and_full_name_together(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
        db_session: AsyncSession,
    ) -> None:
        """Both provided fields reach the single `update_user()` call —
        distinct from the email-only and full_name-only requests covered
        by the other tests in this class."""
        admin, client = admin_user_and_client
        target = await user_factory(username="bothfieldstarget", full_name="Old Name")

        response = await client.patch(
            f"/api/v1/admin/users/{target.id}",
            json={"email": "both.fields@example.com", "full_name": "New Name"},
        )

        assert response.status_code == 200
        data = response.json()["data"]
        assert data["email"] == "both.fields@example.com"
        assert data["full_name"] == "New Name"
        events = await _audit_events_for(db_session, target.id)
        event_types = {event.event_type for event in events}
        assert event_types == {"email_changed", "full_name_changed"}
        assert len(events) == 2
        assert all(event.user_id == admin.id for event in events)

    async def test_duplicate_email_returns_409(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        _admin, client = admin_user_and_client
        await user_factory(email="taken@example.com")
        target = await user_factory(username="conflicttarget")

        response = await client.patch(
            f"/api/v1/admin/users/{target.id}", json={"email": "taken@example.com"}
        )

        assert response.status_code == 409
        assert response.json()["code"] == "USER_ALREADY_EXISTS"

    async def test_external_user_returns_409(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        _admin, client = admin_user_and_client
        target = await user_factory(
            username="externalpatchtarget",
            external_id=uuid4(),
            password_hash=None,
        )

        response = await client.patch(
            f"/api/v1/admin/users/{target.id}", json={"email": "new@example.com"}
        )

        assert response.status_code == 409
        assert response.json()["code"] == "USER_EXTERNAL_FIELD_READONLY"

    @pytest.mark.parametrize(
        ("stored", "requested"), [(False, True), (True, False)], ids=["mark", "unmark"]
    )
    async def test_bot_alone_sets_the_marker_and_creates_bot_changed(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
        db_session: AsyncSession,
        stored: bool,
        requested: bool,
    ) -> None:
        admin, client = admin_user_and_client
        target = await user_factory(
            username="botpatchtarget", bot=stored, full_name="Stored Name"
        )

        response = await client.patch(
            f"/api/v1/admin/users/{target.id}", json={"bot": requested}
        )

        assert response.status_code == 200
        data = response.json()["data"]
        assert data["bot"] is requested
        # The omitted members keep their values; the only event is bot's.
        assert data["full_name"] == "Stored Name"
        events = await _audit_events_for(db_session, target.id)
        assert [
            (event.event_type, event.old_value, event.new_value, event.user_id)
            for event in events
        ] == [("bot_changed", str(stored).lower(), str(requested).lower(), admin.id)]
        assert events[0].detail is None

    async def test_bot_with_email_and_full_name_updates_all_three(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
        db_session: AsyncSession,
    ) -> None:
        _admin, client = admin_user_and_client
        target = await user_factory(username="botallfields", full_name="Old Name")

        response = await client.patch(
            f"/api/v1/admin/users/{target.id}",
            json={
                "email": "bot.all.fields@example.com",
                "full_name": "Scanner",
                "bot": True,
            },
        )

        assert response.status_code == 200
        data = response.json()["data"]
        assert (data["email"], data["full_name"], data["bot"]) == (
            "bot.all.fields@example.com",
            "Scanner",
            True,
        )
        events = await _audit_events_for(db_session, target.id)
        assert {event.event_type for event in events} == {
            "email_changed",
            "full_name_changed",
            "bot_changed",
        }

    async def test_omitted_bot_leaves_the_marker_unchanged(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        _admin, client = admin_user_and_client
        target = await user_factory(username="botkeeptarget", bot=True)

        response = await client.patch(
            f"/api/v1/admin/users/{target.id}", json={"full_name": "Renamed"}
        )

        assert response.status_code == 200
        assert response.json()["data"]["bot"] is True

    @pytest.mark.parametrize("value", [None, "true", 1], ids=["null", "string", "int"])
    async def test_null_or_non_boolean_bot_returns_422(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
        db_session: AsyncSession,
        value: object,
    ) -> None:
        _admin, client = admin_user_and_client
        target = await user_factory(username="botinvalidtarget")

        response = await client.patch(
            f"/api/v1/admin/users/{target.id}", json={"bot": value}
        )

        assert response.status_code == 422
        assert response.json()["code"] == "VALIDATION_ERROR"
        await db_session.refresh(target)
        assert target.bot is False
        assert await _audit_events_for(db_session, target.id) == []

    async def test_external_user_bot_marker_returns_409_without_mutation(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
        db_session: AsyncSession,
    ) -> None:
        """The external identity provider owns the bot marker of an
        external user (user-management.md, Bot Accounts)."""
        _admin, client = admin_user_and_client
        target = await user_factory(
            username="externalbottarget", external_id=uuid4(), password_hash=None
        )

        response = await client.patch(
            f"/api/v1/admin/users/{target.id}", json={"bot": True}
        )

        assert response.status_code == 409
        assert response.json()["code"] == "USER_EXTERNAL_FIELD_READONLY"
        await db_session.refresh(target)
        assert target.bot is False
        assert await _audit_events_for(db_session, target.id) == []

    async def test_race_condition_user_deleted_returns_404(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The genuine concurrent race (the target user resolved
        successfully but disappears before `update_user()`'s own row
        lock) is covered at the service layer
        (`tests/test_services/test_user_service.py`). This verifies
        only the HTTP-layer mapping of the second `UserNotFoundError`
        catch to `404 USER_NOT_FOUND` — reproducing the race itself
        would require true cross-connection concurrency for a mapping
        that is otherwise a single deterministic `except` clause."""
        _admin, client = admin_user_and_client
        target = await user_factory(username="updateracetarget")
        monkeypatch.setattr(
            user_service,
            "update_user",
            AsyncMock(side_effect=UserNotFoundError()),
        )

        response = await client.patch(
            f"/api/v1/admin/users/{target.id}", json={"email": "new@example.com"}
        )

        assert response.status_code == 404
        assert response.json()["code"] == "USER_NOT_FOUND"

    async def test_no_op_when_values_unchanged_creates_no_audit_event(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
        db_session: AsyncSession,
    ) -> None:
        _admin, client = admin_user_and_client
        target = await user_factory(username="noopupdatetarget", full_name="Same Name")

        response = await client.patch(
            f"/api/v1/admin/users/{target.id}", json={"full_name": "Same Name"}
        )

        assert response.status_code == 200
        assert await _audit_events_for(db_session, target.id) == []

    async def test_operates_on_inactive_user(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        _admin, client = admin_user_and_client
        target = await user_factory(username="inactivepatchtarget", active=False)

        response = await client.patch(
            f"/api/v1/admin/users/{target.id}", json={"full_name": "New Name"}
        )

        assert response.status_code == 200
        assert response.json()["data"]["active"] is False


# ---------------------------------------------------------------------------
# POST /api/v1/admin/users/{user}/reactivate
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestReactivateUserAdmin:
    async def test_unauthenticated_returns_401(self, client: AsyncClient) -> None:
        response = await client.post("/api/v1/admin/users/someuser/reactivate")
        assert response.status_code == 401

    async def test_ordinary_user_returns_403(
        self, authenticated_client: AsyncClient
    ) -> None:
        response = await authenticated_client.post(
            "/api/v1/admin/users/someuser/reactivate"
        )
        assert response.status_code == 403

    async def test_missing_user_returns_404(
        self, admin_user_and_client: tuple[User, AsyncClient]
    ) -> None:
        _admin, client = admin_user_and_client
        response = await client.post(f"/api/v1/admin/users/{uuid4()}/reactivate")
        assert response.status_code == 404
        assert response.json()["code"] == "USER_NOT_FOUND"

    async def test_missing_username_returns_404(
        self, admin_user_and_client: tuple[User, AsyncClient]
    ) -> None:
        _admin, client = admin_user_and_client
        response = await client.post("/api/v1/admin/users/no-such-user/reactivate")
        assert response.status_code == 404
        assert response.json()["code"] == "USER_NOT_FOUND"

    async def test_resolves_by_username(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        _admin, client = admin_user_and_client
        target = await user_factory(username="reactivatebyusername", active=False)

        response = await client.post(
            f"/api/v1/admin/users/{target.username}/reactivate"
        )

        assert response.status_code == 200
        assert response.json()["data"]["id"] == str(target.id)
        assert response.json()["data"]["active"] is True

    async def test_reactivates_inactive_local_user_and_creates_audit_event(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
        db_session: AsyncSession,
    ) -> None:
        admin, client = admin_user_and_client
        target = await user_factory(username="reactivatetarget", active=False)

        response = await client.post(f"/api/v1/admin/users/{target.id}/reactivate")

        assert response.status_code == 200
        assert response.json()["data"]["active"] is True
        events = await _audit_events_for(db_session, target.id)
        assert len(events) == 1
        assert events[0].event_type == "user_reactivated"
        assert events[0].user_id == admin.id

    async def test_already_active_local_user_is_idempotent_no_op(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
        db_session: AsyncSession,
    ) -> None:
        _admin, client = admin_user_and_client
        target = await user_factory(username="alreadyactivetarget", active=True)

        response = await client.post(f"/api/v1/admin/users/{target.id}/reactivate")

        assert response.status_code == 200
        assert response.json()["data"]["active"] is True
        assert await _audit_events_for(db_session, target.id) == []

    async def test_external_user_returns_409_even_if_already_active(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
        db_session: AsyncSession,
    ) -> None:
        """See `docs/features/identity/user-service.md`
        (`reactivate_user()`): the external-status guard is evaluated
        before the already-active no-op check, so a human caller can
        never reactivate an external user through the API — active or
        not."""
        _admin, client = admin_user_and_client
        target = await user_factory(
            username="externalactivetarget",
            external_id=uuid4(),
            password_hash=None,
            active=True,
        )

        response = await client.post(f"/api/v1/admin/users/{target.id}/reactivate")

        assert response.status_code == 409
        assert response.json()["code"] == "USER_EXTERNAL_STATUS_READONLY"
        assert await _audit_events_for(db_session, target.id) == []

    async def test_race_condition_user_deleted_returns_404(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The genuine concurrent race (the target user resolved
        successfully but disappears before `reactivate_user()`'s own
        row lock) is covered at the service layer
        (`tests/test_services/test_user_service.py`). This verifies
        only the HTTP-layer mapping of the second `UserNotFoundError`
        catch to `404 USER_NOT_FOUND` — reproducing the race itself
        would require true cross-connection concurrency for a mapping
        that is otherwise a single deterministic `except` clause."""
        _admin, client = admin_user_and_client
        target = await user_factory(username="reactivateracetarget", active=False)
        monkeypatch.setattr(
            user_service,
            "reactivate_user",
            AsyncMock(side_effect=UserNotFoundError()),
        )

        response = await client.post(f"/api/v1/admin/users/{target.id}/reactivate")

        assert response.status_code == 404
        assert response.json()["code"] == "USER_NOT_FOUND"


# ---------------------------------------------------------------------------
# POST /api/v1/admin/users/{user}/password
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestResetUserPasswordAdmin:
    async def test_unauthenticated_returns_401(self, client: AsyncClient) -> None:
        response = await client.post(
            "/api/v1/admin/users/someuser/password",
            json={"password": "a-fictional-password-value"},
        )
        assert response.status_code == 401

    async def test_ordinary_user_returns_403(
        self, authenticated_client: AsyncClient
    ) -> None:
        response = await authenticated_client.post(
            "/api/v1/admin/users/someuser/password",
            json={"password": "a-fictional-password-value"},
        )
        assert response.status_code == 403

    async def test_admin_api_key_returns_403_session_required(
        self,
        client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
        user_role_factory: Callable[..., Awaitable[UserRole]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """This endpoint mints a new credential (a password), so it must
        not be reachable with an API key even for an admin — see
        `docs/features/identity/authentication.md` (Session-Only
        Authentication Dependency)."""
        admin = await user_factory(username="adminwithapikeypwd")
        await user_role_factory(user_id=admin.id, role=Role.ADMIN.value)
        token, digest = _make_api_key_credential()
        await api_key_factory(user_id=admin.id, key_hash=digest)
        monkeypatch.setattr(
            api_key_service, "update_last_used_at", AsyncMock(return_value=True)
        )
        target = await user_factory(username="passwordsessionreqtarget")

        response = await client.post(
            f"/api/v1/admin/users/{target.id}/password",
            json={"password": "a-new-fictional-password"},
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 403
        assert response.json()["code"] == "AUTH_SESSION_REQUIRED"

    async def test_missing_user_returns_404(
        self, admin_user_and_client: tuple[User, AsyncClient]
    ) -> None:
        _admin, client = admin_user_and_client
        response = await client.post(
            f"/api/v1/admin/users/{uuid4()}/password",
            json={"password": "a-fictional-password-value"},
        )
        assert response.status_code == 404
        assert response.json()["code"] == "USER_NOT_FOUND"

    async def test_missing_username_returns_404(
        self, admin_user_and_client: tuple[User, AsyncClient]
    ) -> None:
        _admin, client = admin_user_and_client
        response = await client.post(
            "/api/v1/admin/users/no-such-user/password",
            json={"password": "a-fictional-password-value"},
        )
        assert response.status_code == 404
        assert response.json()["code"] == "USER_NOT_FOUND"

    async def test_resolves_by_username(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
        db_session: AsyncSession,
    ) -> None:
        _admin, client = admin_user_and_client
        target = await user_factory(username="resetbyusername")

        response = await client.post(
            f"/api/v1/admin/users/{target.username}/password",
            json={"password": "a-new-fictional-password"},
        )

        assert response.status_code == 200
        events = await _audit_events_for(db_session, target.id)
        assert len(events) == 1
        assert events[0].event_type == "password_reset"

    async def test_resets_password_and_returns_documented_detail(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        _admin, client = admin_user_and_client
        target = await user_factory(username="resettarget")

        response = await client.post(
            f"/api/v1/admin/users/{target.id}/password",
            json={"password": "a-new-fictional-password"},
        )

        assert response.status_code == 200
        assert response.json()["data"] == {
            "detail": "Password updated. All active sessions have been invalidated."
        }

    async def test_creates_exactly_one_password_reset_audit_event(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
        db_session: AsyncSession,
    ) -> None:
        admin, client = admin_user_and_client
        target = await user_factory(username="resetaudittarget")

        await client.post(
            f"/api/v1/admin/users/{target.id}/password",
            json={"password": "a-new-fictional-password"},
        )

        events = await _audit_events_for(db_session, target.id)
        assert len(events) == 1
        assert events[0].event_type == "password_reset"
        assert events[0].user_id == admin.id
        assert events[0].old_value is None
        assert events[0].new_value is None

    async def test_works_for_inactive_user(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        _admin, client = admin_user_and_client
        target = await user_factory(username="resetinactivetarget", active=False)

        response = await client.post(
            f"/api/v1/admin/users/{target.id}/password",
            json={"password": "a-new-fictional-password"},
        )

        assert response.status_code == 200

    async def test_external_user_returns_409(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        _admin, client = admin_user_and_client
        target = await user_factory(
            username="resetexternaltarget",
            external_id=uuid4(),
            password_hash=None,
        )

        response = await client.post(
            f"/api/v1/admin/users/{target.id}/password",
            json={"password": "a-new-fictional-password"},
        )

        assert response.status_code == 409
        assert response.json()["code"] == "USER_EXTERNAL_PASSWORD_FORBIDDEN"

    async def test_race_condition_user_deleted_returns_404(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The genuine concurrent race (the target user resolved
        successfully but disappears before `reset_password()`'s own row
        lock) is covered at the service layer
        (`tests/test_services/test_user_service.py`). This verifies
        only the HTTP-layer mapping of the second `UserNotFoundError`
        catch to `404 USER_NOT_FOUND` — reproducing the race itself
        would require true cross-connection concurrency for a mapping
        that is otherwise a single deterministic `except` clause."""
        _admin, client = admin_user_and_client
        target = await user_factory(username="resetpasswordracetarget")
        monkeypatch.setattr(
            user_service,
            "reset_password",
            AsyncMock(side_effect=UserNotFoundError()),
        )

        response = await client.post(
            f"/api/v1/admin/users/{target.id}/password",
            json={"password": "a-new-fictional-password"},
        )

        assert response.status_code == 404
        assert response.json()["code"] == "USER_NOT_FOUND"

    async def test_password_outside_policy_returns_domain_422(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        _admin, client = admin_user_and_client
        target = await user_factory(username="resetshorttarget")

        response = await client.post(
            f"/api/v1/admin/users/{target.id}/password",
            json={"password": "short"},
        )

        assert response.status_code == 422
        assert response.json()["code"] == "USER_PASSWORD_POLICY_VIOLATION"

    async def test_missing_password_returns_generic_validation_error(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        _admin, client = admin_user_and_client
        target = await user_factory(username="resetnopasstarget")

        response = await client.post(
            f"/api/v1/admin/users/{target.id}/password", json={}
        )

        assert response.status_code == 422
        assert response.json()["code"] == "VALIDATION_ERROR"

    async def test_response_never_exposes_password_material(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        _admin, client = admin_user_and_client
        target = await user_factory(username="resetnoleaktarget")

        response = await client.post(
            f"/api/v1/admin/users/{target.id}/password",
            json={"password": "a-new-fictional-password"},
        )

        body_text = response.text
        assert "a-new-fictional-password" not in body_text
        assert "password_hash" not in body_text

    async def test_post_commit_callbacks_purge_sessions_and_clear_lockout(
        self,
        admin_commit_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
        redis_client: redis_asyncio.Redis,
        db_session: AsyncSession,
    ) -> None:
        """Proves the endpoint registers both post-commit callbacks (in
        order: session-cache purge, then lockout-counter clear) and that
        they actually execute against Redis — the shared `client`/
        `admin_client` fixtures never commit, so they cannot observe
        this (see `admin_commit_client`'s docstring)."""
        _admin, client = admin_commit_client
        target = await user_factory(username="resetcallbacktarget")
        created = await create_session(
            db_session,
            target,
            SessionCreationReason.LOCAL_LOGIN,
            expected_password_hash=None,
        )
        assert created is not None
        await db_session.commit()
        await redis_client.set("session_liveness:" + str(created.session.id), "1")
        await redis_client.set("login_attempts:resetcallbacktarget", "3")

        response = await client.post(
            f"/api/v1/admin/users/{target.id}/password",
            json={"password": "a-new-fictional-password"},
        )

        assert response.status_code == 200
        assert (
            await redis_client.get("session_liveness:" + str(created.session.id))
            is None
        )
        assert await redis_client.get("login_attempts:resetcallbacktarget") is None


# ---------------------------------------------------------------------------
# POST /api/v1/admin/users/{user}/unlock
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestUnlockUserAdmin:
    async def test_unauthenticated_returns_401(self, client: AsyncClient) -> None:
        response = await client.post("/api/v1/admin/users/someuser/unlock")
        assert response.status_code == 401

    async def test_ordinary_user_returns_403(
        self, authenticated_client: AsyncClient
    ) -> None:
        response = await authenticated_client.post(
            "/api/v1/admin/users/someuser/unlock"
        )
        assert response.status_code == 403

    async def test_missing_user_returns_404(
        self, admin_user_and_client: tuple[User, AsyncClient]
    ) -> None:
        _admin, client = admin_user_and_client
        response = await client.post(f"/api/v1/admin/users/{uuid4()}/unlock")
        assert response.status_code == 404
        assert response.json()["code"] == "USER_NOT_FOUND"

    async def test_missing_username_returns_404(
        self, admin_user_and_client: tuple[User, AsyncClient]
    ) -> None:
        _admin, client = admin_user_and_client
        response = await client.post("/api/v1/admin/users/no-such-user/unlock")
        assert response.status_code == 404
        assert response.json()["code"] == "USER_NOT_FOUND"

    async def test_race_condition_user_deleted_returns_404(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The genuine concurrent race (the target user resolved
        successfully but disappears before `unlock_user()` runs) is
        covered at the service layer
        (`tests/test_services/test_user_service.py`). This verifies
        only the HTTP-layer mapping of the second `UserNotFoundError`
        catch to `404 USER_NOT_FOUND` — reproducing the race itself
        would require true cross-connection concurrency for a mapping
        that is otherwise a single deterministic `except` clause."""
        _admin, client = admin_user_and_client
        target = await user_factory(username="unlockracetarget")
        monkeypatch.setattr(
            user_service,
            "unlock_user",
            AsyncMock(side_effect=UserNotFoundError()),
        )

        response = await client.post(f"/api/v1/admin/users/{target.id}/unlock")

        assert response.status_code == 404
        assert response.json()["code"] == "USER_NOT_FOUND"

    async def test_resolves_by_username(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        _admin, client = admin_user_and_client
        target = await user_factory(username="unlockbyusername")
        await redis_client.set("login_attempts:unlockbyusername", "4")

        response = await client.post(f"/api/v1/admin/users/{target.username}/unlock")

        assert response.status_code == 200
        assert await redis_client.get("login_attempts:unlockbyusername") is None

    async def test_clears_existing_lockout_key(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        _admin, client = admin_user_and_client
        target = await user_factory(username="unlockapitarget")
        await redis_client.set("login_attempts:unlockapitarget", "5")

        response = await client.post(f"/api/v1/admin/users/{target.id}/unlock")

        assert response.status_code == 200
        assert response.json()["data"] == {"detail": "Account unlocked successfully."}
        assert await redis_client.get("login_attempts:unlockapitarget") is None

    async def test_idempotent_when_no_lockout_key(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        _admin, client = admin_user_and_client
        target = await user_factory(username="unlocknokeytarget")

        response = await client.post(f"/api/v1/admin/users/{target.id}/unlock")

        assert response.status_code == 200
        assert response.json()["data"] == {"detail": "Account unlocked successfully."}

    async def test_works_for_external_and_inactive_users(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        _admin, client = admin_user_and_client
        target = await user_factory(
            username="unlockexternaltarget",
            external_id=uuid4(),
            password_hash=None,
            active=False,
        )

        response = await client.post(f"/api/v1/admin/users/{target.id}/unlock")

        assert response.status_code == 200

    async def test_creates_no_audit_event(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
        redis_client: redis_asyncio.Redis,
        db_session: AsyncSession,
    ) -> None:
        _admin, client = admin_user_and_client
        target = await user_factory(username="unlocknoaudittarget")
        await redis_client.set("login_attempts:unlocknoaudittarget", "2")

        await client.post(f"/api/v1/admin/users/{target.id}/unlock")

        assert await _audit_events_for(db_session, target.id) == []


# ---------------------------------------------------------------------------
# OpenAPI surface — the ten admin user endpoints and the directory contract
# ---------------------------------------------------------------------------


def _resolve_schema(document: dict[str, Any], schema: dict[str, Any]) -> dict[str, Any]:
    """Follow one `$ref` of the OpenAPI document, if present."""
    reference = schema.get("$ref")
    if reference is None:
        return schema
    name = reference.rsplit("/", 1)[-1]
    resolved: dict[str, Any] = document["components"]["schemas"][name]
    return resolved


def _success_item_properties(
    document: dict[str, Any], path: str, *, listed: bool
) -> set[str]:
    """Property names of the `data` object (or of each `data` item) of a
    GET operation's 200 response."""
    response = document["paths"][path]["get"]["responses"]["200"]
    envelope = _resolve_schema(
        document, response["content"]["application/json"]["schema"]
    )
    data = envelope["properties"]["data"]
    item = _resolve_schema(document, data["items"] if listed else data)
    return set(item["properties"])


@pytest.mark.unit
class TestAdminUserEndpointsOpenAPISurface:
    def test_exactly_ten_admin_user_endpoints_are_registered(self) -> None:
        from app.main import app as fastapi_app

        openapi_paths = fastapi_app.openapi()["paths"]
        admin_user_paths = {
            path: set(operations.keys())
            for path, operations in openapi_paths.items()
            if path.startswith("/api/v1/admin/users")
        }
        assert admin_user_paths == {
            "/api/v1/admin/users": {"get", "post"},
            "/api/v1/admin/users/{user}": {"get", "patch"},
            "/api/v1/admin/users/{user}/reactivate": {"post"},
            "/api/v1/admin/users/{user}/password": {"post"},
            "/api/v1/admin/users/{user}/unlock": {"post"},
            "/api/v1/admin/users/{user}/roles": {"post"},
            "/api/v1/admin/users/{user}/deactivate": {"post"},
            "/api/v1/admin/users/{user}/deactivation-impact": {"get"},
        }

    @pytest.mark.parametrize(
        ("path", "listed"),
        [("/api/v1/admin/users", True), ("/api/v1/admin/users/{user}", False)],
    )
    def test_admin_reads_document_the_complete_profile(
        self, path: str, listed: bool
    ) -> None:
        from app.main import app as fastapi_app

        document = fastapi_app.openapi()
        assert (
            _success_item_properties(document, path, listed=listed)
            == _COMPLETE_PROFILE_FIELDS
        )


@pytest.mark.unit
class TestUserDirectoryOpenAPISurface:
    @pytest.mark.parametrize(
        ("path", "listed"),
        [("/api/v1/users", True), ("/api/v1/users/{user}", False)],
    )
    def test_directory_reads_document_only_the_directory_entry(
        self, path: str, listed: bool
    ) -> None:
        from app.main import app as fastapi_app

        document = fastapi_app.openapi()
        assert (
            _success_item_properties(document, path, listed=listed)
            == _DIRECTORY_ENTRY_FIELDS
        )

    def test_directory_list_declares_no_type_filter_or_created_at_sort(
        self,
    ) -> None:
        from app.main import app as fastapi_app

        document = fastapi_app.openapi()
        parameters = {
            parameter["name"]: parameter
            for parameter in document["paths"]["/api/v1/users"]["get"]["parameters"]
        }
        assert set(parameters) == {
            "search",
            "active",
            "role",
            "has_role",
            "page",
            "per_page",
            "sort_by",
            "sort_order",
        }
        sort_by = _resolve_schema(document, parameters["sort_by"]["schema"])
        assert set(sort_by["enum"]) == {"username", "full_name", "email"}


@pytest.mark.unit
@pytest.mark.parametrize(
    "schema_name",
    [
        "UserReference",
        "UserDirectoryData",
        "UserData",
        "UserManagerData",
        "CurrentUserData",
    ],
)
def test_user_representation_declares_bot_as_a_required_boolean(
    schema_name: str,
) -> None:
    """Every user representation carries the bot marker
    (`docs/features/identity/user-management.md`, Bot Accounts;
    `docs/features/platform/testing-strategy.md`, Bot marker)."""
    from app.main import app as fastapi_app

    schema = fastapi_app.openapi()["components"]["schemas"][schema_name]
    assert schema["properties"]["bot"]["type"] == "boolean"
    assert "bot" in schema["required"]
