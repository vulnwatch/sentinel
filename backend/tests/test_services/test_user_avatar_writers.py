"""Single-session tests of the `user_service` writers of `User.avatar_url`
(backend/app/services/user_service.py).

Owning specifications:

- docs/features/identity/user-avatars.md (Invariants and Writers; Testing
  Requirements, item 6).
- docs/features/identity/user-service.md (`create_user()` step 8,
  `update_user()` step 6, `deactivate_user()` step 3, `reactivate_user()`
  Explicitly NOT restored; Operational metadata exclusions).
- docs/features/identity/identity-audit-log.md (Service Contract,
  Operational metadata exclusions: the clear creates no event).

The races between these writers and the fetcher's conditional write are in
`tests/test_services/test_identity/test_sync_slack_avatars_concurrency.py`.
Every URL is fictional.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any, Final
from uuid import UUID

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.identity_audit_event import IdentityAuditEvent
from app.models.user import User
from app.services.user_service import (
    create_user,
    deactivate_user,
    reactivate_user,
    update_user,
)
from tests.support.database import rollback_test_scope

UserFactory = Callable[..., Awaitable[User]]

PICTURE: Final = (
    "https://avatars.slack-edge.com/2026-01-15/"
    "1000000000001_0f1c7e00000000000000_192.jpg"
)


class _InjectedError(Exception):
    """A deterministic failure that rolls the workflow back."""


async def _stored(db: AsyncSession, user_id: UUID) -> str | None:
    return await db.scalar(select(User.avatar_url).where(User.id == user_id))


async def _event_count(db: AsyncSession, user_id: UUID) -> int:
    count = await db.scalar(
        select(func.count())
        .select_from(IdentityAuditEvent)
        .where(IdentityAuditEvent.target_user_id == user_id)
    )
    assert count is not None
    return count


@pytest.fixture
async def pictured(user_factory: UserFactory) -> User:
    """An active local user who is not a bot account, with a picture."""
    return await user_factory(username="pictured", avatar_url=PICTURE)


@pytest.mark.integration
class TestCreateUser:
    async def test_creates_every_user_without_a_picture(
        self, db_session: AsyncSession
    ) -> None:
        user = await create_user(
            db_session,
            username="fresh",
            email="fresh@example.com",
            password="Fictional-Password-0001",
            acting_user_id=None,
        )

        assert await _stored(db_session, user.id) is None


@pytest.mark.integration
class TestDeactivateUser:
    async def test_clears_the_url_in_the_deactivation(
        self, db_session: AsyncSession, pictured: User
    ) -> None:
        events = await _event_count(db_session, pictured.id)

        result = await deactivate_user(
            db_session, pictured.id, acting_user_id=None, reason="fictional"
        )

        assert result.deactivated is True
        assert result.user.avatar_url is None
        assert await _stored(db_session, pictured.id) is None
        # Only `user_deactivated`: the clear creates no event of its own.
        assert await _event_count(db_session, pictured.id) == events + 1

    async def test_rollback_keeps_the_url(
        self, db_session: AsyncSession, pictured: User
    ) -> None:
        user_id = pictured.id
        cleared: list[str | None] = []

        async def _deactivate_then_fail() -> None:
            async with rollback_test_scope(db_session):
                await deactivate_user(
                    db_session, user_id, acting_user_id=None, reason="fictional"
                )
                cleared.append(await _stored(db_session, user_id))
                raise _InjectedError

        with pytest.raises(_InjectedError):
            await _deactivate_then_fail()

        assert cleared == [None]
        assert await _stored(db_session, user_id) == PICTURE


@pytest.mark.integration
class TestReactivateUser:
    async def test_restores_no_url(
        self, db_session: AsyncSession, pictured: User
    ) -> None:
        await deactivate_user(
            db_session, pictured.id, acting_user_id=None, reason="fictional"
        )

        result = await reactivate_user(db_session, pictured.id, acting_user_id=None)

        assert result.reactivated is True
        assert await _stored(db_session, pictured.id) is None


@pytest.mark.integration
class TestUpdateUser:
    @pytest.mark.parametrize(
        "change",
        [
            pytest.param({"email": "renamed@example.com"}, id="email"),
            pytest.param({"bot": True}, id="bot-true"),
            pytest.param(
                {"email": "renamed@example.com", "full_name": "Renamed"},
                id="email-with-another-field",
            ),
        ],
    )
    async def test_effective_change_clears_the_url_without_a_field_or_event(
        self, db_session: AsyncSession, pictured: User, change: dict[str, Any]
    ) -> None:
        events = await _event_count(db_session, pictured.id)

        result = await update_user(
            db_session, pictured.id, acting_user_id=None, **change
        )

        assert await _stored(db_session, pictured.id) is None
        assert result.user.avatar_url is None
        assert "avatar_url" not in result.changed_fields
        assert len(result.changed_fields) == len(change)
        # One field-change event per changed field, none for the clear.
        assert await _event_count(db_session, pictured.id) == events + len(change)

    @pytest.mark.parametrize(
        "change",
        [
            pytest.param({"username": "renamed"}, id="username"),
            pytest.param({"full_name": "Renamed"}, id="full-name"),
            pytest.param({"email": "pictured@example.com"}, id="same-email"),
            pytest.param({"email": "  PICTURED@Example.com "}, id="same-normalized"),
            pytest.param({"bot": False}, id="bot-unchanged"),
            pytest.param({}, id="no-field"),
        ],
    )
    async def test_other_change_or_no_op_keeps_the_url(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        change: dict[str, Any],
    ) -> None:
        user = await user_factory(
            username="pictured", email="pictured@example.com", avatar_url=PICTURE
        )

        await update_user(db_session, user.id, acting_user_id=None, **change)

        assert await _stored(db_session, user.id) == PICTURE

    async def test_change_of_bot_to_false_sets_no_url(
        self, db_session: AsyncSession, user_factory: UserFactory
    ) -> None:
        bot = await user_factory(bot=True)

        result = await update_user(db_session, bot.id, acting_user_id=None, bot=False)

        assert result.changed_fields == ["bot"]
        assert await _stored(db_session, bot.id) is None
