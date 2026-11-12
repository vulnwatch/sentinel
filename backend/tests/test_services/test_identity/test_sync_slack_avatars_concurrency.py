"""Independent-session races between the conditional write of
`sync_slack_avatars` (backend/app/services/identity/sync_slack_avatars.py)
and the user lifecycle writers.

Owning specifications:

- docs/features/identity/user-avatars.md (Algorithm, step 5; Concurrency;
  Invariants and Writers; Testing Requirements, item 5).
- docs/features/identity/user-service.md (`deactivate_user()`,
  `update_user()`; Assignment concurrent with eligibility loss).
- docs/conventions.md (Cross-Domain Root Lock Order: the `FOR SHARE` of the
  assignment paths and the `FOR NO KEY UPDATE` of the lifecycle writers).
- docs/features/platform/testing-strategy.md (Concurrency Testing,
  Lock-Wait Observation).

The fetcher runs `execute()` on its own session; the lifecycle writer is the
real service function on another, and the assignment path's lock is the real
`ticket_mutations.stabilize_acting_user()`. Committed state is read through a
fresh session, and every committed row is deleted at teardown. Every address
and URL is fictional.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Final

import httpx
import pytest
from pydantic import SecretStr
from sqlalchemy import delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.identity_audit_event import IdentityAuditEvent
from app.models.user import User
from app.services import ticket_mutations
from app.services.identity.sync_slack_avatars import SyncSlackAvatars
from app.services.user_service import deactivate_user, update_user
from tests.support.database import assert_lock_wait
from tests.support.slack import TOKEN, UPLOADED_PICTURE, SlackServer, body, found

Factory = Callable[[], Awaitable[AsyncSession]]
Writer = Callable[[AsyncSession, uuid.UUID], Awaitable[object]]

PICTURE: Final = UPLOADED_PICTURE
OLD_PICTURE: Final = (
    "https://avatars.slack-edge.com/2026-02-01/"
    "2000000000002_0f1c7e00000000000002_192.jpg"
)


async def _deactivate(session: AsyncSession, user_id: uuid.UUID) -> object:
    return await deactivate_user(
        session, user_id, acting_user_id=None, reason="fictional"
    )


async def _mark_bot(session: AsyncSession, user_id: uuid.UUID) -> object:
    return await update_user(session, user_id, acting_user_id=None, bot=True)


async def _change_email(session: AsyncSession, user_id: uuid.UUID) -> object:
    return await update_user(
        session,
        user_id,
        acting_user_id=None,
        email=f"changed-{uuid.uuid4().hex[:8]}@example.com",
    )


WRITERS: Final = [
    pytest.param(_deactivate, id="deactivation"),
    pytest.param(_mark_bot, id="bot-marking"),
    pytest.param(_change_email, id="email-change"),
]


class World:
    """Committed users of one test and the sessions that act on them."""

    def __init__(self, factory: Factory) -> None:
        self.factory = factory
        self.user_ids: list[uuid.UUID] = []

    async def user(self, avatar_url: str | None = OLD_PICTURE) -> uuid.UUID:
        session = await self.factory()
        n = uuid.uuid4().hex[:8]
        user = User(
            username=f"race-{n}",
            email=f"race-{n}@example.com",
            password_hash="$2b$12$" + "a" * 53,
            avatar_url=avatar_url,
        )
        session.add(user)
        await session.commit()
        self.user_ids.append(user.id)
        return user.id

    async def stored(self, user_id: uuid.UUID) -> str | None:
        session = await self.factory()
        value = await session.scalar(select(User.avatar_url).where(User.id == user_id))
        await session.rollback()
        return value


@pytest.fixture
async def world(db_session_factory: Factory) -> AsyncIterator[World]:
    created = World(db_session_factory)
    try:
        yield created
    finally:
        session = await db_session_factory()
        await session.execute(
            delete(IdentityAuditEvent).where(
                or_(
                    IdentityAuditEvent.target_user_id.in_(created.user_ids),
                    IdentityAuditEvent.user_id.in_(created.user_ids),
                )
            )
        )
        await session.execute(delete(User).where(User.id.in_(created.user_ids)))
        await session.commit()


@pytest.fixture(autouse=True)
def _token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "slack_bot_token", SecretStr(TOKEN))


def _fetcher(
    before_response: Callable[[], Awaitable[None]] | None = None,
) -> SyncSlackAvatars:
    """A fetcher whose every lookup finds `PICTURE`, after awaiting
    `before_response`: the point between the selection and the write."""
    server = SlackServer()
    server.response = body(found(PICTURE))

    async def handler(request: httpx.Request) -> httpx.Response:
        if before_response is not None:
            await before_response()
        return server.handler(request)

    fetcher = SyncSlackAvatars()
    fetcher._http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return fetcher


async def _execute(fetcher: SyncSlackAvatars, session: AsyncSession) -> None:
    try:
        await fetcher.execute(session)
    finally:
        await fetcher._teardown_http_client()


def _metrics(fetcher: SyncSlackAvatars) -> tuple[int, int, int, int]:
    return (fetcher._succeeded, fetcher._created, fetcher._updated, fetcher._failed)


@pytest.mark.integration
class TestLifecycleChangeBeforeTheWrite:
    @pytest.mark.parametrize("writer", WRITERS)
    async def test_change_committed_after_the_selection_leaves_null(
        self, world: World, db_session_factory: Factory, writer: Writer
    ) -> None:
        user_id = await world.user()
        other = await db_session_factory()

        async def change() -> None:
            await writer(other, user_id)
            await other.commit()

        fetcher = _fetcher(change)

        await _execute(fetcher, await db_session_factory())

        # The write matched no row: a success without an update.
        assert _metrics(fetcher) == (1, 0, 0, 0)
        assert await world.stored(user_id) is None

    @pytest.mark.parametrize("writer", WRITERS)
    async def test_write_waiting_for_an_uncommitted_change_matches_no_row(
        self, world: World, db_session_factory: Factory, writer: Writer
    ) -> None:
        user_id = await world.user()
        holder = await db_session_factory()
        # The change holds the User row, uncommitted, before the run starts:
        # the selection still reads the committed row.
        await writer(holder, user_id)
        waiter = await db_session_factory()
        fetcher = _fetcher()
        task = asyncio.create_task(_execute(fetcher, waiter))

        await assert_lock_wait(task, waiter=waiter, blocked_by=holder)
        await holder.commit()
        await asyncio.wait_for(task, timeout=10)

        assert _metrics(fetcher) == (1, 0, 0, 0)
        assert await world.stored(user_id) is None


@pytest.mark.integration
class TestWriteBeforeTheLifecycleChange:
    @pytest.mark.parametrize("writer", WRITERS)
    async def test_later_change_clears_the_written_url(
        self, world: World, db_session_factory: Factory, writer: Writer
    ) -> None:
        user_id = await world.user(avatar_url=None)
        fetcher = _fetcher()
        await _execute(fetcher, await db_session_factory())
        assert await world.stored(user_id) == PICTURE

        session = await db_session_factory()
        await writer(session, user_id)
        await session.commit()

        assert _metrics(fetcher) == (1, 0, 1, 0)
        assert await world.stored(user_id) is None


@pytest.mark.integration
class TestAssignmentLock:
    async def test_write_waits_for_the_assignment_lock_and_completes_after_it(
        self, world: World, db_session_factory: Factory
    ) -> None:
        user_id = await world.user(avatar_url=None)
        holder = await db_session_factory()
        await ticket_mutations.stabilize_acting_user(holder, user_id)
        waiter = await db_session_factory()
        fetcher = _fetcher()
        task = asyncio.create_task(_execute(fetcher, waiter))

        await assert_lock_wait(task, waiter=waiter, blocked_by=holder)
        await holder.commit()
        await asyncio.wait_for(task, timeout=10)

        assert _metrics(fetcher) == (1, 0, 1, 0)
        assert await world.stored(user_id) == PICTURE
