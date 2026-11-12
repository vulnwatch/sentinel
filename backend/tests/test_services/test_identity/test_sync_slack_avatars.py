"""Tests for the `sync_slack_avatars` fetcher
(backend/app/services/identity/sync_slack_avatars.py).

Owning specifications:

- docs/features/identity/user-avatars.md (Slack Integration — Slack App and
  Bot Token, Lookup Request, Response Contract, Accepted Picture URL;
  Fetcher: `sync_slack_avatars` — properties, Algorithm, Error Handling,
  Work Unit and Metrics; Security and Privacy; Testing Requirements, items
  2, 3, 4, and 7).
- docs/features/platform/fetcher-infrastructure.md (BaseFetcher Base Class:
  execution-session transaction contract, Finalization, Outcome and effect
  accounting; Error Message Sanitization; `SoftTimeLimitExceeded` handling
  convention; Request Delay; Naming Convention; Per-Ticket Catch-Up
  inventory; Fetcher Discovery; FetcherConfig bootstrap; Celery Beat
  Schedule Synchronization).
- docs/features/platform/networking.md (Transport-Level Retry, Method
  Safety; Redirect Policy).
- docs/features/platform/testing-strategy.md (User Avatars; Fetcher Outcome
  and Effect Accounting; External String Admissibility; External JSON
  Decoding).

`execute()` tests run against users seeded in the rolled-back `db_session`:
each commit of the fetcher releases a savepoint of the per-test outer
transaction, so every row is rolled back at teardown. The `run()` tests
commit users, a `FetcherConfig`, and a `FetcherRun` through
`real_session_factory` and delete them at teardown. Slack is the in-process
`SlackServer`. Every user, address, token, and URL is fictional. The races
with the user lifecycle are in `test_sync_slack_avatars_concurrency.py`.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Final
from unittest.mock import AsyncMock

import httpx
import pytest
from celery import Celery
from celery.exceptions import SoftTimeLimitExceeded
from pydantic import SecretStr
from redbeat import RedBeatSchedulerEntry
from sqlalchemy import delete, func, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from structlog.testing import capture_logs

import app.services.base_fetcher as base_fetcher_module
import app.services.identity.sync_slack_avatars as sync_module
from app.config import settings
from app.models.fetcher_config import FetcherConfig
from app.models.fetcher_run import FetcherRun
from app.models.identity_audit_event import IdentityAuditEvent
from app.models.user import User
from app.services import fetcher_discovery, http_client
from app.services.base_fetcher import (
    FETCHER_REGISTRY,
    FetcherError,
    FetcherRunConfig,
    get_catch_up_fetchers,
)
from app.services.fetcher_bootstrap import bootstrap_fetcher_configs
from app.services.fetcher_schedule import reconcile_beat_schedule
from app.services.identity.sync_slack_avatars import (
    LOOKUP_URL,
    TOKEN_ERRORS,
    Lookup,
    Outcome,
    SlackLookupError,
    SlackResponseError,
    SyncSlackAvatars,
    accepted_picture_url,
    classify_lookup,
)
from tests.support.inadmissible import INADMISSIBLE_CHARACTERS, SURROGATE, json_bytes
from tests.support.json_decoding import (
    NESTED_ARRAY,
    OVERSIZED_INTEGER,
    limit_parser_nesting,
)
from tests.support.slack import (
    FIXTURES,
    TOKEN,
    UPLOADED_PICTURE,
    Responder,
    SlackServer,
    body,
    error,
    form,
    found,
    load,
    raising,
    raw,
    sequence,
    unconsumed_strings,
)
from tests.support.slack import (
    LOOKUP_URL as FIXTURE_URL,
)

NAME: Final = "sync_slack_avatars"

# The specified messages and events, as literals (user-avatars.md, Error
# Handling; Algorithm, step 6).
CONNECT_FAILED_MESSAGE: Final = "Failed to connect to Slack"
TIMED_OUT_MESSAGE: Final = "Slack request timed out"
RATE_LIMITED_MESSAGE: Final = "Slack rate limit reached"
ITEM_FAILED_EVENT: Final = "fetcher_item_failed"
DISABLED_EVENT: Final = "slack_avatar_sync_disabled"

PICTURE: Final = UPLOADED_PICTURE
OTHER_PICTURE: Final = (
    "https://avatars.slack-edge.com/2026-02-01/"
    "2000000000002_0f1c7e00000000000002_192.jpg"
)
STALE: Final = datetime(2000, 1, 1, tzinfo=UTC)
"""An `updated_at` far before the transaction's `now()`."""

Metrics = tuple[int, int, int, int]
"""`(succeeded, created, updated, failed)` of one fetcher run."""
UserFactory = Callable[..., Awaitable[User]]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def token(monkeypatch: pytest.MonkeyPatch) -> str:
    """Lookup mode: a configured bot token."""
    monkeypatch.setattr(settings, "slack_bot_token", SecretStr(TOKEN))
    return TOKEN


@pytest.fixture
def no_token(monkeypatch: pytest.MonkeyPatch) -> None:
    """Disabled mode: an empty bot token."""
    monkeypatch.setattr(settings, "slack_bot_token", SecretStr(""))


def _metrics(fetcher: SyncSlackAvatars) -> Metrics:
    return (fetcher._succeeded, fetcher._created, fetcher._updated, fetcher._failed)


def _fetcher(
    server: SlackServer, request_delay: float | None = None
) -> SyncSlackAvatars:
    fetcher = SyncSlackAvatars()
    fetcher._http_client = server.client()
    if request_delay is not None:
        fetcher.config = FetcherRunConfig(
            hard_time_limit_seconds=3600,
            request_delay=request_delay,
            custom_settings={},
        )
    return fetcher


async def _execute(
    db: AsyncSession, server: SlackServer, request_delay: float | None = None
) -> SyncSlackAvatars:
    fetcher = _fetcher(server, request_delay)
    try:
        await fetcher.execute(db)
    finally:
        await fetcher._teardown_http_client()
    return fetcher


async def _execute_failing(
    db: AsyncSession, server: SlackServer, error: type[BaseException] = FetcherError
) -> tuple[BaseException, SyncSlackAvatars]:
    fetcher = _fetcher(server)
    try:
        with pytest.raises(error) as raised:
            await fetcher.execute(db)
    finally:
        await fetcher._teardown_http_client()
    return raised.value, fetcher


async def _stored(db: AsyncSession, user: User) -> str | None:
    return await db.scalar(select(User.avatar_url).where(User.id == user.id))


async def _users(user_factory: UserFactory, count: int, **values: Any) -> list[User]:
    """`count` users in ascending `id` order, the order of the selection."""
    users = [await user_factory(**values) for _ in range(count)]
    return sorted(users, key=lambda user: user.id)


def _logged(logs: Sequence[Mapping[str, Any]], name: str) -> list[Mapping[str, Any]]:
    return [entry for entry in logs if entry["event"] == name]


def _status_error_text(code: int) -> str:
    """The text that `httpx` gives the `HTTPStatusError` of `code`."""
    request = httpx.Request("POST", LOOKUP_URL)
    response = httpx.Response(code, request=request)
    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as e:
        return str(e)
    raise AssertionError(code)


# ---------------------------------------------------------------------------
# Classification (Response Contract; Accepted Picture URL)
# ---------------------------------------------------------------------------


def _url_of_length(length: int) -> str:
    prefix = "https://avatars.slack-edge.com/"
    return prefix + "a" * (length - len(prefix))


@pytest.mark.unit
class TestAcceptedPictureUrl:
    @pytest.mark.parametrize(
        "url",
        [
            pytest.param(PICTURE, id="uploaded"),
            pytest.param("https://avatars.slack-edge.com", id="no-path"),
            pytest.param(
                "https://avatars.slack-edge.com/a/b_192.jpg?v=1&w=2", id="query"
            ),
            pytest.param(_url_of_length(2048), id="2048-characters"),
            pytest.param(
                "https://avatars.slack-edge.com/~!$&'()*+,;=:@%20", id="punct"
            ),
        ],
    )
    def test_accepted(self, url: str) -> None:
        assert accepted_picture_url(url) is True
        assert classify_lookup(found(url)) == Lookup(Outcome.PICTURE, picture_url=url)

    @pytest.mark.parametrize(
        "url",
        [
            pytest.param(_url_of_length(2049), id="2049-characters"),
            pytest.param(
                load("lookup_gravatar")["user"]["profile"]["image_192"], id="gravatar"
            ),
            pytest.param(
                "https://secure.gravatar.com/avatar/0.jpg", id="gravatar-host"
            ),
            pytest.param("https://ca.slack-edge.com/T0-U0-0a1-192", id="ca-host"),
            pytest.param("https://a.slack-edge.com/img/ava.png", id="a-host"),
            pytest.param("https://example.com/avatar.jpg", id="another-host"),
            pytest.param("https://avatars.slack-edge.com.example.com/x", id="suffix"),
            pytest.param("https://AVATARS.SLACK-EDGE.COM/x", id="host-case"),
            pytest.param("http://avatars.slack-edge.com/x", id="http"),
            pytest.param("HTTPS://avatars.slack-edge.com/x", id="scheme-case"),
            pytest.param("ftp://avatars.slack-edge.com/x", id="ftp"),
            pytest.param("//avatars.slack-edge.com/x", id="scheme-relative"),
            pytest.param("/2026-01-15/x_192.jpg", id="relative"),
            pytest.param("https://user@avatars.slack-edge.com/x", id="user-info"),
            pytest.param("https://user:pw@avatars.slack-edge.com/x", id="password"),
            pytest.param("https://avatars.slack-edge.com:443/x", id="port"),
            pytest.param("https://avatars.slack-edge.com:/x", id="empty-port"),
            pytest.param("https://avatars.slack-edge.com/x#top", id="fragment"),
            pytest.param("https://avatars.slack-edge.com/x#", id="empty-fragment"),
            pytest.param("https://avatars.slack-edge.com/a b", id="space"),
            pytest.param("https://avatars.slack-edge.com/a\tb", id="tab"),
            pytest.param("https://avatars.slack-edge.com/x\n", id="newline"),
            pytest.param("https://avatars.slack-edge.com/\x7f", id="delete"),
            pytest.param("https://avatars.slack-edge.com/\u00e9", id="non-ascii"),
            pytest.param("https://[avatars.slack-edge.com/x", id="malformed"),
            pytest.param("", id="empty"),
        ],
    )
    def test_not_accepted_is_no_picture(self, url: str) -> None:
        assert accepted_picture_url(url) is False
        assert classify_lookup(found(url)) == Lookup(Outcome.NO_PICTURE)

    @pytest.mark.parametrize("character", INADMISSIBLE_CHARACTERS)
    def test_inadmissible_character_is_no_picture(self, character: str) -> None:
        url = f"{PICTURE}{character}"

        assert accepted_picture_url(url) is False
        assert classify_lookup(found(url)) == Lookup(Outcome.NO_PICTURE)

    def test_accepted_url_is_returned_unchanged(self) -> None:
        url = "https://avatars.slack-edge.com/A%2Fb/C_192.JPG?X=Y"

        lookup = classify_lookup(found(url))

        assert lookup.picture_url is url


@pytest.mark.unit
class TestClassifyLookup:
    def test_users_not_found_is_no_picture(self) -> None:
        assert classify_lookup(error("users_not_found")) == Lookup(Outcome.NO_PICTURE)

    @pytest.mark.parametrize("code", sorted(TOKEN_ERRORS))
    def test_token_error_is_token_rejected(self, code: str) -> None:
        assert classify_lookup(error(code)) == Lookup(
            Outcome.TOKEN_REJECTED, token_error=code
        )

    def test_token_errors_are_the_specified_codes(self) -> None:
        assert {
            "not_authed",
            "invalid_auth",
            "account_inactive",
            "token_revoked",
            "token_expired",
            "missing_scope",
            "not_allowed_token_type",
        } == TOKEN_ERRORS

    def test_ratelimited_is_rate_limited(self) -> None:
        assert classify_lookup(error("ratelimited")) == Lookup(Outcome.RATE_LIMITED)

    @pytest.mark.parametrize(
        "document",
        [
            pytest.param(error("invalid_arguments"), id="invalid-arguments"),
            pytest.param(error("internal_error"), id="internal-error"),
            pytest.param(error(""), id="empty-code"),
            pytest.param(error("USERS_NOT_FOUND"), id="code-case"),
            pytest.param({"ok": False}, id="absent"),
            pytest.param(error(None), id="null"),
            pytest.param(error(1), id="number"),
            pytest.param(error(["invalid_auth"]), id="array"),
            pytest.param(error({"code": "invalid_auth"}), id="object"),
        ],
    )
    def test_other_or_absent_error_is_lookup_error(
        self, document: dict[str, Any]
    ) -> None:
        assert classify_lookup(document) == Lookup(Outcome.LOOKUP_ERROR)

    @pytest.mark.parametrize(
        "document",
        [
            pytest.param([], id="array-root"),
            pytest.param("ok", id="string-root"),
            pytest.param(None, id="null-root"),
            pytest.param({}, id="ok-absent"),
            pytest.param({"ok": "true", "user": {}}, id="ok-string"),
            pytest.param({"ok": 1}, id="ok-number"),
            pytest.param({"ok": None}, id="ok-null"),
            pytest.param({"ok": True}, id="user-absent"),
            pytest.param({"ok": True, "user": None}, id="user-null"),
            pytest.param({"ok": True, "user": []}, id="user-array"),
            pytest.param({"ok": True, "user": {}}, id="profile-absent"),
            pytest.param({"ok": True, "user": {"profile": "x"}}, id="profile-string"),
            pytest.param({"ok": True, "user": {"profile": {}}}, id="image-absent"),
            pytest.param(found(None), id="image-null"),
            pytest.param(found(192), id="image-number"),
            pytest.param(found([PICTURE]), id="image-array"),
        ],
    )
    def test_any_other_body_is_invalid_response(self, document: object) -> None:
        assert classify_lookup(document) == Lookup(Outcome.INVALID_RESPONSE)

    def test_only_the_consumed_members_are_read(self) -> None:
        """A member that the fetcher does not consume changes no outcome."""
        document = found(PICTURE)
        document["user"]["deleted"] = True
        document["user"]["profile"]["is_custom_image"] = False
        document["user"]["profile"]["image_512"] = None
        document["extra"] = {"ok": False}

        assert classify_lookup(document) == Lookup(Outcome.PICTURE, picture_url=PICTURE)

    def test_exception_messages_carry_no_response_value(self) -> None:
        assert str(SlackResponseError()) == "Slack returned an invalid lookup response"
        assert str(SlackLookupError()) == "Slack reported a lookup error"


# ---------------------------------------------------------------------------
# The lookup request (Lookup Request; Request Delay; Transport-Level Retry)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRequest:
    async def test_one_post_per_selected_user_in_id_order(
        self, db_session: AsyncSession, user_factory: UserFactory, token: str
    ) -> None:
        users = await _users(user_factory, 3)
        server = SlackServer()

        await _execute(db_session, server)

        assert server.emails() == [user.email for user in users]
        for request, user in zip(server.requests, users, strict=True):
            assert request.method == "POST"
            assert str(request.url) == LOOKUP_URL == FIXTURE_URL
            assert request.headers["authorization"] == f"Bearer {token}"
            assert request.headers["content-type"] == (
                "application/x-www-form-urlencoded"
            )
            assert form(request) == {"email": [user.email]}
            assert token not in str(request.url)
            assert token.encode() not in request.content

    async def test_disabled_mode_sends_no_request_and_creates_no_client(
        self, db_session: AsyncSession, user_factory: UserFactory, no_token: None
    ) -> None:
        await _users(user_factory, 2, avatar_url=PICTURE)
        fetcher = SyncSlackAvatars()

        await fetcher.execute(db_session)

        assert fetcher._http_client is None
        assert _metrics(fetcher) == (2, 0, 2, 0)

    async def test_shared_client_follows_no_redirect(self) -> None:
        fetcher = SyncSlackAvatars()
        try:
            assert fetcher.http_client.follow_redirects is False
        finally:
            await fetcher._teardown_http_client()

    @pytest.fixture
    def shared_transport(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> tuple[SlackServer, AsyncMock]:
        """The fetcher's own shared client, whose network is a
        `SlackServer`; its retry backoff is recorded instead of awaited."""
        server = SlackServer()
        backoff = AsyncMock()
        monkeypatch.setattr(http_client, "asyncio", SimpleNamespace(sleep=backoff))
        monkeypatch.setattr(httpx, "AsyncHTTPTransport", lambda **_: server.transport())
        return server, backoff

    @pytest.mark.parametrize(
        "first",
        [
            pytest.param(raising(httpx.ConnectError("fictional")), id="connect"),
            pytest.param(raising(httpx.ReadTimeout("fictional")), id="timeout"),
            pytest.param(raw(b"", 503), id="5xx"),
        ],
    )
    async def test_transport_retries_a_failed_lookup(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        token: str,
        shared_transport: tuple[SlackServer, AsyncMock],
        first: Responder,
    ) -> None:
        server, backoff = shared_transport
        user = await user_factory()
        server.response = sequence(first, body(found(PICTURE)))
        fetcher = SyncSlackAvatars()
        try:
            await fetcher.execute(db_session)
        finally:
            await fetcher._teardown_http_client()

        assert server.emails() == [user.email, user.email]
        assert [call.args[0] for call in backoff.await_args_list] == [1.0]
        assert await _stored(db_session, user) == PICTURE

    @pytest.fixture
    def waits(self, monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
        """The run's request-delay waits, in order with its requests."""
        events: list[tuple[str, str]] = []

        async def sleep(delay: float) -> None:
            events.append(("sleep", repr(delay)))

        monkeypatch.setattr(sync_module, "asyncio", SimpleNamespace(sleep=sleep))
        return events

    async def test_snapshot_delay_separates_consecutive_lookups_only(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        token: str,
        waits: list[tuple[str, str]],
    ) -> None:
        users = await _users(user_factory, 3)
        server = SlackServer()
        server.on_request = lambda request: waits.append(
            ("http", form(request)["email"][0])
        )
        server.responses[users[1].email] = body(error("invalid_arguments"))

        await _execute(db_session, server, request_delay=0.5)

        # Not the class default of 1.2 seconds; a failed unit is a lookup too.
        assert waits == [
            ("http", users[0].email),
            ("sleep", "0.5"),
            ("http", users[1].email),
            ("sleep", "0.5"),
            ("http", users[2].email),
        ]

    async def test_zero_delay_never_waits(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        token: str,
        waits: list[tuple[str, str]],
    ) -> None:
        await _users(user_factory, 3)

        await _execute(db_session, SlackServer(), request_delay=0)

        assert waits == []

    async def test_without_run_config_no_delay_is_applied(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        token: str,
        waits: list[tuple[str, str]],
    ) -> None:
        await _users(user_factory, 2)

        await _execute(db_session, SlackServer())

        assert waits == []

    async def test_disabled_mode_never_waits(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        no_token: None,
        waits: list[tuple[str, str]],
    ) -> None:
        await _users(user_factory, 2)

        await _execute(db_session, SlackServer(), request_delay=0.5)

        assert waits == []

    async def test_transport_retries_of_one_lookup_are_not_delayed(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        token: str,
        shared_transport: tuple[SlackServer, AsyncMock],
        waits: list[tuple[str, str]],
    ) -> None:
        server, backoff = shared_transport
        users = await _users(user_factory, 2)
        server.on_request = lambda request: waits.append(
            ("http", form(request)["email"][0])
        )
        server.responses[users[0].email] = sequence(raw(b"", 503), body(error("x")))
        fetcher = SyncSlackAvatars()
        fetcher.config = FetcherRunConfig(
            hard_time_limit_seconds=3600, request_delay=0.5, custom_settings={}
        )
        try:
            await fetcher.execute(db_session)
        finally:
            await fetcher._teardown_http_client()

        assert waits == [
            ("http", users[0].email),
            ("http", users[0].email),
            ("sleep", "0.5"),
            ("http", users[1].email),
        ]
        assert [call.args[0] for call in backoff.await_args_list] == [1.0]


# ---------------------------------------------------------------------------
# Algorithm, values, and metrics
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestValues:
    async def test_selection_excludes_inactive_users_and_bot_accounts(
        self, db_session: AsyncSession, user_factory: UserFactory, token: str
    ) -> None:
        person = await user_factory()
        # The invariant keeps their value NULL; a stale value proves that the
        # run neither looks them up nor writes them.
        inactive = await user_factory(active=False, avatar_url=OTHER_PICTURE)
        bot = await user_factory(bot=True, avatar_url=OTHER_PICTURE)
        server = SlackServer()
        for user in (person, inactive, bot):
            server.responses[user.email] = body(found(PICTURE))

        fetcher = await _execute(db_session, server)

        assert server.emails() == [person.email]
        assert _metrics(fetcher) == (1, 0, 1, 0)
        assert await _stored(db_session, person) == PICTURE
        assert await _stored(db_session, inactive) == OTHER_PICTURE
        assert await _stored(db_session, bot) == OTHER_PICTURE

    async def test_local_and_external_users_are_looked_up(
        self, db_session: AsyncSession, user_factory: UserFactory, token: str
    ) -> None:
        users = sorted(
            [await user_factory(), await user_factory(external_id=uuid.uuid4())],
            key=lambda user: user.id,
        )
        server = SlackServer()

        await _execute(db_session, server)

        assert server.emails() == [user.email for user in users]

    @pytest.mark.parametrize(
        ("stored", "expected_metrics"),
        [
            pytest.param(None, (1, 0, 1, 0), id="set"),
            pytest.param(OTHER_PICTURE, (1, 0, 1, 0), id="changed"),
            pytest.param(PICTURE, (1, 0, 0, 0), id="unchanged"),
        ],
    )
    async def test_picture_is_stored_as_returned(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        token: str,
        stored: str | None,
        expected_metrics: Metrics,
    ) -> None:
        user = await user_factory(avatar_url=stored)
        server = SlackServer()
        server.responses[user.email] = body(load("lookup_uploaded"))

        fetcher = await _execute(db_session, server)

        assert _metrics(fetcher) == expected_metrics
        assert await _stored(db_session, user) == PICTURE

    @pytest.mark.parametrize(
        "response",
        [
            pytest.param(load("lookup_gravatar"), id="gravatar"),
            pytest.param(load("users_not_found"), id="users-not-found"),
            pytest.param(found("https://ca.slack-edge.com/T0-U0-0a1-192"), id="host"),
            pytest.param(found(PICTURE + SURROGATE), id="surrogate-escape"),
            pytest.param(found(PICTURE + "\x00"), id="nul-escape"),
        ],
    )
    @pytest.mark.parametrize(
        ("stored", "expected_metrics"),
        [
            pytest.param(PICTURE, (1, 0, 1, 0), id="cleared"),
            pytest.param(None, (1, 0, 0, 0), id="already-null"),
        ],
    )
    async def test_no_picture_clears_the_stored_url(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        token: str,
        response: dict[str, Any],
        stored: str | None,
        expected_metrics: Metrics,
    ) -> None:
        user = await user_factory(avatar_url=stored)
        server = SlackServer()
        server.responses[user.email] = body(response)

        fetcher = await _execute(db_session, server)

        assert _metrics(fetcher) == expected_metrics
        assert await _stored(db_session, user) is None

    async def test_effective_write_advances_updated_at_only(
        self, db_session: AsyncSession, user_factory: UserFactory, token: str
    ) -> None:
        changed = await user_factory(updated_at=STALE)
        unchanged = await user_factory(avatar_url=PICTURE, updated_at=STALE)
        server = SlackServer()
        for user in (changed, unchanged):
            server.responses[user.email] = body(found(PICTURE))
        columns = [c for c in User.__table__.columns if c.name != "avatar_url"]
        before = {
            row.id: row
            for row in await db_session.execute(
                select(*columns).where(User.id.in_([changed.id, unchanged.id]))
            )
        }

        await _execute(db_session, server)

        after = {
            row.id: row
            for row in await db_session.execute(
                select(*columns).where(User.id.in_([changed.id, unchanged.id]))
            )
        }
        assert after[unchanged.id] == before[unchanged.id]
        assert after[changed.id].updated_at > STALE
        assert {**after[changed.id]._asdict(), "updated_at": STALE} == (
            before[changed.id]._asdict()
        )

    async def test_writes_create_no_identity_audit_event(
        self, db_session: AsyncSession, user_factory: UserFactory, token: str
    ) -> None:
        """The URL is operational metadata (identity-audit-log.md, Service
        Contract, Operational metadata exclusions)."""
        set_user, cleared_user = await _users(user_factory, 2)
        cleared_user.avatar_url = OTHER_PICTURE
        await db_session.flush()
        server = SlackServer()
        server.responses[set_user.email] = body(found(PICTURE))
        events_before = await db_session.scalar(
            select(func.count()).select_from(IdentityAuditEvent)
        )

        fetcher = await _execute(db_session, server)

        assert _metrics(fetcher) == (2, 0, 2, 0)
        assert (
            await db_session.scalar(
                select(func.count()).select_from(IdentityAuditEvent)
            )
            == events_before
        )

    async def test_empty_selection_is_an_empty_run(
        self, db_session: AsyncSession, token: str
    ) -> None:
        server = SlackServer()

        fetcher = await _execute(db_session, server)

        assert server.requests == []
        assert _metrics(fetcher) == (0, 0, 0, 0)


@pytest.mark.integration
class TestDisabledMode:
    async def test_clears_every_stored_url_and_warns(
        self, db_session: AsyncSession, user_factory: UserFactory, no_token: None
    ) -> None:
        pictured = await _users(user_factory, 2, avatar_url=PICTURE)
        plain = await user_factory()

        with capture_logs() as logs:
            fetcher = await _execute(db_session, SlackServer())

        assert _metrics(fetcher) == (3, 0, 2, 0)
        for user in (*pictured, plain):
            assert await _stored(db_session, user) is None
        assert _logged(logs, DISABLED_EVENT) == [
            {
                "event": DISABLED_EVENT,
                "log_level": "warning",
                "fetcher_name": NAME,
                "cleared": 2,
            }
        ]

    async def test_reports_at_info_when_nothing_is_cleared(
        self, db_session: AsyncSession, user_factory: UserFactory, no_token: None
    ) -> None:
        await user_factory()

        with capture_logs() as logs:
            fetcher = await _execute(db_session, SlackServer())

        assert _metrics(fetcher) == (1, 0, 0, 0)
        assert _logged(logs, DISABLED_EVENT) == [
            {
                "event": DISABLED_EVENT,
                "log_level": "info",
                "fetcher_name": NAME,
                "cleared": 0,
            }
        ]

    async def test_failed_run_reports_its_clears_in_its_metrics_only(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        no_token: None,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        await _users(user_factory, 2, avatar_url=PICTURE)
        real = SyncSlackAvatars._write
        calls = 0

        async def second_raises(
            session: AsyncSession, unit: Any, value: str | None
        ) -> bool:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise SoftTimeLimitExceeded()
            return await real(session, unit, value)

        monkeypatch.setattr(SyncSlackAvatars, "_write", staticmethod(second_raises))

        with capture_logs() as logs:
            _, fetcher = await _execute_failing(
                db_session, SlackServer(), SoftTimeLimitExceeded
            )

        assert _metrics(fetcher) == (1, 0, 1, 0)
        assert _logged(logs, DISABLED_EVENT) == []

    async def test_lookup_mode_emits_no_disabled_report(
        self, db_session: AsyncSession, user_factory: UserFactory, token: str
    ) -> None:
        await user_factory(avatar_url=PICTURE)

        with capture_logs() as logs:
            await _execute(db_session, SlackServer())

        assert _logged(logs, DISABLED_EVENT) == []


# ---------------------------------------------------------------------------
# Error Handling
# ---------------------------------------------------------------------------


def _found_with_raw_member(member: str) -> Responder:
    """A found body with an accepted picture whose unconsumed member `extra`
    is the raw JSON text `member`: the body is Invalid response only when
    decoding it fails."""
    document = found(PICTURE)
    document["extra"] = "__RAW__"
    return raw(json_bytes(document).replace(b'"__RAW__"', member.encode()))


_INVALID_BODIES: Final = [
    pytest.param(raw(b"not json"), id="not-json"),
    pytest.param(raw(b"\xff\xfe\x00"), id="not-utf8"),
    pytest.param(raw(b""), id="empty"),
    pytest.param(body([]), id="array-root"),
    pytest.param(body({"user": {}}), id="ok-absent"),
    pytest.param(body({"ok": "true"}), id="ok-string"),
    pytest.param(body({"ok": True}), id="user-absent"),
    pytest.param(body(found(None)), id="image-null"),
    pytest.param(raw(b"\x00\x01", content_encoding="gzip"), id="undecodable-coding"),
    pytest.param(_found_with_raw_member(OVERSIZED_INTEGER), id="integer"),
]


@pytest.mark.integration
class TestUnitFailures:
    async def _assert_unit_failure(
        self,
        db: AsyncSession,
        user_factory: UserFactory,
        responder: Responder,
        cause: str,
    ) -> None:
        # The failing user is looked up first, so the next one proves that
        # the run continues.
        failing, following = await _users(user_factory, 2)
        failing.avatar_url = OTHER_PICTURE
        await db.flush()
        server = SlackServer()
        server.responses[failing.email] = responder
        server.responses[following.email] = body(found(PICTURE))

        with capture_logs() as logs:
            fetcher = await _execute(db, server)

        assert _metrics(fetcher) == (1, 0, 1, 1)
        assert await _stored(db, failing) == OTHER_PICTURE
        assert await _stored(db, following) == PICTURE
        assert _logged(logs, ITEM_FAILED_EVENT) == [
            {
                "event": ITEM_FAILED_EVENT,
                "log_level": "warning",
                "item": str(failing.id),
                "fetcher_name": NAME,
                "cause": cause,
            }
        ]

    @pytest.mark.parametrize("responder", _INVALID_BODIES)
    async def test_invalid_response_fails_only_its_user(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        token: str,
        responder: Responder,
    ) -> None:
        await self._assert_unit_failure(
            db_session, user_factory, responder, "SlackResponseError"
        )

    async def test_nesting_beyond_the_parser_limit_fails_only_its_user(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        token: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        limit_parser_nesting(monkeypatch)
        responder = _found_with_raw_member(NESTED_ARRAY)

        await self._assert_unit_failure(
            db_session, user_factory, responder, "SlackResponseError"
        )

    @pytest.mark.parametrize(
        "document",
        [
            pytest.param(load("invalid_arguments"), id="invalid-arguments"),
            pytest.param({"ok": False}, id="error-absent"),
            pytest.param(error(7), id="error-number"),
        ],
    )
    async def test_lookup_error_fails_only_its_user(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        token: str,
        document: dict[str, Any],
    ) -> None:
        await self._assert_unit_failure(
            db_session, user_factory, body(document), "SlackLookupError"
        )

    async def test_failed_commit_of_a_matched_write_is_rolled_back(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        token: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The first unit's `UPDATE` matches its row and its commit fails: the
        rollback restores the stored value, the unit records a failure and no
        update, and the next unit succeeds. The error carries the address
        and the URL as its parameters, and neither reaches a log."""
        failing, following = await _users(user_factory, 2)
        failing.avatar_url = OTHER_PICTURE
        await db_session.flush()
        failing_id, following_id, email = failing.id, following.id, failing.email
        server = SlackServer()
        for user in (failing, following):
            server.responses[user.email] = body(found(PICTURE))
        real_commit = db_session.commit
        commits = 0

        async def commit() -> None:
            nonlocal commits
            commits += 1
            # The first commit ends the selection; the second is the first
            # unit's write.
            if commits == 2:
                raise OperationalError(
                    'UPDATE "user"',
                    {"email_1": email, "avatar_url": PICTURE},
                    Exception("fictional connection loss"),
                )
            await real_commit()

        monkeypatch.setattr(db_session, "commit", commit)

        with capture_logs() as logs:
            fetcher = await _execute(db_session, server)

        stored = {
            row.id: row.avatar_url
            for row in await db_session.execute(
                select(User.id, User.avatar_url).where(
                    User.id.in_([failing_id, following_id])
                )
            )
        }
        assert _metrics(fetcher) == (1, 0, 1, 1)
        assert stored == {failing_id: OTHER_PICTURE, following_id: PICTURE}
        assert [
            (entry["item"], entry["cause"])
            for entry in _logged(logs, ITEM_FAILED_EVENT)
        ] == [(str(failing_id), "OperationalError")]
        assert email not in repr(logs)
        assert PICTURE not in repr(logs)

    async def test_every_unit_failing_records_each_once(
        self, db_session: AsyncSession, user_factory: UserFactory, token: str
    ) -> None:
        await _users(user_factory, 3)
        server = SlackServer()
        server.response = body(error("invalid_arguments"))

        fetcher = await _execute(db_session, server)

        assert _metrics(fetcher) == (0, 0, 0, 3)


_RUN_FAILURES: Final = [
    pytest.param(
        raising(httpx.ConnectError("fictional")),
        CONNECT_FAILED_MESSAGE,
        httpx.ConnectError,
        id="connect",
    ),
    pytest.param(
        raising(httpx.ReadError("fictional")),
        CONNECT_FAILED_MESSAGE,
        httpx.ReadError,
        id="read",
    ),
    pytest.param(
        raising(httpx.ProxyError("fictional")),
        CONNECT_FAILED_MESSAGE,
        httpx.ProxyError,
        id="proxy",
    ),
    pytest.param(
        raising(httpx.RemoteProtocolError("fictional")),
        CONNECT_FAILED_MESSAGE,
        httpx.RemoteProtocolError,
        id="protocol",
    ),
    pytest.param(
        raising(httpx.ConnectTimeout("fictional")),
        TIMED_OUT_MESSAGE,
        httpx.ConnectTimeout,
        id="connect-timeout",
    ),
    pytest.param(
        raising(httpx.ReadTimeout("fictional")),
        TIMED_OUT_MESSAGE,
        httpx.ReadTimeout,
        id="read-timeout",
    ),
    pytest.param(
        raw(b"", 429, retry_after="30"),
        RATE_LIMITED_MESSAGE,
        httpx.HTTPStatusError,
        id="http-429",
    ),
    pytest.param(
        body(error("ratelimited")), RATE_LIMITED_MESSAGE, None, id="ratelimited"
    ),
    pytest.param(raw(b"", 500), "Slack returned HTTP 500", httpx.HTTPStatusError),
    pytest.param(raw(b"", 404), "Slack returned HTTP 404", httpx.HTTPStatusError),
    pytest.param(raw(b"", 403), "Slack returned HTTP 403", httpx.HTTPStatusError),
    pytest.param(
        raw(b"", 301, location="https://slack.com/x"),
        "Slack returned HTTP 301",
        httpx.HTTPStatusError,
    ),
    pytest.param(body(found(PICTURE), 201), "Slack returned HTTP 201", None),
    pytest.param(raw(b"", 204), "Slack returned HTTP 204", None),
    *[
        pytest.param(
            body(error(code)),
            f"Slack rejected the bot token ({code})",
            None,
            id=f"token-{code}",
        )
        for code in sorted(TOKEN_ERRORS)
    ],
]


@pytest.mark.integration
class TestRunFailures:
    @pytest.mark.parametrize(("responder", "message", "cause"), _RUN_FAILURES)
    async def test_run_fails_and_keeps_every_stored_url(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        token: str,
        responder: Responder,
        message: str,
        cause: type[Exception] | None,
    ) -> None:
        first, failing, later = await _users(user_factory, 3, avatar_url=OTHER_PICTURE)
        server = SlackServer()
        server.responses[first.email] = body(found(PICTURE))
        server.responses[failing.email] = responder
        server.responses[later.email] = body(load("users_not_found"))

        raised, fetcher = await _execute_failing(db_session, server)

        assert str(raised) == message
        if cause is None:
            assert raised.__cause__ is None
        else:
            assert isinstance(raised.__cause__, cause)
        # The earlier unit keeps its commit; the failing and later units
        # record no outcome and keep their values.
        assert _metrics(fetcher) == (1, 0, 1, 0)
        assert server.emails() == [first.email, failing.email]
        assert await _stored(db_session, first) == PICTURE
        assert await _stored(db_session, failing) == OTHER_PICTURE
        assert await _stored(db_session, later) == OTHER_PICTURE

    @pytest.mark.parametrize("code", [500, 404, 429])
    async def test_status_error_text_is_the_status_and_the_fixed_url(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        token: str,
        code: int,
    ) -> None:
        await user_factory()
        server = SlackServer()
        server.response = raw(b'{"ok": false, "error": "secret"}', code)

        raised, _ = await _execute_failing(db_session, server)

        assert str(raised.__cause__) == _status_error_text(code)
        assert "secret" not in str(raised.__cause__)

    async def test_database_error_in_the_selection_propagates(
        self,
        db_session: AsyncSession,
        token: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        failure = OperationalError("SELECT", {}, Exception("fictional failure"))

        async def failing(session: AsyncSession) -> list[Any]:
            raise failure

        monkeypatch.setattr(SyncSlackAvatars, "_select", staticmethod(failing))
        server = SlackServer()

        raised, _ = await _execute_failing(db_session, server, OperationalError)

        assert raised is failure
        assert server.requests == []

    @pytest.mark.parametrize(
        "signal",
        [
            pytest.param(MemoryError(), id="memory"),
            pytest.param(asyncio.CancelledError(), id="cancelled"),
            pytest.param(SoftTimeLimitExceeded(), id="soft-limit"),
        ],
    )
    async def test_whole_run_signals_are_never_caught_per_unit(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        token: str,
        monkeypatch: pytest.MonkeyPatch,
        signal: BaseException,
    ) -> None:
        await _users(user_factory, 2)

        async def raising_write(
            session: AsyncSession, unit: Any, value: str | None
        ) -> bool:
            raise signal

        monkeypatch.setattr(SyncSlackAvatars, "_write", staticmethod(raising_write))

        raised, fetcher = await _execute_failing(
            db_session, SlackServer(), type(signal)
        )

        assert raised is signal
        assert _metrics(fetcher) == (0, 0, 0, 0)


# ---------------------------------------------------------------------------
# Privacy (Security and Privacy; Error Handling)
# ---------------------------------------------------------------------------

_PRIVACY_SCENARIOS: Final = [
    pytest.param(body(load("lookup_uploaded")), None, id="uploaded"),
    pytest.param(body(load("lookup_gravatar")), None, id="gravatar"),
    pytest.param(body(load("users_not_found")), None, id="users-not-found"),
    pytest.param(body(load("invalid_arguments")), None, id="lookup-error"),
    pytest.param(raw(b"not json"), None, id="invalid-response"),
    pytest.param(body(load("invalid_auth")), FetcherError, id="token-rejected"),
    pytest.param(body(load("not_authed")), FetcherError, id="not-authed"),
    pytest.param(raw(b"", 500), FetcherError, id="http-500"),
    pytest.param(
        raw(b"", 302, location="https://slack.com/api/elsewhere"),
        FetcherError,
        id="redirect",
    ),
    pytest.param(raising(httpx.ConnectError("fictional")), FetcherError, id="conn"),
]


@pytest.mark.integration
class TestPrivacy:
    @pytest.mark.parametrize(("responder", "raises"), _PRIVACY_SCENARIOS)
    async def test_no_log_or_error_holds_a_personal_or_response_value(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        token: str,
        caplog: pytest.LogCaptureFixture,
        responder: Responder,
        raises: type[Exception] | None,
    ) -> None:
        user = await user_factory(
            email="distinctive.person@example.com", avatar_url=OTHER_PICTURE
        )
        server = SlackServer()
        server.responses[user.email] = responder
        caplog.set_level("DEBUG")

        with capture_logs() as logs:
            if raises is None:
                await _execute(db_session, server)
                errors = ""
            else:
                raised, _ = await _execute_failing(db_session, server, raises)
                errors = f"{raised}\n{raised.__cause__}\n{raised.__cause__!r}"

        rendered = f"{logs!r}\n{caplog.text}\n{errors}"
        forbidden = {
            user.email,
            "distinctive.person",
            token,
            PICTURE,
            OTHER_PICTURE,
            load("lookup_gravatar")["user"]["profile"]["image_192"],
            *(value for name in FIXTURES for value in unconsumed_strings(load(name))),
            # Every Slack error code, except the token error code of a run
            # that fails because Slack rejected the token.
            *(
                code
                for name in FIXTURES
                if (code := load(name).get("error")) is not None and code not in errors
            ),
        }
        assert [value for value in forbidden if value in rendered] == []


# ---------------------------------------------------------------------------
# run(): finalization and the run report
# ---------------------------------------------------------------------------


class CommittedRun:
    """Commits the users and the run of one `run()` test; see
    `committed_run`."""

    def __init__(
        self,
        factory: async_sessionmaker[AsyncSession],
        monkeypatch: pytest.MonkeyPatch,
        fetcher_name: str,
    ) -> None:
        self.factory = factory
        self.monkeypatch = monkeypatch
        self.fetcher_name = fetcher_name
        self.seeded: list[uuid.UUID] = []

    async def __call__(
        self, server: SlackServer, stored: Sequence[str | None]
    ) -> uuid.UUID:
        """Commit one active user per stored URL, in ascending `id` order,
        and a `running` FetcherRun; return the run's id."""
        self.monkeypatch.setattr(
            base_fetcher_module,
            "create_http_client",
            lambda name, **options: server.client(),
        )
        prefix = uuid.uuid4().hex[:8]
        async with self.factory() as session:
            for n, url in enumerate(stored):
                user = User(
                    username=f"run-{prefix}-{n}",
                    email=f"run-{prefix}-{n}@example.com",
                    password_hash="$2b$12$" + "a" * 53,
                    avatar_url=url,
                )
                session.add(user)
                await session.flush()
                self.seeded.append(user.id)
            session.add(
                FetcherConfig(
                    fetcher_name=self.fetcher_name,
                    enabled=True,
                    run_timeout=3600,
                    request_delay=0,
                    custom_settings={},
                )
            )
            run = FetcherRun(
                fetcher_name=self.fetcher_name,
                started_at=datetime.now(UTC),
                status="running",
                triggered_by="schedule",
            )
            session.add(run)
            await session.commit()
            return run.id

    async def urls(self) -> list[str | None]:
        """The committed URL of each seeded user, in seeding order."""
        async with self.factory() as session:
            rows = await session.execute(
                select(User.id, User.avatar_url).where(User.id.in_(self.seeded))
            )
            stored = {row.id: row.avatar_url for row in rows}
        return [stored[user_id] for user_id in self.seeded]


@pytest.fixture
async def committed_run(
    real_session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[CommittedRun]:
    """Route `run()` and commit its users and run through `CommittedRun`.

    `run()` opens its own sessions through `base_fetcher`'s
    `async_session_factory` and creates its HTTP client through
    `create_http_client`; both are redirected here. Every committed row is
    deleted at teardown. A seeded user's UUIDv7 grows with its insertion, so
    the seeding order is the selection order.
    """
    monkeypatch.setattr(
        base_fetcher_module, "async_session_factory", real_session_factory
    )
    run = CommittedRun(
        real_session_factory, monkeypatch, f"test_slack_run_{uuid.uuid4().hex[:12]}"
    )
    try:
        yield run
    finally:
        async with real_session_factory() as session:
            await session.execute(delete(User).where(User.id.in_(run.seeded)))
            await session.execute(
                delete(FetcherRun).where(FetcherRun.fetcher_name == run.fetcher_name)
            )
            await session.execute(
                delete(FetcherConfig).where(
                    FetcherConfig.fetcher_name == run.fetcher_name
                )
            )
            await session.commit()


def _run_config() -> FetcherRunConfig:
    return FetcherRunConfig(
        hard_time_limit_seconds=3600, request_delay=0, custom_settings={}
    )


async def _finalized(
    real_session_factory: async_sessionmaker[AsyncSession], run_id: uuid.UUID
) -> FetcherRun:
    async with real_session_factory() as session:
        run = await session.get(FetcherRun, run_id)
        assert run is not None
        return run


def _run_metrics(run: FetcherRun) -> Metrics:
    return (run.items_succeeded, run.items_created, run.items_updated, run.items_failed)


@pytest.mark.integration
class TestRunLifecycle:
    async def test_lookups_are_committed_and_the_run_succeeds(
        self,
        committed_run: CommittedRun,
        real_session_factory: async_sessionmaker[AsyncSession],
        token: str,
    ) -> None:
        server = SlackServer()
        server.response = body(found(PICTURE))
        run_id = await committed_run(server, [None, PICTURE])

        await SyncSlackAvatars().run(run_id=run_id, config=_run_config())

        run = await _finalized(real_session_factory, run_id)
        assert run.status == "success"
        assert _run_metrics(run) == (2, 0, 1, 0)
        assert (run.error_message, run.error_detail, run.error_traceback) == (
            None,
            None,
            None,
        )
        assert await committed_run.urls() == [PICTURE] * 2

    async def test_some_unit_failures_make_the_run_partial(
        self,
        committed_run: CommittedRun,
        real_session_factory: async_sessionmaker[AsyncSession],
        token: str,
    ) -> None:
        server = SlackServer()
        server.response = sequence(body(error("invalid_arguments")), body(found()))
        # The successful unit finds its picture already stored.
        run_id = await committed_run(server, [None, PICTURE])

        await SyncSlackAvatars().run(run_id=run_id, config=_run_config())

        run = await _finalized(real_session_factory, run_id)
        assert run.status == "partial"
        assert _run_metrics(run) == (1, 0, 0, 1)

    async def test_every_unit_failing_fails_the_run_without_an_exception(
        self,
        committed_run: CommittedRun,
        real_session_factory: async_sessionmaker[AsyncSession],
        token: str,
    ) -> None:
        server = SlackServer()
        server.response = raw(b"not json")
        run_id = await committed_run(server, [PICTURE, PICTURE])

        await SyncSlackAvatars().run(run_id=run_id, config=_run_config())

        run = await _finalized(real_session_factory, run_id)
        assert run.status == "failure"
        assert run.error_message == "All 2 items failed"
        assert (run.error_detail, run.error_traceback) == (None, None)
        assert _run_metrics(run) == (0, 0, 0, 2)
        assert await committed_run.urls() == [PICTURE] * 2

    async def test_empty_selection_is_a_success(
        self,
        committed_run: CommittedRun,
        real_session_factory: async_sessionmaker[AsyncSession],
        token: str,
    ) -> None:
        run_id = await committed_run(SlackServer(), [])

        await SyncSlackAvatars().run(run_id=run_id, config=_run_config())

        run = await _finalized(real_session_factory, run_id)
        assert run.status == "success"
        assert _run_metrics(run) == (0, 0, 0, 0)

    async def test_status_failure_is_finalized_with_its_chained_detail(
        self,
        committed_run: CommittedRun,
        real_session_factory: async_sessionmaker[AsyncSession],
        token: str,
    ) -> None:
        server = SlackServer()
        server.response = sequence(body(found()), raw(b"", 500))
        run_id = await committed_run(server, [None, PICTURE])

        with pytest.raises(FetcherError, match=r"^Slack returned HTTP 500$"):
            await SyncSlackAvatars().run(run_id=run_id, config=_run_config())

        run = await _finalized(real_session_factory, run_id)
        assert run.status == "failure"
        assert run.error_message == "Slack returned HTTP 500"
        assert run.error_detail == _status_error_text(500)
        assert _run_metrics(run) == (1, 0, 1, 0)
        assert await committed_run.urls() == [PICTURE] * 2

    async def test_rejected_token_fails_every_run_and_removes_no_url(
        self,
        committed_run: CommittedRun,
        real_session_factory: async_sessionmaker[AsyncSession],
        token: str,
    ) -> None:
        server = SlackServer()
        server.response = body(error("token_revoked"))
        run_id = await committed_run(server, [PICTURE, PICTURE])

        with pytest.raises(FetcherError):
            await SyncSlackAvatars().run(run_id=run_id, config=_run_config())

        run = await _finalized(real_session_factory, run_id)
        assert run.status == "failure"
        assert run.error_message == "Slack rejected the bot token (token_revoked)"
        assert run.error_detail is None
        assert _run_metrics(run) == (0, 0, 0, 0)
        assert await committed_run.urls() == [PICTURE] * 2

    async def test_disabled_run_reports_its_clears_as_updates(
        self,
        committed_run: CommittedRun,
        real_session_factory: async_sessionmaker[AsyncSession],
        no_token: None,
    ) -> None:
        server = SlackServer()
        run_id = await committed_run(server, [PICTURE, None, PICTURE])

        with capture_logs() as logs:
            await SyncSlackAvatars().run(run_id=run_id, config=_run_config())

        run = await _finalized(real_session_factory, run_id)
        assert run.status == "success"
        assert _run_metrics(run) == (3, 0, 2, 0)
        assert server.requests == []
        assert await committed_run.urls() == [None] * 3
        assert [
            (entry["log_level"], entry["cleared"])
            for entry in _logged(logs, DISABLED_EVENT)
        ] == [("warning", 2)]

    async def test_database_failure_in_the_selection_uses_the_generic_message(
        self,
        committed_run: CommittedRun,
        real_session_factory: async_sessionmaker[AsyncSession],
        token: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        async def failing(session: AsyncSession) -> list[Any]:
            raise OperationalError("SELECT", {}, Exception("fictional failure"))

        monkeypatch.setattr(SyncSlackAvatars, "_select", staticmethod(failing))
        run_id = await committed_run(SlackServer(), [PICTURE])

        with pytest.raises(OperationalError):
            await SyncSlackAvatars().run(run_id=run_id, config=_run_config())

        run = await _finalized(real_session_factory, run_id)
        assert run.status == "failure"
        assert run.error_message == "Unexpected error"


# ---------------------------------------------------------------------------
# Registration, configuration bootstrap, and the RedBeat entry
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRegistration:
    def test_discovery_registers_the_fetcher(self) -> None:
        assert FETCHER_REGISTRY[NAME] is SyncSlackAvatars

    def test_properties_match_the_specification(self) -> None:
        assert SyncSlackAvatars.name == NAME
        assert SyncSlackAvatars.description == (
            "Sync user profile picture URLs from Slack"
        )
        assert SyncSlackAvatars.default_schedule == "30 6 * * *"
        assert SyncSlackAvatars.default_request_delay == 1.2
        assert SyncSlackAvatars.participates_in_catch_up is False
        assert SyncSlackAvatars.Settings is None
        assert SyncSlackAvatars.queue is None
        assert SyncSlackAvatars.http_client_options == {"retry_non_idempotent": True}

    def test_class_name_is_derived_from_the_fetcher_name(self) -> None:
        derived = "".join(part.capitalize() for part in NAME.split("_"))

        assert derived == SyncSlackAvatars.__name__ == "SyncSlackAvatars"

    def test_fetcher_does_not_participate_in_catch_up(self) -> None:
        assert NAME not in get_catch_up_fetchers()

    def test_discovery_module_imports_the_fetcher_module(self) -> None:
        source = Path(fetcher_discovery.__file__).read_text(encoding="utf-8")
        lines = [line.split("#")[0].strip() for line in source.splitlines()]

        assert "import app.services.identity.sync_slack_avatars" in lines


@pytest.mark.integration
class TestBootstrapAndSchedule:
    async def test_bootstrap_creates_the_configuration_from_the_class(
        self, db_session: AsyncSession
    ) -> None:
        assert await db_session.get(FetcherConfig, NAME) is None

        await bootstrap_fetcher_configs(db_session)

        config = await db_session.get(FetcherConfig, NAME)
        assert config is not None
        assert config.enabled is True
        assert config.schedule_override is None
        assert config.run_timeout == 3600
        assert config.request_delay == 1.2
        assert config.custom_settings == {}

    async def test_reconciliation_writes_the_daily_entry(
        self, db_session: AsyncSession, celery_test_app: Celery
    ) -> None:
        await bootstrap_fetcher_configs(db_session)

        await reconcile_beat_schedule(db_session, celery_test_app)

        key = RedBeatSchedulerEntry.generate_key(celery_test_app, NAME)
        entry = RedBeatSchedulerEntry.from_key(key, app=celery_test_app)
        assert entry.task == "run_fetcher"
        assert entry.kwargs == {"fetcher_name": NAME, "triggered_by": "schedule"}
        # 30 6 * * *
        assert entry.schedule.minute == {30}
        assert entry.schedule.hour == {6}
        assert entry.schedule.day_of_month == set(range(1, 32))
        assert entry.schedule.month_of_year == set(range(1, 13))
        assert entry.schedule.day_of_week == set(range(7))
        assert "queue" not in entry.options
