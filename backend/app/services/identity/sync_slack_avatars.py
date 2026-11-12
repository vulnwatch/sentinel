"""`sync_slack_avatars`: the URLs of the pictures that users uploaded to
Slack.

Implements docs/features/identity/user-avatars.md (Slack Integration;
Fetcher: `sync_slack_avatars`; Concurrency) on the `BaseFetcher` contract of
docs/features/platform/fetcher-infrastructure.md. Each run:

1. is in disabled mode when `SLACK_BOT_TOKEN` is empty or unset: it sends no
   request, and every selected user has no picture;
2. reads the `id` and `email` of every active user who is not a bot account,
   in ascending `id` order, in one short transaction;
3. in lookup mode, sends one `POST users.lookupByEmail` per user, with no
   transaction open and the run's request delay between lookups, and
   classifies the response (`classify_lookup()`);
4. writes the resulting URL, or `NULL`, in a transaction of its own with a
   conditional `UPDATE` that matches only while the user is still active,
   not a bot account, and has the selected address.

The bot token is read only here and used only for that lookup. No value of a
Slack response other than an accepted picture URL is kept, and none is
logged: the per-user warnings carry the user's UUID and an exception class
name, and the only response value in an error field is the token error code
of a run that fails because Slack rejected the token.
"""

from __future__ import annotations

import asyncio
import enum
from dataclasses import dataclass
from typing import Any, ClassVar, Final
from urllib.parse import urlsplit
from uuid import UUID

import httpx
import structlog
from sqlalchemy import select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.user import User
from app.services.base_fetcher import BaseFetcher, FetcherError
from app.services.json_decoding import decode_json

logger = structlog.get_logger(__name__)

LOOKUP_URL: Final = "https://slack.com/api/users.lookupByEmail"
"""The only Slack method the bot token is used for (Lookup Request)."""

PICTURE_HOST: Final = "avatars.slack-edge.com"
"""The host of the pictures that people upload to Slack (Accepted Picture
URL)."""

MAX_PICTURE_URL_LENGTH: Final = 2048
"""The length of `User.avatar_url` (docs/data-model.md, User)."""

TOKEN_ERRORS: Final = frozenset(
    {
        "not_authed",
        "invalid_auth",
        "account_inactive",
        "token_revoked",
        "token_expired",
        "missing_scope",
        "not_allowed_token_type",
    }
)
"""The Slack error codes of a token that Slack rejects (Response Contract)."""

CONNECT_FAILED_MESSAGE: Final = "Failed to connect to Slack"
TIMED_OUT_MESSAGE: Final = "Slack request timed out"
RATE_LIMITED_MESSAGE: Final = "Slack rate limit reached"

ITEM_FAILED_EVENT: Final = "fetcher_item_failed"
DISABLED_EVENT: Final = "slack_avatar_sync_disabled"

_TRANSPORT_FAILURES: Final = (
    httpx.NetworkError,
    httpx.ProxyError,
    httpx.RemoteProtocolError,
)


class Outcome(enum.Enum):
    """The outcome of one lookup (Response Contract)."""

    PICTURE = enum.auto()
    NO_PICTURE = enum.auto()
    TOKEN_REJECTED = enum.auto()
    RATE_LIMITED = enum.auto()
    LOOKUP_ERROR = enum.auto()
    INVALID_RESPONSE = enum.auto()


@dataclass(frozen=True, slots=True)
class Lookup:
    """A classified lookup. `picture_url` is set for `PICTURE` only, and
    `token_error`, one of `TOKEN_ERRORS`, for `TOKEN_REJECTED` only."""

    outcome: Outcome
    picture_url: str | None = None
    token_error: str | None = None


class SlackResponseError(Exception):
    """The outcome Invalid response. Fixed message, no response value."""

    def __init__(self) -> None:
        super().__init__("Slack returned an invalid lookup response")


class SlackLookupError(Exception):
    """The outcome Lookup error. Fixed message, no response value."""

    def __init__(self) -> None:
        super().__init__("Slack reported a lookup error")


def accepted_picture_url(value: str) -> bool:
    """Whether `image_192` is an accepted picture URL: at most 2048
    printable ASCII characters (U+0021 to U+007E), an absolute `https` URL
    whose host is exactly `avatars.slack-edge.com`, without user
    information, port, or fragment. Path and query are not restricted.
    Pure."""
    if len(value) > MAX_PICTURE_URL_LENGTH:
        return False
    if not all("\x21" <= character <= "\x7e" for character in value):
        return False
    if "#" in value:
        return False
    try:
        parts = urlsplit(value)
    except ValueError:
        return False
    return (
        value.startswith("https://")
        and parts.scheme == "https"
        and parts.netloc == PICTURE_HOST
    )


def classify_lookup(document: object) -> Lookup:
    """Classify a decoded HTTP 200 body of `users.lookupByEmail` (Response
    Contract). Reads only `ok`, `error`, and `user.profile.image_192`. Pure."""
    if not isinstance(document, dict):
        return Lookup(Outcome.INVALID_RESPONSE)
    ok = document.get("ok")
    if ok is True:
        user = document.get("user")
        profile = user.get("profile") if isinstance(user, dict) else None
        image = profile.get("image_192") if isinstance(profile, dict) else None
        if not isinstance(image, str):
            return Lookup(Outcome.INVALID_RESPONSE)
        if accepted_picture_url(image):
            return Lookup(Outcome.PICTURE, picture_url=image)
        return Lookup(Outcome.NO_PICTURE)
    if ok is not False:
        return Lookup(Outcome.INVALID_RESPONSE)
    error = document.get("error")
    if not isinstance(error, str):
        return Lookup(Outcome.LOOKUP_ERROR)
    if error == "users_not_found":
        return Lookup(Outcome.NO_PICTURE)
    if error in TOKEN_ERRORS:
        return Lookup(Outcome.TOKEN_REJECTED, token_error=error)
    if error == "ratelimited":
        return Lookup(Outcome.RATE_LIMITED)
    return Lookup(Outcome.LOOKUP_ERROR)


@dataclass(frozen=True, slots=True)
class _Selected:
    id: UUID
    email: str


class SyncSlackAvatars(BaseFetcher):
    """Sync the URLs of the pictures that users uploaded to Slack."""

    name = "sync_slack_avatars"
    description = "Sync user profile picture URLs from Slack"
    default_schedule = "30 6 * * *"
    default_request_delay = 1.2
    # The lookup is read-only despite its `POST` (Lookup Request).
    http_client_options: ClassVar[dict[str, Any]] = {"retry_non_idempotent": True}

    async def execute(self, session: AsyncSession) -> None:
        token = settings.slack_bot_token.get_secret_value()
        selected = await self._select(session)
        request_delay = self.config.request_delay if self.config is not None else 0.0
        cleared = 0
        for index, unit in enumerate(selected):
            if token:
                if index > 0 and request_delay > 0:
                    await asyncio.sleep(request_delay)
                try:
                    value = await self._lookup(token, unit.email)
                except (SlackResponseError, SlackLookupError) as e:
                    self._unit_failed(unit, e)
                    continue
            else:
                value = None
            try:
                changed = await self._write(session, unit, value)
            except SQLAlchemyError as e:
                await session.rollback()
                self._unit_failed(unit, e)
                continue
            self.record_succeeded()
            if changed:
                self.record_updated()
                if value is None:
                    cleared += 1
        if not token:
            log = logger.warning if cleared else logger.info
            log(DISABLED_EVENT, fetcher_name=self.name, cleared=cleared)

    @staticmethod
    async def _select(session: AsyncSession) -> list[_Selected]:
        """Algorithm step 2: one short read-only transaction."""
        rows = await session.execute(
            select(User.id, User.email)
            .where(User.active.is_(True), User.bot.is_(False))
            .order_by(User.id)
        )
        selected = [_Selected(id=row.id, email=row.email) for row in rows]
        await session.commit()
        return selected

    async def _lookup(self, token: str, email: str) -> str | None:
        """Algorithm steps 3-4: the accepted URL, or `None` for No picture.

        Raises `FetcherError` for a run failure, and `SlackResponseError` or
        `SlackLookupError` for a unit failure (Error Handling).
        """
        try:
            response = await self.http_client.post(
                LOOKUP_URL,
                data={"email": email},
                headers={"Authorization": f"Bearer {token}"},
            )
        except httpx.DecodingError:
            # An undecodable content coding is a response, not a transport
            # failure.
            raise SlackResponseError() from None
        except httpx.TimeoutException as e:
            raise FetcherError(TIMED_OUT_MESSAGE) from e
        except _TRANSPORT_FAILURES as e:
            raise FetcherError(CONNECT_FAILED_MESSAGE) from e
        if response.status_code == 429:
            raise FetcherError(RATE_LIMITED_MESSAGE) from _status_error(response)
        if response.status_code != 200:
            raise FetcherError(
                f"Slack returned HTTP {response.status_code}"
            ) from _status_error(response)
        try:
            document = decode_json(response.content)
        except ValueError:
            raise SlackResponseError() from None
        lookup = classify_lookup(document)
        match lookup.outcome:
            case Outcome.PICTURE:
                return lookup.picture_url
            case Outcome.NO_PICTURE:
                return None
            case Outcome.TOKEN_REJECTED:
                raise FetcherError(
                    f"Slack rejected the bot token ({lookup.token_error})"
                )
            case Outcome.RATE_LIMITED:
                raise FetcherError(RATE_LIMITED_MESSAGE)
            case Outcome.LOOKUP_ERROR:
                raise SlackLookupError()
            case Outcome.INVALID_RESPONSE:
                raise SlackResponseError()

    @staticmethod
    async def _write(session: AsyncSession, unit: _Selected, value: str | None) -> bool:
        """Algorithm step 5: set `avatar_url` to `value` in a transaction of
        its own, only while the user is still active, not a bot account, and
        has the selected address, and only when the stored value differs
        (`NULL` differs from every URL). Locks only that User row. Returns
        whether the row changed."""
        result = await session.execute(
            update(User)
            .where(
                User.id == unit.id,
                User.active.is_(True),
                User.bot.is_(False),
                User.email == unit.email,
                User.avatar_url.is_distinct_from(value),
            )
            .values(avatar_url=value)
            .returning(User.id)
            .execution_options(synchronize_session=False)
        )
        changed = result.scalar_one_or_none() is not None
        await session.commit()
        return changed

    def _unit_failed(self, unit: _Selected, exception: Exception) -> None:
        """A unit failure: the stored value is kept (Error Handling)."""
        self.record_failed()
        logger.warning(
            ITEM_FAILED_EVENT,
            item=str(unit.id),
            fetcher_name=self.name,
            cause=type(exception).__name__,
        )


def _status_error(response: httpx.Response) -> httpx.HTTPStatusError | None:
    """The `httpx.HTTPStatusError` that `httpx` reports for `response`, or
    `None` for a 2xx status, which it does not report. Its text holds the
    status with its reason phrase and the fixed URL, plus the `Location`
    header of a redirect, never a body or an email address."""
    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as e:
        return e
    return None
