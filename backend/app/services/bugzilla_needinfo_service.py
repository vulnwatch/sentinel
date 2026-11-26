"""Count of open SUSE Bugzilla needinfo requests to the security team.

Implements docs/features/integrations/bugzilla-needinfo-count.md:

- Bugzilla Search: one fixed JSON-RPC `Bug.search` (`POST
  https://bugzilla.suse.com/jsonrpc.cgi`) through the shared HTTP client
  with `retry_non_idempotent=True`, the optional `BUGZILLA_API_KEY` only as
  the member `Bugzilla_api_key` of `params[0]`, and a 10-second deadline
  that includes the transport retries. The response is classified into
  exactly one outcome of the Response Contract; the bug IDs are validated
  and discarded.
- Cache and Read Coordination: the outcome of the latest read in
  `sentinel:bugzilla_needinfo_count` (60 seconds after a Count, 10 seconds
  after a failed read), at most one read at a time across API processes
  through `sentinel:bugzilla_needinfo_count:lock`, and a direct read from
  Bugzilla when Redis fails before the wait.
- Logging: `bugzilla_needinfo_read_failed`,
  `bugzilla_needinfo_api_key_rejected`, and
  `bugzilla_needinfo_cache_failed`. No record, Redis value, or exception
  message carries the API key, a bug ID, or text received from Bugzilla.

The module reads no application data and opens no database session.
"""

from __future__ import annotations

import asyncio
import json
from collections import Counter
from contextlib import suppress
from dataclasses import dataclass
from typing import Any, Final, Literal

import httpx
import redis.asyncio as redis_asyncio
import structlog
from redis.asyncio.retry import Retry
from redis.backoff import NoBackoff
from redis.exceptions import RedisError

from app.config import settings
from app.core.exceptions import ServiceError
from app.services.http_client import create_http_client
from app.services.json_decoding import decode_json

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants (bugzilla-needinfo-count.md, Search Request; Search URL; Redis
# Keys; get_needinfo_count())
# ---------------------------------------------------------------------------

JSONRPC_URL: Final = "https://bugzilla.suse.com/jsonrpc.cgi"
SEARCH_URL: Final = (
    "https://bugzilla.suse.com/buglist.cgi?bug_status=UNCONFIRMED"
    "&bug_status=NEW&bug_status=CONFIRMED&bug_status=IN_PROGRESS"
    "&bug_status=REOPENED&f1=flagtypes.name&o1=equals&v1=needinfo%3F"
    "&f2=requestees.login_name&o2=equals&v2=security-team%40suse.de"
    "&query_format=advanced"
)
"""The Bugzilla web search with the conditions of the count."""

HTTP_CLIENT_NAME: Final = "bugzilla_needinfo_count"

OPEN_STATUSES: Final = ("UNCONFIRMED", "NEW", "CONFIRMED", "IN_PROGRESS", "REOPENED")
SECURITY_TEAM_REQUESTEE: Final = "security-team@suse.de"
API_KEY_MEMBER: Final = "Bugzilla_api_key"
API_KEY_REJECTED_CODE: Final = 306
"""The JSON-RPC `error.code` of an invalid or revoked API key."""

READ_DEADLINE_SECONDS: Final = 10.0

CACHE_KEY: Final = "sentinel:bugzilla_needinfo_count"
LOCK_KEY: Final = "sentinel:bugzilla_needinfo_count:lock"
COUNT_TTL_SECONDS: Final = 60
FAILURE_TTL_SECONDS: Final = 10
LOCK_TTL_SECONDS: Final = 15
WAIT_SECONDS: Final = 15.0
"""How long a caller waits for the outcome of another read: the lock expiry."""
POLL_INTERVAL_SECONDS: Final = 0.25
_REDIS_OPERATION_TIMEOUT_SECONDS: Final = 2.0

READ_FAILED_EVENT: Final = "bugzilla_needinfo_read_failed"
API_KEY_REJECTED_EVENT: Final = "bugzilla_needinfo_api_key_rejected"
CACHE_FAILED_EVENT: Final = "bugzilla_needinfo_cache_failed"

UNAVAILABLE_MESSAGE: Final = "No valid count could be obtained from SUSE Bugzilla."
"""The fixed message of `BugzillaUnavailableError` and of its `503` detail."""


# ---------------------------------------------------------------------------
# Results and exceptions
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class NeedinfoCount:
    """The count, whether the read that produced it was authenticated, and
    the Search URL."""

    count: int
    authenticated: bool
    url: str


class BugzillaNeedinfoServiceError(ServiceError):
    """Base of this module's exceptions."""


class BugzillaUnavailableError(BugzillaNeedinfoServiceError):
    """No valid count from SUSE Bugzilla is available (`503
    BUGZILLA_UNAVAILABLE`). The message is fixed."""

    def __init__(self) -> None:
        super().__init__(UNAVAILABLE_MESSAGE)


FailureReason = Literal[
    "http_status", "bugzilla_error", "invalid_response", "transport", "api_key_rejected"
]


@dataclass(frozen=True, slots=True)
class SearchCount:
    """The outcome Count: the number of matching bugs."""

    count: int
    authenticated: bool


@dataclass(frozen=True, slots=True)
class SearchFailure:
    """A failed read: its outcome and the bounded fields of its log record."""

    reason: FailureReason
    http_status: int | None = None
    error_code: int | None = None


SearchOutcome = SearchCount | SearchFailure

_CACHED_UNAVAILABLE: Final = "unavailable"
CachedOutcome = SearchCount | Literal["unavailable"]

_INVALID: Final = SearchFailure("invalid_response")


# ---------------------------------------------------------------------------
# Strict JSON decoding (docs/conventions.md, External JSON Decoding)
# ---------------------------------------------------------------------------


class _JSONObject(dict[str, Any]):
    """A JSON object that remembers its repeated member names."""

    __slots__ = ("duplicated",)

    def __init__(self, pairs: list[tuple[str, Any]]) -> None:
        super().__init__(pairs)
        counts = Counter(name for name, _ in pairs) if len(self) < len(pairs) else {}
        self.duplicated: frozenset[str] = frozenset(
            name for name, count in counts.items() if count > 1
        )


def _reject_constant(_: str) -> Any:
    """Reject the non-standard `NaN`, `Infinity`, and `-Infinity`."""
    raise ValueError("non-standard JSON constant")


def _decode_strict(content: bytes) -> Any:
    """Decode exactly one JSON text from strict UTF-8 without a byte order
    mark (decoding a `str` rejects one). Raises `ValueError` otherwise,
    including for a non-standard constant."""
    text = content.decode("utf-8")
    return decode_json(
        text, object_pairs_hook=_JSONObject, parse_constant=_reject_constant
    )


def _is_integer(value: Any) -> bool:
    """A JSON integer: not a boolean, and not a number with a fraction or
    exponent (those decode as `float`)."""
    return type(value) is int


# ---------------------------------------------------------------------------
# Bugzilla Search
# ---------------------------------------------------------------------------


def search_request_body(api_key: str) -> dict[str, Any]:
    """The JSON-RPC body of the fixed search; `api_key` is added as
    `Bugzilla_api_key` only when non-empty."""
    params: dict[str, Any] = {
        "include_fields": ["id"],
        "bug_status": list(OPEN_STATUSES),
        "f1": "flagtypes.name",
        "o1": "equals",
        "v1": "needinfo?",
        "f2": "requestees.login_name",
        "o2": "equals",
        "v2": SECURITY_TEAM_REQUESTEE,
        "limit": 0,
    }
    if api_key:
        params[API_KEY_MEMBER] = api_key
    return {"method": "Bug.search", "params": [params], "id": 1}


def classify_search_body(content: bytes, *, authenticated: bool) -> SearchOutcome:
    """Classify the body of an HTTP 200 answer (Response Contract).

    Category: pure validation. Never raises for any input; the body and the
    IDs are not retained.
    """
    try:
        document = _decode_strict(content)
    except ValueError:
        # Invalid UTF-8, a byte order mark, not exactly one JSON text, a
        # non-standard constant, the integer digit limit, or nesting beyond
        # the parser's limit.
        return _INVALID
    if not isinstance(document, _JSONObject):
        return _INVALID
    if document.duplicated & {"error", "result"} or "error" not in document:
        return _INVALID
    error = document["error"]
    if error is None:
        return _classify_result(document.get("result"), authenticated=authenticated)
    if isinstance(error, dict) and _is_integer(error.get("code")):
        code: int = error["code"]
        if authenticated and code == API_KEY_REJECTED_CODE:
            return SearchFailure("api_key_rejected")
        return SearchFailure("bugzilla_error", error_code=code)
    return _INVALID


def _classify_result(result: Any, *, authenticated: bool) -> SearchOutcome:
    if not isinstance(result, _JSONObject) or "bugs" in result.duplicated:
        return _INVALID
    bugs = result.get("bugs")
    if not isinstance(bugs, list):
        return _INVALID
    for bug in bugs:
        if not isinstance(bug, dict):
            return _INVALID
        bug_id = bug.get("id")
        if type(bug_id) is not int or bug_id < 1:
            return _INVALID
    return SearchCount(count=len(bugs), authenticated=authenticated)


async def read_from_bugzilla(api_key: str) -> SearchOutcome:
    """Read the count from Bugzilla once and log a failed read.

    Category: external I/O. The read, including transport retries, is
    abandoned after `READ_DEADLINE_SECONDS` with the outcome Transport
    failure. A failure to create the HTTP client (`TLSConfigurationError`,
    or the `ValueError` of an invalid proxy variable) propagates.
    """
    authenticated = bool(api_key)
    async with create_http_client(
        HTTP_CLIENT_NAME, retry_non_idempotent=True
    ) as client:
        try:
            async with asyncio.timeout(READ_DEADLINE_SECONDS):
                outcome = await _search(client, api_key, authenticated=authenticated)
        except TimeoutError:
            outcome = SearchFailure("transport")
    if isinstance(outcome, SearchFailure):
        _log_read_failure(outcome, authenticated=authenticated)
    return outcome


async def _search(
    client: httpx.AsyncClient, api_key: str, *, authenticated: bool
) -> SearchOutcome:
    request = client.build_request(
        "POST", JSONRPC_URL, json=search_request_body(api_key)
    )
    try:
        response = await client.send(request, stream=True)
    except httpx.TransportError:
        # Connection, timeout, proxy, or protocol error after the transport
        # retries. The exception is discarded: it can render the request.
        return SearchFailure("transport")
    try:
        if response.status_code != 200:
            return SearchFailure("http_status", http_status=response.status_code)
        try:
            content = await response.aread()
        except httpx.DecodingError:
            return _INVALID
        except httpx.TransportError:
            return SearchFailure("transport")
    finally:
        await response.aclose()
    return classify_search_body(content, authenticated=authenticated)


def _log_read_failure(outcome: SearchFailure, *, authenticated: bool) -> None:
    if outcome.reason == "api_key_rejected":
        logger.error(API_KEY_REJECTED_EVENT)
        return
    fields: dict[str, Any] = {"reason": outcome.reason, "authenticated": authenticated}
    if outcome.reason == "http_status":
        fields["http_status"] = outcome.http_status
    elif outcome.reason == "bugzilla_error":
        fields["error_code"] = outcome.error_code
    logger.warning(READ_FAILED_EVENT, **fields)


# ---------------------------------------------------------------------------
# Cache values (Redis Keys)
# ---------------------------------------------------------------------------


def encode_cached(outcome: SearchOutcome) -> str:
    """The cache value written after a read."""
    if isinstance(outcome, SearchCount):
        value: dict[str, Any] = {
            "outcome": "count",
            "count": outcome.count,
            "authenticated": outcome.authenticated,
        }
    else:
        value = {"outcome": _CACHED_UNAVAILABLE}
    return json.dumps(value, separators=(",", ":"))


def decode_cached(raw: bytes | str | None) -> CachedOutcome | None:
    """The cached outcome, or `None` for an absent value or one that is not
    exactly one of the documented forms. Never raises."""
    if raw is None:
        return None
    try:
        document = _decode_strict(raw.encode("utf-8") if isinstance(raw, str) else raw)
    except ValueError:
        return None
    if not isinstance(document, _JSONObject) or document.duplicated:
        return None
    if set(document) == {"outcome"} and document["outcome"] == _CACHED_UNAVAILABLE:
        return _CACHED_UNAVAILABLE
    if set(document) != {"outcome", "count", "authenticated"}:
        return None
    count = document["count"]
    authenticated = document["authenticated"]
    if (
        document["outcome"] != "count"
        or not _is_integer(count)
        or count < 0
        or type(authenticated) is not bool
    ):
        return None
    return SearchCount(count=count, authenticated=authenticated)


def _expiry(outcome: SearchOutcome) -> int:
    return (
        COUNT_TTL_SECONDS if isinstance(outcome, SearchCount) else FAILURE_TTL_SECONDS
    )


# ---------------------------------------------------------------------------
# Redis boundary
# ---------------------------------------------------------------------------


def get_bugzilla_needinfo_redis_url() -> str:
    """Return the Redis URL of the cache and the lock.

    Performs no I/O — returns the configured `REDIS_URL`. Extracted so
    tests can redirect the operations (docs/features/platform/
    testing-strategy.md, Redis Strategy).
    """
    return settings.redis_url


def _new_redis_client() -> redis_asyncio.Redis:
    """Create the Redis client of one invocation.

    Values are bytes, so that a stored value that is not UTF-8 counts as
    absent instead of failing in the client. Every command has a 2-second
    connect and operation timeout and is never retried: a resent `SET NX`
    would report the lock as held by another read after its own write.
    Kept as its own function so tests can simulate `RedisError`.
    """
    client: redis_asyncio.Redis = redis_asyncio.Redis.from_url(
        get_bugzilla_needinfo_redis_url(),
        decode_responses=False,
        socket_connect_timeout=_REDIS_OPERATION_TIMEOUT_SECONDS,
        socket_timeout=_REDIS_OPERATION_TIMEOUT_SECONDS,
        retry=Retry(NoBackoff(), 0),
    )
    return client


class _CacheFailureLog:
    """Logs `bugzilla_needinfo_cache_failed` at most once per invocation."""

    __slots__ = ("_logged",)

    def __init__(self) -> None:
        self._logged = False

    def record(self, exc: RedisError) -> None:
        if not self._logged:
            self._logged = True
            logger.warning(CACHE_FAILED_EVENT, error_type=type(exc).__name__)


# ---------------------------------------------------------------------------
# get_needinfo_count()
# ---------------------------------------------------------------------------


async def get_needinfo_count() -> NeedinfoCount:
    """Return the count of open needinfo requests to the security team.

    Category: external I/O with an ephemeral Redis cache; no database
    access, no audit event. See bugzilla-needinfo-count.md
    (`get_needinfo_count()`) for the steps. Raises
    `BugzillaUnavailableError` when no valid count is available; a failure
    to create the HTTP client propagates after the lock is released.
    """
    api_key = settings.bugzilla_api_key.get_secret_value()
    failures = _CacheFailureLog()
    client = _new_redis_client()
    try:
        result = await _coordinated_read(client, api_key, failures)
    finally:
        with suppress(RedisError):
            await client.aclose()
    return NeedinfoCount(
        count=result.count, authenticated=result.authenticated, url=SEARCH_URL
    )


def _result(outcome: SearchOutcome | CachedOutcome) -> SearchCount:
    if isinstance(outcome, SearchCount):
        return outcome
    raise BugzillaUnavailableError


async def _coordinated_read(
    client: redis_asyncio.Redis, api_key: str, failures: _CacheFailureLog
) -> SearchCount:
    acquired = False
    try:
        # Step 1: a cached outcome answers without a Bugzilla request.
        cached = decode_cached(await client.get(CACHE_KEY))
        if cached is None:
            # Step 2: take the lock only if it is absent.
            acquired = bool(
                await client.set(LOCK_KEY, b"1", nx=True, ex=LOCK_TTL_SECONDS)
            )
    except RedisError as exc:
        # The cache only spares Bugzilla repeated requests: read directly,
        # without lock or cache write.
        failures.record(exc)
        return _result(await read_from_bugzilla(api_key))
    if cached is not None:
        return _result(cached)
    if acquired:
        return await _read_holding_lock(client, api_key, failures)
    return await _wait_for_outcome(client, failures)


async def _read_holding_lock(
    client: redis_asyncio.Redis, api_key: str, failures: _CacheFailureLog
) -> SearchCount:
    """Step 3: re-read the cache, read Bugzilla, write the outcome, and
    release the lock, also when the read raises."""
    outcome: SearchOutcome | CachedOutcome
    try:
        try:
            cached = decode_cached(await client.get(CACHE_KEY))
        except RedisError as exc:
            failures.record(exc)
            cached = None
        if cached is not None:
            # A read that completed between steps 1 and 2 wrote it.
            outcome = cached
        else:
            outcome = await read_from_bugzilla(api_key)
            try:
                await client.set(CACHE_KEY, encode_cached(outcome), ex=_expiry(outcome))
            except RedisError as exc:
                failures.record(exc)
    finally:
        try:
            await client.delete(LOCK_KEY)
        except RedisError as exc:
            # The lock expires.
            failures.record(exc)
    return _result(outcome)


async def _wait_for_outcome(
    client: redis_asyncio.Redis, failures: _CacheFailureLog
) -> SearchCount:
    """Step 4: poll both keys until the other read's outcome appears, the
    lock disappears without one, or the wait reaches the lock expiry."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + WAIT_SECONDS
    while True:
        await asyncio.sleep(POLL_INTERVAL_SECONDS)
        try:
            value, lock = await client.mget([CACHE_KEY, LOCK_KEY])
        except RedisError as exc:
            # Another read is in progress; a second one would exceed the
            # bounded response time.
            failures.record(exc)
            raise BugzillaUnavailableError from None
        cached = decode_cached(value)
        if cached is not None:
            return _result(cached)
        if lock is None or loop.time() >= deadline:
            raise BugzillaUnavailableError
