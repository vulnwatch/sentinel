"""Tests for `app/services/bugzilla_needinfo_service.py`.

Contract under test: docs/features/integrations/bugzilla-needinfo-count.md
(Search Request, Authentication, Response Contract, Search URL, Redis Keys,
`get_needinfo_count()`, Service Exceptions, Logging, Security and Privacy,
Testing Requirements), docs/conventions.md (Redis Error Handling; External
JSON Decoding), docs/features/platform/networking.md (Non-Fetcher
Components), and docs/features/platform/testing-strategy.md (External JSON
Decoding; Application-Owned Redis Operations; Redis Strategy).

The shared HTTP client is the production one; only its network transport is
replaced by `JsonRpcServer` (`tests/support/bugzilla_jsonrpc.py`). Its retry
backoff sleeps are recorded instead of awaited, except where a test needs the
real wait to be cut short by the read deadline. Redis is the worker database
of `redis_client`; failures are injected at the module's replaceable client
boundary (`_new_redis_client`). The waits of the read coordination are
shortened by patching the module constants.

Expected values are transcribed from the specification. The API key is
fictional and built at run time.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator, Callable, MutableMapping, Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Final
from unittest.mock import AsyncMock

import httpx
import pytest
import pytest_asyncio
import redis.asyncio as redis_asyncio
from pydantic import SecretStr
from redis import exceptions as redis_exceptions
from structlog.testing import capture_logs

from app.config import settings
from app.core.exceptions import ServiceError
from app.services import bugzilla_needinfo_service as service
from app.services import http_client
from app.services.bugzilla_needinfo_service import (
    API_KEY_REJECTED_EVENT,
    CACHE_FAILED_EVENT,
    CACHE_KEY,
    LOCK_KEY,
    READ_FAILED_EVENT,
    SEARCH_URL,
    BugzillaNeedinfoServiceError,
    BugzillaUnavailableError,
    NeedinfoCount,
    SearchCount,
    SearchFailure,
)
from tests.support import bugzilla_jsonrpc as rpc
from tests.support.bugzilla_jsonrpc import (
    ANONYMOUS_FIXTURE,
    AUTHENTICATED_FIXTURE,
    INVALID_KEY_FIXTURE,
    PUBLIC_TEST_BUG,
    RESTRICTED_TEST_BUG,
    JsonRpcServer,
)
from tests.support.http_client_errors import CONFIGURATION_ERRORS, break_shared_client
from tests.support.inadmissible import json_bytes
from tests.support.json_decoding import (
    NESTED_ARRAY,
    OVERSIZED_INTEGER,
    limit_parser_nesting,
)

API_KEY: Final = "-".join(("fictional", "bugzilla", "key", "0000"))
"""A fictional API key; never a real credential."""

_EXPECTED_URL: Final = "https://bugzilla.suse.com/jsonrpc.cgi"
_EXPECTED_SEARCH_URL: Final = (
    "https://bugzilla.suse.com/buglist.cgi?bug_status=UNCONFIRMED&bug_status=NEW"
    "&bug_status=CONFIRMED&bug_status=IN_PROGRESS&bug_status=REOPENED"
    "&f1=flagtypes.name&o1=equals&v1=needinfo%3F&f2=requestees.login_name"
    "&o2=equals&v2=security-team%40suse.de&query_format=advanced"
)
_EXPECTED_BODY: Final[dict[str, Any]] = {
    "method": "Bug.search",
    "params": [
        {
            "include_fields": ["id"],
            "bug_status": [
                "UNCONFIRMED",
                "NEW",
                "CONFIRMED",
                "IN_PROGRESS",
                "REOPENED",
            ],
            "f1": "flagtypes.name",
            "o1": "equals",
            "v1": "needinfo?",
            "f2": "requestees.login_name",
            "o2": "equals",
            "v2": "security-team@suse.de",
            "limit": 0,
        }
    ],
    "id": 1,
}
"""The request body of Search Request, transcribed."""

_REDIS_ERRORS: Final = (
    redis_exceptions.ConnectionError("fictional connection loss"),
    redis_exceptions.ResponseError(
        "OOM command not allowed when used memory > 'maxmemory'."
    ),
    redis_exceptions.TimeoutError("fictional timeout"),
)
_REDIS_ERROR_IDS: Final = ("connection", "oom_response_error", "timeout")


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def server(monkeypatch: pytest.MonkeyPatch) -> JsonRpcServer:
    """The fake Bugzilla behind the production shared HTTP client."""
    fake = JsonRpcServer()
    monkeypatch.setattr(
        httpx, "AsyncHTTPTransport", lambda **_: httpx.MockTransport(fake.handler)
    )
    return fake


@pytest.fixture
def backoff(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    """Records the shared transport's retry sleeps instead of awaiting them."""
    recorded = AsyncMock()
    monkeypatch.setattr(http_client, "asyncio", SimpleNamespace(sleep=recorded))
    return recorded


@pytest.fixture
def anonymous(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "bugzilla_api_key", SecretStr(""))


@pytest.fixture
def with_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "bugzilla_api_key", SecretStr(API_KEY))


@pytest.fixture
def fast_wait(monkeypatch: pytest.MonkeyPatch) -> None:
    """A 10 ms poll and a 1-second wait instead of 250 ms and 15 seconds."""
    monkeypatch.setattr(service, "POLL_INTERVAL_SECONDS", 0.01)
    monkeypatch.setattr(service, "WAIT_SECONDS", 1.0)


def _failure_records(
    logs: Sequence[MutableMapping[str, Any]],
) -> list[MutableMapping[str, Any]]:
    events = {READ_FAILED_EVENT, API_KEY_REJECTED_EVENT, CACHE_FAILED_EVENT}
    return [record for record in logs if record["event"] in events]


async def _stored(redis_client: redis_asyncio.Redis) -> Any:
    """The decoded cache value; it must exist."""
    raw = await redis_client.get(CACHE_KEY)
    assert raw is not None
    return json.loads(raw)


async def _ttl(redis_client: redis_asyncio.Redis, key: str) -> int:
    value: int = await redis_client.ttl(key)
    return value


class _FaultyRedis:
    """Delegates to a real client and raises `error` at one named step:
    `get` (step 1), `lock` (step 2), `reget` (step 3.1), `write` (step
    3.3), `release` (step 3.4), or `poll` (step 4)."""

    def __init__(
        self, inner: redis_asyncio.Redis, fail: set[str], error: Exception
    ) -> None:
        self._inner = inner
        self._fail = fail
        self._error = error
        self._gets = 0
        self.steps: list[str] = []

    def _step(self, name: str) -> None:
        self.steps.append(name)
        if name in self._fail:
            raise self._error

    async def get(self, key: str) -> Any:
        self._gets += 1
        self._step("get" if self._gets == 1 else "reget")
        return await self._inner.get(key)

    async def set(self, key: str, value: Any, **options: Any) -> Any:
        self._step("lock" if options.get("nx") else "write")
        return await self._inner.set(key, value, **options)

    async def delete(self, key: str) -> Any:
        self._step("release")
        return await self._inner.delete(key)

    async def mget(self, keys: list[str]) -> Any:
        self._step("poll")
        return await self._inner.mget(keys)

    async def aclose(self) -> None:
        await self._inner.aclose()


def _use_faulty_redis(
    monkeypatch: pytest.MonkeyPatch, fail: set[str], error: Exception
) -> list[_FaultyRedis]:
    created: list[_FaultyRedis] = []
    real = service._new_redis_client

    def factory() -> Any:
        client = _FaultyRedis(real(), fail, error)
        created.append(client)
        return client

    monkeypatch.setattr(service, "_new_redis_client", factory)
    return created


# ---------------------------------------------------------------------------
# Search Request
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestSearchRequest:
    async def test_anonymous_request_is_the_fixed_post_without_a_credential(
        self, server: JsonRpcServer, backoff: AsyncMock
    ) -> None:
        await service.read_from_bugzilla("")

        [request] = server.requests
        assert request.method == "POST"
        assert str(request.url) == _EXPECTED_URL
        assert request.headers["content-type"] == "application/json"
        assert request.headers["accept"] == "application/json"
        assert json.loads(request.content) == _EXPECTED_BODY
        assert "Bugzilla_api_key" not in request.content.decode()

    async def test_key_is_only_the_member_bugzilla_api_key_of_params_0(
        self, server: JsonRpcServer, backoff: AsyncMock
    ) -> None:
        await service.read_from_bugzilla(API_KEY)

        [request] = server.requests
        body = json.loads(request.content)
        params = dict(body["params"][0])
        assert params.pop("Bugzilla_api_key") == API_KEY
        assert {**body, "params": [params]} == _EXPECTED_BODY
        assert API_KEY not in str(request.url)
        for name, value in request.headers.items():
            assert API_KEY not in name
            assert API_KEY not in value

    def test_search_url_is_the_specified_constant(self) -> None:
        assert SEARCH_URL == _EXPECTED_SEARCH_URL
        assert service.JSONRPC_URL == _EXPECTED_URL

    async def test_post_is_retried_after_a_connection_error(
        self, server: JsonRpcServer, backoff: AsyncMock
    ) -> None:
        """`retry_non_idempotent=True`: a connection error of the `POST` is
        retried like that of a `GET`."""
        server.queue.append(rpc.raising(httpx.ConnectError("fictional")))

        outcome = await service.read_from_bugzilla("")

        assert outcome == SearchCount(count=1, authenticated=False)
        assert len(server.requests) == 2
        assert [call.args[0] for call in backoff.await_args_list] == [1.0]

    async def test_redirect_is_not_followed(
        self, server: JsonRpcServer, backoff: AsyncMock
    ) -> None:
        server.queue.append(
            rpc.status(302, {"Location": "https://bugzilla.example.test/jsonrpc.cgi"})
        )

        outcome = await service.read_from_bugzilla(API_KEY)

        assert outcome == SearchFailure("http_status", http_status=302)
        assert len(server.requests) == 1


# ---------------------------------------------------------------------------
# Response Contract
# ---------------------------------------------------------------------------


def _bugs(*elements: Any) -> bytes:
    return json_bytes({"error": None, "id": 1, "result": {"bugs": list(elements)}})


_INVALID_BODIES: Final[dict[str, bytes]] = {
    "boolean_id": _bugs({"id": True}),
    "float_id": b'{"error":null,"id":1,"result":{"bugs":[{"id":1291903.0}]}}',
    "exponent_id": b'{"error":null,"id":1,"result":{"bugs":[{"id":1e3}]}}',
    "zero_id": _bugs({"id": 0}),
    "negative_id": _bugs({"id": -1}),
    "string_id": _bugs({"id": "1291903"}),
    "missing_id": _bugs({"summary": "fictional"}),
    "element_not_object": _bugs(1291903),
    "element_null": _bugs(None),
    "body_array": b"[]",
    "body_string": b'"bugs"',
    "body_null": b"null",
    "result_absent": b'{"error":null,"id":1}',
    "result_null": b'{"error":null,"id":1,"result":null}',
    "result_array": b'{"error":null,"id":1,"result":[]}',
    "bugs_absent": b'{"error":null,"id":1,"result":{}}',
    "bugs_not_array": b'{"error":null,"id":1,"result":{"bugs":{}}}',
    "error_absent": b'{"id":1,"result":{"bugs":[]}}',
    "error_string": b'{"error":"fictional","id":1,"result":null}',
    "error_without_code": b'{"error":{"message":"x"},"id":1,"result":null}',
    "error_code_boolean": b'{"error":{"code":true},"id":1,"result":null}',
    "error_code_float": b'{"error":{"code":306.0},"id":1,"result":null}',
    "error_code_string": b'{"error":{"code":"306"},"id":1,"result":null}',
    "duplicated_bugs": b'{"error":null,"id":1,"result":{"bugs":[],"bugs":[{"id":1}]}}',
    "duplicated_result": (
        b'{"error":null,"id":1,"result":{"bugs":[]},"result":{"bugs":[]}}'
    ),
    "duplicated_error": b'{"error":null,"error":null,"id":1,"result":{"bugs":[]}}',
    "nan_id": b'{"error":null,"id":1,"result":{"bugs":[{"id":NaN}]}}',
    "infinity_id": b'{"error":null,"id":1,"result":{"bugs":[{"id":Infinity}]}}',
    "negative_infinity": b'{"error":null,"id":-Infinity,"result":{"bugs":[]}}',
    "byte_order_mark": b"\xef\xbb\xbf" + rpc.load_raw_fixture(ANONYMOUS_FIXTURE),
    "trailing_content": rpc.load_raw_fixture(ANONYMOUS_FIXTURE) + b"{}",
    "empty": b"",
    "invalid_utf8": b'{"error":null,"id":1,"result":{"bugs":[]},"x":"\xff"}',
    "html": b"<!DOCTYPE html><html><body>fictional</body></html>",
    "oversized_integer": (
        b'{"error":null,"id":1,"result":{"bugs":[{"id":'
        + OVERSIZED_INTEGER.encode()
        + b"}]}}"
    ),
}


@pytest.mark.unit
class TestResponseContract:
    async def test_anonymous_fixture_is_a_count_of_one(
        self, server: JsonRpcServer, backoff: AsyncMock
    ) -> None:
        server.default = rpc.fixture(ANONYMOUS_FIXTURE)

        outcome = await service.read_from_bugzilla("")

        assert outcome == SearchCount(count=1, authenticated=False)

    async def test_authenticated_fixture_is_a_count_of_two(
        self, server: JsonRpcServer, backoff: AsyncMock
    ) -> None:
        server.default = rpc.fixture(AUTHENTICATED_FIXTURE)

        outcome = await service.read_from_bugzilla(API_KEY)

        assert outcome == SearchCount(count=2, authenticated=True)

    async def test_empty_bugs_is_a_count_of_zero(
        self, server: JsonRpcServer, backoff: AsyncMock
    ) -> None:
        server.default = rpc.document(rpc.count_document([]))

        assert await service.read_from_bugzilla("") == SearchCount(0, False)

    async def test_other_members_are_ignored(
        self, server: JsonRpcServer, backoff: AsyncMock
    ) -> None:
        server.default = rpc.document(
            {
                "error": None,
                "id": 7,
                "extra": [1, 2],
                "result": {
                    "bugs": [{"id": 5, "summary": "fictional"}, {"id": 6}],
                    "faults": [],
                },
            }
        )

        assert await service.read_from_bugzilla("") == SearchCount(2, False)

    async def test_code_306_on_an_authenticated_read_is_api_key_rejected(
        self, server: JsonRpcServer, backoff: AsyncMock
    ) -> None:
        server.default = rpc.fixture(INVALID_KEY_FIXTURE)

        with capture_logs() as logs:
            outcome = await service.read_from_bugzilla(API_KEY)

        assert outcome == SearchFailure("api_key_rejected")
        assert _failure_records(logs) == [
            {"event": API_KEY_REJECTED_EVENT, "log_level": "error"}
        ]

    async def test_code_306_on_an_anonymous_read_is_a_bugzilla_error(
        self, server: JsonRpcServer, backoff: AsyncMock
    ) -> None:
        server.default = rpc.fixture(INVALID_KEY_FIXTURE)

        with capture_logs() as logs:
            outcome = await service.read_from_bugzilla("")

        assert outcome == SearchFailure("bugzilla_error", error_code=306)
        assert _failure_records(logs) == [
            {
                "event": READ_FAILED_EVENT,
                "log_level": "warning",
                "reason": "bugzilla_error",
                "authenticated": False,
                "error_code": 306,
            }
        ]

    @pytest.mark.parametrize("code", [102, 32000, -32601, 0])
    async def test_any_other_integer_code_is_a_bugzilla_error(
        self, server: JsonRpcServer, backoff: AsyncMock, code: int
    ) -> None:
        server.default = rpc.document(rpc.error_document(code))

        outcome = await service.read_from_bugzilla(API_KEY)

        assert outcome == SearchFailure("bugzilla_error", error_code=code)

    async def test_error_without_result_member_is_a_bugzilla_error(
        self, server: JsonRpcServer, backoff: AsyncMock
    ) -> None:
        server.default = rpc.raw(b'{"error":{"code":102}}')

        outcome = await service.read_from_bugzilla("")

        assert outcome == SearchFailure("bugzilla_error", error_code=102)

    @pytest.mark.parametrize("name", list(_INVALID_BODIES))
    async def test_invalid_body_is_an_invalid_response(
        self, server: JsonRpcServer, backoff: AsyncMock, name: str
    ) -> None:
        server.default = rpc.raw(_INVALID_BODIES[name])

        with capture_logs() as logs:
            outcome = await service.read_from_bugzilla(API_KEY)

        assert outcome == SearchFailure("invalid_response")
        assert _failure_records(logs) == [
            {
                "event": READ_FAILED_EVENT,
                "log_level": "warning",
                "reason": "invalid_response",
                "authenticated": True,
            }
        ]

    async def test_nesting_beyond_the_parser_limit_is_an_invalid_response(
        self,
        server: JsonRpcServer,
        backoff: AsyncMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """testing-strategy.md, External JSON Decoding."""
        limit_parser_nesting(monkeypatch)
        server.default = rpc.raw(
            b'{"error":null,"id":1,"result":{"bugs":[]},"x":'
            + NESTED_ARRAY.encode()
            + b"}"
        )

        outcome = await service.read_from_bugzilla("")

        assert outcome == SearchFailure("invalid_response")

    async def test_rejected_content_coding_is_an_invalid_response(
        self, server: JsonRpcServer, backoff: AsyncMock
    ) -> None:
        server.default = rpc.undecodable()

        outcome = await service.read_from_bugzilla("")

        assert outcome == SearchFailure("invalid_response")

    @pytest.mark.parametrize("code", [201, 204, 301, 400, 401, 403, 404, 429])
    async def test_status_other_than_200_is_an_http_failure(
        self, server: JsonRpcServer, backoff: AsyncMock, code: int
    ) -> None:
        server.default = rpc.raw(rpc.load_raw_fixture(ANONYMOUS_FIXTURE), code)

        with capture_logs() as logs:
            outcome = await service.read_from_bugzilla("")

        assert outcome == SearchFailure("http_status", http_status=code)
        assert len(server.requests) == 1
        assert _failure_records(logs) == [
            {
                "event": READ_FAILED_EVENT,
                "log_level": "warning",
                "reason": "http_status",
                "authenticated": False,
                "http_status": code,
            }
        ]

    async def test_5xx_after_transport_retries_is_an_http_failure(
        self, server: JsonRpcServer, backoff: AsyncMock
    ) -> None:
        server.default = rpc.status(502)

        outcome = await service.read_from_bugzilla("")

        assert outcome == SearchFailure("http_status", http_status=502)
        assert len(server.requests) == 4
        assert [call.args[0] for call in backoff.await_args_list] == [1.0, 2.0, 4.0]

    @pytest.mark.parametrize(
        "error",
        [
            httpx.ConnectError("fictional"),
            httpx.ReadTimeout("fictional"),
            httpx.ProxyError("fictional"),
            httpx.RemoteProtocolError("fictional"),
            httpx.LocalProtocolError("fictional"),
        ],
        ids=["connect", "read_timeout", "proxy", "remote_protocol", "local_protocol"],
    )
    async def test_transport_error_after_retries_is_a_transport_failure(
        self, server: JsonRpcServer, backoff: AsyncMock, error: Exception
    ) -> None:
        server.default = rpc.raising(error)

        with capture_logs() as logs:
            outcome = await service.read_from_bugzilla(API_KEY)

        assert outcome == SearchFailure("transport")
        assert _failure_records(logs) == [
            {
                "event": READ_FAILED_EVENT,
                "log_level": "warning",
                "reason": "transport",
                "authenticated": True,
            }
        ]

    async def test_body_interrupted_by_a_transport_error_is_a_transport_failure(
        self, server: JsonRpcServer, backoff: AsyncMock
    ) -> None:
        server.default = rpc.interrupted()

        outcome = await service.read_from_bugzilla("")

        assert outcome == SearchFailure("transport")

    async def test_deadline_cuts_short_a_retry_after_wait(
        self, server: JsonRpcServer, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The 10-second deadline (shortened here) includes the transport
        retries, also a `Retry-After` wait that would last 60 seconds."""
        monkeypatch.setattr(service, "READ_DEADLINE_SECONDS", 0.2)
        server.default = rpc.status(503, {"Retry-After": "60"})

        started = time.monotonic()
        outcome = await service.read_from_bugzilla("")

        assert outcome == SearchFailure("transport")
        assert time.monotonic() - started < 5
        assert len(server.requests) == 1

    async def test_deadline_cuts_short_a_slow_answer(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(service, "READ_DEADLINE_SECONDS", 0.2)

        async def slow(request: httpx.Request) -> httpx.Response:
            await asyncio.sleep(30)
            return httpx.Response(200, request=request)

        monkeypatch.setattr(
            httpx, "AsyncHTTPTransport", lambda **_: httpx.MockTransport(slow)
        )

        started = time.monotonic()
        outcome = await service.read_from_bugzilla("")

        assert outcome == SearchFailure("transport")
        assert time.monotonic() - started < 5

    def test_deadline_and_waits_are_the_specified_values(self) -> None:
        assert service.READ_DEADLINE_SECONDS == 10.0
        assert service.WAIT_SECONDS == 15.0
        assert service.LOCK_TTL_SECONDS == 15
        assert service.POLL_INTERVAL_SECONDS == 0.25
        assert service.COUNT_TTL_SECONDS == 60
        assert service.FAILURE_TTL_SECONDS == 10

    async def test_count_logs_nothing(
        self, server: JsonRpcServer, backoff: AsyncMock
    ) -> None:
        with capture_logs() as logs:
            await service.read_from_bugzilla("")

        assert _failure_records(logs) == []

    @pytest.mark.parametrize("kind", CONFIGURATION_ERRORS)
    async def test_client_creation_failure_propagates(
        self,
        server: JsonRpcServer,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        kind: Any,
    ) -> None:
        broken = break_shared_client(kind, monkeypatch, tmp_path)

        with pytest.raises(broken.error):
            await service.read_from_bugzilla(API_KEY)

        assert server.requests == []


# ---------------------------------------------------------------------------
# Cache values
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestCacheValues:
    @pytest.mark.parametrize(
        ("outcome", "encoded"),
        [
            (
                SearchCount(2, True),
                '{"outcome":"count","count":2,"authenticated":true}',
            ),
            (
                SearchCount(0, False),
                '{"outcome":"count","count":0,"authenticated":false}',
            ),
            (SearchFailure("transport"), '{"outcome":"unavailable"}'),
            (SearchFailure("api_key_rejected"), '{"outcome":"unavailable"}'),
        ],
    )
    def test_value_is_one_of_the_documented_forms(
        self, outcome: Any, encoded: str
    ) -> None:
        assert json.loads(service.encode_cached(outcome)) == json.loads(encoded)

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            (
                b'{"outcome":"count","count":2,"authenticated":true}',
                SearchCount(2, True),
            ),
            (
                b'{"authenticated":false,"count":0,"outcome":"count"}',
                SearchCount(0, False),
            ),
            (b'{"outcome":"unavailable"}', "unavailable"),
        ],
    )
    def test_documented_value_is_decoded(self, raw: bytes, expected: Any) -> None:
        assert service.decode_cached(raw) == expected

    @pytest.mark.parametrize(
        "raw",
        [
            None,
            b"",
            b"1",
            b"[]",
            b"not json",
            b"\xff\xfe",
            b"\xef\xbb\xbf" + b'{"outcome":"unavailable"}',
            b'{"outcome":"unavailable","count":1}',
            b'{"outcome":"unavailable","outcome":"unavailable"}',
            b'{"outcome":"count","count":2}',
            b'{"outcome":"count","count":-1,"authenticated":true}',
            b'{"outcome":"count","count":true,"authenticated":true}',
            b'{"outcome":"count","count":2.0,"authenticated":true}',
            b'{"outcome":"count","count":NaN,"authenticated":true}',
            b'{"outcome":"count","count":2,"authenticated":1}',
            b'{"outcome":"count","count":2,"authenticated":true,"bugs":[1]}',
            b'{"outcome":"other","count":2,"authenticated":true}',
            b'{"outcome":"failed"}',
            OVERSIZED_INTEGER.encode(),
        ],
    )
    def test_any_other_value_counts_as_absent(self, raw: bytes | None) -> None:
        assert service.decode_cached(raw) is None

    def test_redis_client_has_two_second_timeouts_and_no_retry(self) -> None:
        client = service._new_redis_client()
        kwargs = client.connection_pool.connection_kwargs

        assert kwargs["socket_timeout"] == 2.0
        assert kwargs["socket_connect_timeout"] == 2.0
        assert client.get_retry().get_retries() == 0  # type: ignore[union-attr]

    def test_redis_url_is_the_configured_one(self) -> None:
        assert service.get_bugzilla_needinfo_redis_url() == settings.redis_url


# ---------------------------------------------------------------------------
# get_needinfo_count(): cache
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("backoff")
class TestCache:
    async def test_miss_reads_bugzilla_writes_a_count_for_60_seconds(
        self,
        redis_client: redis_asyncio.Redis,
        server: JsonRpcServer,
        anonymous: None,
    ) -> None:
        result = await service.get_needinfo_count()

        assert result == NeedinfoCount(count=1, authenticated=False, url=SEARCH_URL)
        assert len(server.requests) == 1
        assert await _stored(redis_client) == {
            "outcome": "count",
            "count": 1,
            "authenticated": False,
        }
        assert 55 < await _ttl(redis_client, CACHE_KEY) <= 60
        assert await redis_client.exists(LOCK_KEY) == 0

    async def test_authenticated_read_is_reported(
        self,
        redis_client: redis_asyncio.Redis,
        server: JsonRpcServer,
        with_key: None,
    ) -> None:
        server.default = rpc.fixture(AUTHENTICATED_FIXTURE)

        result = await service.get_needinfo_count()

        assert result == NeedinfoCount(count=2, authenticated=True, url=SEARCH_URL)

    async def test_hit_sends_no_bugzilla_request(
        self,
        redis_client: redis_asyncio.Redis,
        server: JsonRpcServer,
        anonymous: None,
    ) -> None:
        await redis_client.set(
            CACHE_KEY, '{"outcome":"count","count":7,"authenticated":true}', ex=60
        )

        result = await service.get_needinfo_count()

        assert result == NeedinfoCount(count=7, authenticated=True, url=SEARCH_URL)
        assert server.requests == []

    async def test_second_call_within_the_expiry_is_a_hit(
        self,
        redis_client: redis_asyncio.Redis,
        server: JsonRpcServer,
        anonymous: None,
    ) -> None:
        first = await service.get_needinfo_count()
        second = await service.get_needinfo_count()

        assert first == second
        assert len(server.requests) == 1

    async def test_failed_read_is_cached_for_10_seconds(
        self,
        redis_client: redis_asyncio.Redis,
        server: JsonRpcServer,
        anonymous: None,
    ) -> None:
        server.default = rpc.status(403)

        with pytest.raises(BugzillaUnavailableError):
            await service.get_needinfo_count()

        assert await _stored(redis_client) == {"outcome": "unavailable"}
        assert 5 < await _ttl(redis_client, CACHE_KEY) <= 10
        assert await redis_client.exists(LOCK_KEY) == 0

    async def test_cached_failure_raises_without_a_bugzilla_request(
        self,
        redis_client: redis_asyncio.Redis,
        server: JsonRpcServer,
        anonymous: None,
    ) -> None:
        await redis_client.set(CACHE_KEY, '{"outcome":"unavailable"}', ex=10)

        with capture_logs() as logs, pytest.raises(BugzillaUnavailableError):
            await service.get_needinfo_count()

        assert server.requests == []
        assert _failure_records(logs) == []

    async def test_api_key_rejected_fails_without_anonymous_fallback(
        self,
        redis_client: redis_asyncio.Redis,
        server: JsonRpcServer,
        with_key: None,
    ) -> None:
        server.default = rpc.fixture(INVALID_KEY_FIXTURE)

        with pytest.raises(BugzillaUnavailableError):
            await service.get_needinfo_count()

        assert len(server.requests) == 1
        assert await _stored(redis_client) == {"outcome": "unavailable"}

    @pytest.mark.parametrize(
        "value",
        [b"not json", b"\xff", b'{"outcome":"count","count":-1,"authenticated":true}'],
    )
    async def test_invalid_cached_value_counts_as_absent(
        self,
        redis_client: redis_asyncio.Redis,
        server: JsonRpcServer,
        anonymous: None,
        value: bytes,
    ) -> None:
        await redis_client.set(CACHE_KEY, value, ex=60)

        result = await service.get_needinfo_count()

        assert result.count == 1
        assert len(server.requests) == 1
        assert (await _stored(redis_client))["count"] == 1

    async def test_value_written_between_steps_1_and_2_is_returned(
        self,
        redis_client: redis_asyncio.Redis,
        server: JsonRpcServer,
        anonymous: None,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Another read completes after step 1 and before the lock is taken:
        the re-read of step 3.1 returns its value without a Bugzilla
        request and releases the lock."""
        real = service._new_redis_client

        class _Racing(_FaultyRedis):
            async def set(self, key: str, value: Any, **options: Any) -> Any:
                if options.get("nx"):
                    await redis_client.set(
                        CACHE_KEY,
                        '{"outcome":"count","count":4,"authenticated":true}',
                        ex=60,
                    )
                return await super().set(key, value, **options)

        monkeypatch.setattr(
            service, "_new_redis_client", lambda: _Racing(real(), set(), Exception())
        )

        result = await service.get_needinfo_count()

        assert result == NeedinfoCount(count=4, authenticated=True, url=SEARCH_URL)
        assert server.requests == []
        assert await redis_client.exists(LOCK_KEY) == 0

    async def test_cached_failure_between_steps_1_and_2_raises(
        self,
        redis_client: redis_asyncio.Redis,
        server: JsonRpcServer,
        anonymous: None,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        real = service._new_redis_client

        class _Racing(_FaultyRedis):
            async def set(self, key: str, value: Any, **options: Any) -> Any:
                if options.get("nx"):
                    await redis_client.set(
                        CACHE_KEY, '{"outcome":"unavailable"}', ex=10
                    )
                return await super().set(key, value, **options)

        monkeypatch.setattr(
            service, "_new_redis_client", lambda: _Racing(real(), set(), Exception())
        )

        with pytest.raises(BugzillaUnavailableError):
            await service.get_needinfo_count()

        assert server.requests == []
        assert await redis_client.exists(LOCK_KEY) == 0

    @pytest.mark.parametrize("kind", CONFIGURATION_ERRORS)
    async def test_client_creation_failure_releases_the_lock_and_writes_nothing(
        self,
        redis_client: redis_asyncio.Redis,
        server: JsonRpcServer,
        anonymous: None,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        kind: Any,
    ) -> None:
        broken = break_shared_client(kind, monkeypatch, tmp_path)

        with pytest.raises(broken.error):
            await service.get_needinfo_count()

        assert await redis_client.exists(CACHE_KEY, LOCK_KEY) == 0
        assert server.requests == []

    async def test_changed_key_takes_effect_after_the_cached_value_expires(
        self,
        redis_client: redis_asyncio.Redis,
        server: JsonRpcServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Known Limitations, Changed key or deployment: `authenticated`
        reports the read that produced the cached value."""
        monkeypatch.setattr(settings, "bugzilla_api_key", SecretStr(""))
        await service.get_needinfo_count()
        monkeypatch.setattr(settings, "bugzilla_api_key", SecretStr(API_KEY))
        server.default = rpc.fixture(AUTHENTICATED_FIXTURE)

        cached = await service.get_needinfo_count()
        await redis_client.delete(CACHE_KEY)
        fresh = await service.get_needinfo_count()

        assert (cached.count, cached.authenticated) == (1, False)
        assert (fresh.count, fresh.authenticated) == (2, True)
        assert len(server.requests) == 2


# ---------------------------------------------------------------------------
# get_needinfo_count(): read coordination
# ---------------------------------------------------------------------------


class _Gate:
    """A Bugzilla answer held until `open()`; `entered` is set when the
    first request arrives, and every request is recorded."""

    def __init__(self, responder: rpc.Responder) -> None:
        self.entered = asyncio.Event()
        self.requests: list[httpx.Request] = []
        self._released = asyncio.Event()
        self._responder = responder

    def open(self) -> None:
        self._released.set()

    async def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        self.entered.set()
        await self._released.wait()
        return self._responder(request)


@pytest.fixture
def gated(monkeypatch: pytest.MonkeyPatch) -> Callable[[rpc.Responder], _Gate]:
    """Install a `_Gate` as the network behind the shared HTTP client."""

    def install(responder: rpc.Responder) -> _Gate:
        gate = _Gate(responder)
        monkeypatch.setattr(
            httpx, "AsyncHTTPTransport", lambda **_: httpx.MockTransport(gate.handler)
        )
        return gate

    return install


async def _start_waiter(
    redis_client: redis_asyncio.Redis,
) -> asyncio.Task[NeedinfoCount]:
    """Start a second call while the first, whose request has reached
    Bugzilla, holds the lock, and let it reach its wait."""
    assert await redis_client.exists(LOCK_KEY) == 1
    task = asyncio.create_task(service.get_needinfo_count())
    await asyncio.sleep(0.05)
    assert not task.done()
    return task


@pytest_asyncio.fixture
async def lock_held_elsewhere(
    redis_client: redis_asyncio.Redis,
) -> AsyncIterator[None]:
    """The lock of a read in another API process."""
    await redis_client.set(LOCK_KEY, "1", ex=15)
    yield


@pytest.mark.integration
@pytest.mark.usefixtures("backoff", "fast_wait", "anonymous")
class TestReadCoordination:
    async def test_concurrent_call_waits_and_shares_the_count(
        self,
        redis_client: redis_asyncio.Redis,
        gated: Callable[[rpc.Responder], _Gate],
    ) -> None:
        gate = gated(rpc.fixture(ANONYMOUS_FIXTURE))
        first = asyncio.create_task(service.get_needinfo_count())
        await gate.entered.wait()
        second = await _start_waiter(redis_client)

        gate.open()
        results = await asyncio.gather(first, second)

        assert results[0] == results[1] == NeedinfoCount(1, False, SEARCH_URL)
        assert len(gate.requests) == 1

    async def test_concurrent_call_shares_the_failure_and_logs_nothing(
        self,
        redis_client: redis_asyncio.Redis,
        gated: Callable[[rpc.Responder], _Gate],
    ) -> None:
        gate = gated(rpc.status(403))
        with capture_logs() as logs:
            first = asyncio.create_task(service.get_needinfo_count())
            await gate.entered.wait()
            second = await _start_waiter(redis_client)
            gate.open()
            results = await asyncio.gather(first, second, return_exceptions=True)

        assert all(isinstance(r, BugzillaUnavailableError) for r in results)
        assert len(gate.requests) == 1
        assert [r["event"] for r in _failure_records(logs)] == [READ_FAILED_EVENT]

    async def test_waiter_receives_a_read_that_ends_near_its_deadline(
        self,
        redis_client: redis_asyncio.Redis,
        gated: Callable[[rpc.Responder], _Gate],
    ) -> None:
        """The waiter's bound (15 s, here 1 s) exceeds the read deadline, so
        an outcome that arrives late in the wait is still received."""
        gate = gated(rpc.fixture(ANONYMOUS_FIXTURE))
        first = asyncio.create_task(service.get_needinfo_count())
        await gate.entered.wait()
        second = await _start_waiter(redis_client)

        await asyncio.sleep(0.7)
        assert not second.done()
        gate.open()

        assert (await second).count == 1
        assert (await first).count == 1
        assert len(gate.requests) == 1

    @pytest.mark.usefixtures("lock_held_elsewhere")
    async def test_waiter_raises_when_both_keys_disappear(
        self, redis_client: redis_asyncio.Redis, server: JsonRpcServer
    ) -> None:
        """The other read ended without writing an outcome."""
        task = asyncio.create_task(service.get_needinfo_count())
        await asyncio.sleep(0.05)
        assert not task.done()

        await redis_client.delete(LOCK_KEY)

        with capture_logs() as logs, pytest.raises(BugzillaUnavailableError):
            await task
        assert server.requests == []
        assert _failure_records(logs) == []

    @pytest.mark.usefixtures("lock_held_elsewhere")
    async def test_waiter_raises_when_no_value_appears_within_the_wait(
        self, server: JsonRpcServer
    ) -> None:
        started = time.monotonic()

        with pytest.raises(BugzillaUnavailableError):
            await service.get_needinfo_count()

        elapsed = time.monotonic() - started
        assert 1.0 <= elapsed < 5
        assert server.requests == []

    @pytest.mark.usefixtures("lock_held_elsewhere")
    async def test_waiter_returns_a_value_that_appears_during_the_wait(
        self, redis_client: redis_asyncio.Redis, server: JsonRpcServer
    ) -> None:
        task = asyncio.create_task(service.get_needinfo_count())
        await asyncio.sleep(0.05)

        await redis_client.set(
            CACHE_KEY, '{"outcome":"count","count":3,"authenticated":true}', ex=60
        )

        assert await task == NeedinfoCount(3, True, SEARCH_URL)
        assert server.requests == []

    @pytest.mark.usefixtures("lock_held_elsewhere")
    async def test_waiter_ignores_an_invalid_value_while_the_lock_is_held(
        self, redis_client: redis_asyncio.Redis, server: JsonRpcServer
    ) -> None:
        await redis_client.set(CACHE_KEY, "not json", ex=60)
        task = asyncio.create_task(service.get_needinfo_count())
        await asyncio.sleep(0.05)
        assert not task.done()

        await redis_client.set(CACHE_KEY, '{"outcome":"unavailable"}', ex=10)

        with pytest.raises(BugzillaUnavailableError):
            await task
        assert server.requests == []


# ---------------------------------------------------------------------------
# get_needinfo_count(): Redis unavailability
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("backoff", "fast_wait", "anonymous")
class TestRedisFailure:
    @pytest.mark.parametrize("error", _REDIS_ERRORS, ids=_REDIS_ERROR_IDS)
    @pytest.mark.parametrize("step", ["get", "lock"])
    async def test_failure_before_the_lock_reads_bugzilla_directly(
        self,
        redis_client: redis_asyncio.Redis,
        server: JsonRpcServer,
        monkeypatch: pytest.MonkeyPatch,
        step: str,
        error: Exception,
    ) -> None:
        _use_faulty_redis(monkeypatch, {step}, error)

        with capture_logs() as logs:
            result = await service.get_needinfo_count()

        assert result == NeedinfoCount(1, False, SEARCH_URL)
        assert len(server.requests) == 1
        assert await redis_client.exists(CACHE_KEY, LOCK_KEY) == 0
        assert _failure_records(logs) == [
            {
                "event": CACHE_FAILED_EVENT,
                "log_level": "warning",
                "error_type": type(error).__name__,
            }
        ]

    @pytest.mark.parametrize("error", _REDIS_ERRORS, ids=_REDIS_ERROR_IDS)
    async def test_direct_read_failure_raises_and_writes_nothing(
        self,
        redis_client: redis_asyncio.Redis,
        server: JsonRpcServer,
        monkeypatch: pytest.MonkeyPatch,
        error: Exception,
    ) -> None:
        _use_faulty_redis(monkeypatch, {"get"}, error)
        server.default = rpc.status(403)

        with capture_logs() as logs, pytest.raises(BugzillaUnavailableError):
            await service.get_needinfo_count()

        assert await redis_client.exists(CACHE_KEY, LOCK_KEY) == 0
        assert sorted(r["event"] for r in _failure_records(logs)) == [
            CACHE_FAILED_EVENT,
            READ_FAILED_EVENT,
        ]

    @pytest.mark.parametrize("error", _REDIS_ERRORS, ids=_REDIS_ERROR_IDS)
    async def test_failed_reread_continues_with_the_read(
        self,
        redis_client: redis_asyncio.Redis,
        server: JsonRpcServer,
        monkeypatch: pytest.MonkeyPatch,
        error: Exception,
    ) -> None:
        _use_faulty_redis(monkeypatch, {"reget"}, error)

        with capture_logs() as logs:
            result = await service.get_needinfo_count()

        assert result.count == 1
        assert len(server.requests) == 1
        assert await redis_client.exists(CACHE_KEY) == 1
        assert await redis_client.exists(LOCK_KEY) == 0
        assert [r["event"] for r in _failure_records(logs)] == [CACHE_FAILED_EVENT]

    @pytest.mark.parametrize("error", _REDIS_ERRORS, ids=_REDIS_ERROR_IDS)
    async def test_failed_write_is_ignored(
        self,
        redis_client: redis_asyncio.Redis,
        server: JsonRpcServer,
        monkeypatch: pytest.MonkeyPatch,
        error: Exception,
    ) -> None:
        _use_faulty_redis(monkeypatch, {"write"}, error)

        with capture_logs() as logs:
            result = await service.get_needinfo_count()

        assert result.count == 1
        assert await redis_client.exists(CACHE_KEY) == 0
        assert await redis_client.exists(LOCK_KEY) == 0
        assert [r["event"] for r in _failure_records(logs)] == [CACHE_FAILED_EVENT]

    @pytest.mark.parametrize("error", _REDIS_ERRORS, ids=_REDIS_ERROR_IDS)
    async def test_failed_release_leaves_the_lock_to_expire(
        self,
        redis_client: redis_asyncio.Redis,
        server: JsonRpcServer,
        monkeypatch: pytest.MonkeyPatch,
        error: Exception,
    ) -> None:
        _use_faulty_redis(monkeypatch, {"release"}, error)

        with capture_logs() as logs:
            result = await service.get_needinfo_count()

        assert result.count == 1
        assert await redis_client.exists(CACHE_KEY) == 1
        assert 10 < await _ttl(redis_client, LOCK_KEY) <= 15
        assert [r["event"] for r in _failure_records(logs)] == [CACHE_FAILED_EVENT]

    @pytest.mark.parametrize("error", _REDIS_ERRORS, ids=_REDIS_ERROR_IDS)
    @pytest.mark.usefixtures("lock_held_elsewhere")
    async def test_failure_during_the_wait_raises(
        self,
        server: JsonRpcServer,
        monkeypatch: pytest.MonkeyPatch,
        error: Exception,
    ) -> None:
        _use_faulty_redis(monkeypatch, {"poll"}, error)

        with capture_logs() as logs, pytest.raises(BugzillaUnavailableError):
            await service.get_needinfo_count()

        assert server.requests == []
        assert _failure_records(logs) == [
            {
                "event": CACHE_FAILED_EVENT,
                "log_level": "warning",
                "error_type": type(error).__name__,
            }
        ]

    async def test_several_failures_of_one_invocation_log_once(
        self,
        redis_client: redis_asyncio.Redis,
        server: JsonRpcServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _use_faulty_redis(
            monkeypatch, {"reget", "write", "release"}, redis_exceptions.RedisError()
        )

        with capture_logs() as logs:
            result = await service.get_needinfo_count()

        assert result.count == 1
        assert [r["event"] for r in _failure_records(logs)] == [CACHE_FAILED_EVENT]

    async def test_each_invocation_logs_its_own_failure(
        self,
        redis_client: redis_asyncio.Redis,
        server: JsonRpcServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _use_faulty_redis(monkeypatch, {"get"}, redis_exceptions.RedisError())

        with capture_logs() as logs:
            await service.get_needinfo_count()
            await service.get_needinfo_count()

        assert [r["event"] for r in _failure_records(logs)] == [
            CACHE_FAILED_EVENT,
            CACHE_FAILED_EVENT,
        ]
        assert len(server.requests) == 2


# ---------------------------------------------------------------------------
# Security and Privacy; Service Exceptions
# ---------------------------------------------------------------------------


_Scenario = Callable[[JsonRpcServer], None]


def _serve(responder: rpc.Responder) -> _Scenario:
    def apply(server: JsonRpcServer) -> None:
        server.default = responder

    return apply


@pytest.mark.integration
@pytest.mark.usefixtures("backoff", "with_key")
class TestNoDisclosure:
    @pytest.mark.parametrize(
        "scenario",
        [
            _serve(rpc.fixture(AUTHENTICATED_FIXTURE)),
            _serve(rpc.fixture(INVALID_KEY_FIXTURE)),
            _serve(rpc.document(rpc.error_document(102))),
            _serve(rpc.raw(b'{"error":null,"result":{"bugs":[{"id":1291902.5}]}}')),
            _serve(rpc.status(403)),
            _serve(rpc.raising(httpx.ConnectError(f"fictional {API_KEY}"))),
        ],
        ids=[
            "count",
            "api_key_rejected",
            "bugzilla_error",
            "invalid",
            "http",
            "transport",
        ],
    )
    async def test_no_log_value_or_result_carries_the_key_or_a_bug_id(
        self,
        redis_client: redis_asyncio.Redis,
        server: JsonRpcServer,
        caplog: pytest.LogCaptureFixture,
        scenario: _Scenario,
    ) -> None:
        scenario(server)
        caplog.set_level("DEBUG")

        with capture_logs() as logs:
            try:
                result: object = await service.get_needinfo_count()
            except BugzillaUnavailableError as exc:
                result = exc

        stored = await redis_client.get(CACHE_KEY)
        rendered = " ".join(
            [str(logs), caplog.text, str(stored), repr(result), str(result)]
        )
        for secret in (API_KEY, str(RESTRICTED_TEST_BUG), str(PUBLIC_TEST_BUG)):
            assert secret not in rendered
        for bugzilla_text in ("you specified", "Fictional error message"):
            assert bugzilla_text not in rendered


@pytest.mark.unit
class TestServiceExceptions:
    def test_unavailable_error_has_the_fixed_message_and_base(self) -> None:
        error = BugzillaUnavailableError()

        assert str(error) == "No valid count could be obtained from SUSE Bugzilla."
        assert isinstance(error, BugzillaNeedinfoServiceError)
        assert issubclass(BugzillaNeedinfoServiceError, ServiceError)
