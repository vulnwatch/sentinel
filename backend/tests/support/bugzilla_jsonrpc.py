"""SUSE Bugzilla JSON-RPC fixtures and a fake `/jsonrpc.cgi` endpoint.

The `jsonrpc_*.json` files under `backend/tests/fixtures/bugzilla/` are live
`POST https://bugzilla.suse.com/jsonrpc.cgi` answers to the fixed
`Bug.search` of the needinfo count
(docs/features/integrations/bugzilla-needinfo-count.md, Search Request),
captured on 2026-11-26 (Bugzilla 5.0.6) with `Content-Type:
application/json` and `Accept: application/json`, and stored
byte-for-byte. Every answer was HTTP 200 `application/json;
charset=UTF-8` without a content coding:

- `jsonrpc_search_anonymous.json`: the search without `Bugzilla_api_key`.
  It returned only the public test bug bsc#1291903;
- `jsonrpc_search_authenticated.json`: the search with the API key of a
  Bugzilla account that sees the security team's restricted bugs. It
  returned the restricted test bug bsc#1291902 and bsc#1291903;
- `jsonrpc_error_invalid_api_key.json`: the search with a fictional,
  invalid key, answered with `error.code` 306.

No sanitization was needed: `include_fields: ["id"]` returns only bug IDs,
which are not personal identifiers, and the only bugs that matched were
the two test bugs. The error `message` is Bugzilla's fixed text. No API key
appears in any file.

`JsonRpcServer` is an in-process `httpx.MockTransport` handler: it records
every request and answers a `POST` to the endpoint with the next queued
responder, or with `default` when the queue is empty; any other request is
answered with HTTP 404.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Callable, Iterable
from pathlib import Path
from typing import Any, Final

import httpx

from tests.support.inadmissible import json_bytes

FIXTURE_DIR: Final = Path(__file__).resolve().parents[1] / "fixtures" / "bugzilla"

JSONRPC_HOST: Final = "bugzilla.suse.com"
JSONRPC_PATH: Final = "/jsonrpc.cgi"
JSONRPC_URL: Final = f"https://{JSONRPC_HOST}{JSONRPC_PATH}"

ANONYMOUS_FIXTURE: Final = "jsonrpc_search_anonymous"
AUTHENTICATED_FIXTURE: Final = "jsonrpc_search_authenticated"
INVALID_KEY_FIXTURE: Final = "jsonrpc_error_invalid_api_key"

RESTRICTED_TEST_BUG: Final = 1291902
PUBLIC_TEST_BUG: Final = 1291903
INVALID_API_KEY_CODE: Final = 306

JSON_CONTENT_TYPE: Final = "application/json; charset=UTF-8"
"""The live `Content-Type` of every answer."""


def load_raw_fixture(name: str) -> bytes:
    """Return one fixture's bytes as served."""
    return (FIXTURE_DIR / f"{name}.json").read_bytes()


def load_fixture(name: str) -> dict[str, Any]:
    """Return one fixture as parsed JSON."""
    data: dict[str, Any] = json.loads(load_raw_fixture(name))
    return data


def count_document(bug_ids: Iterable[int]) -> dict[str, Any]:
    """A live-shaped successful answer holding `bug_ids`."""
    return {
        "error": None,
        "id": 1,
        "result": {"bugs": [{"id": bug_id} for bug_id in bug_ids]},
    }


def error_document(code: Any) -> dict[str, Any]:
    """A live-shaped error answer with `code`."""
    return {
        "result": None,
        "id": 1,
        "error": {"code": code, "message": "Fictional error message."},
    }


Responder = Callable[[httpx.Request], httpx.Response]


def raw(content: bytes, status_code: int = 200) -> Responder:
    """A responder that serves `content` unchanged as JSON."""

    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code,
            content=content,
            headers={"Content-Type": JSON_CONTENT_TYPE},
            request=request,
        )

    return respond


def fixture(name: str) -> Responder:
    """A responder that serves one fixture as captured."""
    return raw(load_raw_fixture(name))


def document(value: Any, status_code: int = 200) -> Responder:
    """A responder that serves the JSON `value`."""
    return raw(json_bytes(value), status_code)


def status(code: int, headers: dict[str, str] | None = None) -> Responder:
    """A responder that answers `code` with an empty body."""

    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(code, headers=headers or {}, request=request)

    return respond


def raising(error: Exception) -> Responder:
    """A responder that raises `error` (for example `httpx.ConnectError`)."""

    def respond(request: httpx.Request) -> httpx.Response:
        raise error

    return respond


def undecodable() -> Responder:
    """A responder whose body declares `gzip` but is not gzip."""

    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Encoding": "gzip", "Content-Type": JSON_CONTENT_TYPE},
            stream=httpx.ByteStream(b"not gzip"),
            request=request,
        )

    return respond


class _InterruptedStream(httpx.AsyncByteStream):
    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield b'{"error":null,'
        raise httpx.ReadError("fictional interruption")


def interrupted() -> Responder:
    """A responder whose HTTP 200 body breaks off with `httpx.ReadError`."""

    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Type": JSON_CONTENT_TYPE},
            stream=_InterruptedStream(),
            request=request,
        )

    return respond


def is_jsonrpc_request(request: httpx.Request) -> bool:
    """Whether `request` is a `POST` to `https://bugzilla.suse.com/jsonrpc.cgi`
    without an explicit port or a query."""
    url = request.url
    return (
        request.method == "POST"
        and url.scheme == "https"
        and url.host == JSONRPC_HOST
        and url.port is None
        and url.path == JSONRPC_PATH
        and not url.query
    )


class JsonRpcServer:
    """A fake `/jsonrpc.cgi` endpoint for `httpx.MockTransport`."""

    def __init__(self, default: Responder | None = None) -> None:
        self.default: Responder = default or fixture(ANONYMOUS_FIXTURE)
        self.queue: list[Responder] = []
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if not is_jsonrpc_request(request):
            return httpx.Response(404, request=request)
        responder = self.queue.pop(0) if self.queue else self.default
        return responder(request)

    @property
    def bodies(self) -> list[dict[str, Any]]:
        """The decoded body of every recorded request."""
        return [json.loads(request.content) for request in self.requests]
