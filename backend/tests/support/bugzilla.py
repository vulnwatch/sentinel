"""Shared SUSE Bugzilla fixtures and a fake `/rest/bug` endpoint.

The files under `backend/tests/fixtures/bugzilla/` listed below are live
`GET https://bugzilla.suse.com/rest/bug` responses captured anonymously on
2026-11-16 through Sentinel's production HTTP client
(`create_http_client(name="sync_bugzilla_bugs")`: its standard User-Agent,
`Accept: application/json`, and `Accept-Encoding: gzip, deflate`; every
response was served without a content coding). Every request selected the
consumed fields with `include_fields=id,alias,summary,groups`
(docs/features/tickets/cve-sync-bugzilla.md, Algorithm):

- `page.json`: seven bugs of the first page of the periodic query
  `?include_fields=id,alias,summary,groups&f1=alias&o1=substring&v1=CVE-&f2=bug_id&o2=greaterthan&v2=0&last_change_time=2026-11-16T07:17:01Z&order=bug_id&limit=1000`,
  which held 162 bugs. The seven keep their ascending order and the
  first page's last bug, and include a `VUL-1` bug, a bug with four CVE
  aliases, a bug with a CVE and a GHSA alias, and a bug with 52 CVE
  aliases;
- `page_empty.json`: the closing page of the same query with
  `v2=1290610`, the last bug of the first page, stored byte-for-byte;
- `single.json`: the `?include_fields=id,alias,summary,groups&alias=CVE-2024-3094`
  answer, one bug. The same query with `alias=cve-2024-3094` was answered
  with the identical body;
- `single_multi.json`: the `alias=CVE-2026-113399` answer, the bug of
  `page.json` with four CVE aliases;
- `single_empty.json`: the `alias=CVE-2099-0001` answer for an absent
  alias, stored byte-for-byte;
- `rest_html.html`: the same absent-alias query sent with
  `Accept: text/html`, answered with HTTP 200 `text/html`, stored
  byte-for-byte;
- `error_400.json`: the HTTP 400 answer to an unknown search field
  (`f1=nonexistent_field`), stored byte-for-byte.

The `jsonrpc_*.json` files of the same directory belong to the needinfo
count and are described in `tests/support/bugzilla_jsonrpc.py`.

The bugs were sanitized before saving (docs/conventions.md, External
Integration Contract Verification): every `summary` was replaced with
fictional text that keeps the `VUL-<n>:` prefix and, for up to four CVE
aliases, the CVE IDs; the member order of every bug object is the served
one. Bug IDs, CVE IDs, and GHSA IDs are public product data, not personal
identifiers, and are retained. No response contains a personal identifier:
`include_fields` excludes the reporter, assignee, QA contact, and CC list.

`BugzillaServer` is an in-process `httpx.MockTransport` handler for the
endpoint. A request with an `alias` parameter is a single query; any other
request is a page request answered from `bugs` by its keyset parameter
`v2`, at most `page_cap` bugs per page as the live server caps a response.
Tests override raw responses and inspect the recorded requests in order.

Consumers, all under `tests/test_services/test_tickets/`: the contract
tests of `test_bugzilla_bug_contract.py`, and the parser and fetcher tests
of `sync_bugzilla_bugs`.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any, Final

import httpx

from tests.support.inadmissible import json_bytes

FIXTURE_DIR: Final = Path(__file__).resolve().parents[1] / "fixtures" / "bugzilla"

BUGZILLA_HOST: Final = "bugzilla.suse.com"
BUG_PATH: Final = "/rest/bug"
BUG_URL: Final = f"https://{BUGZILLA_HOST}{BUG_PATH}"
"""The production endpoint, without query parameters."""

CONSUMED_FIELDS: Final = "id,alias,summary,groups"

PAGE_FIXTURE: Final = "page"
PAGE_EMPTY_FIXTURE: Final = "page_empty"
SINGLE_FIXTURE: Final = "single"
SINGLE_MULTI_FIXTURE: Final = "single_multi"
SINGLE_EMPTY_FIXTURE: Final = "single_empty"
ERROR_400_FIXTURE: Final = "error_400"
HTML_FIXTURE: Final = "rest_html.html"
"""The HTML answer to `Accept: text/html`, by file name."""

PAGE_WINDOW_START: Final = "2026-11-16T07:17:01Z"
PAGE_LAST_BUG_ID: Final = 1290610
"""The last bug of the captured first page, and the `v2` of its empty page."""
SINGLE_CVE_ID: Final = "CVE-2024-3094"
SINGLE_BUG_ID: Final = 1222124
SINGLE_MULTI_CVE_ID: Final = "CVE-2026-113399"
SINGLE_MULTI_BUG_ID: Final = 1286385
ABSENT_CVE_ID: Final = "CVE-2099-0001"

JSON_CONTENT_TYPE: Final = "application/json; charset=UTF-8"
"""The live `Content-Type` of every JSON response."""
HTML_CONTENT_TYPE: Final = "text/html; charset=UTF-8"


def load_fixture(name: str) -> dict[str, Any]:
    """Return one JSON fixture as parsed JSON."""
    data: dict[str, Any] = json.loads(load_raw_fixture(name))
    return data


def load_raw_fixture(name: str) -> bytes:
    """Return one fixture file's bytes unparsed (a body as served); a name
    without a suffix is a `.json` file."""
    file_name = name if "." in name else f"{name}.json"
    return (FIXTURE_DIR / file_name).read_bytes()


def page_bugs() -> list[dict[str, Any]]:
    """The bugs of `page.json` (fresh copies)."""
    bugs: list[dict[str, Any]] = load_fixture(PAGE_FIXTURE)["bugs"]
    return bugs


def bug(
    bug_id: int,
    *aliases: str,
    summary: str | None = None,
    groups: Sequence[Any] = (),
) -> dict[str, Any]:
    """A live-shaped bug with the consumed members only."""
    return {
        "id": bug_id,
        "alias": list(aliases),
        "summary": (
            summary
            if summary is not None
            else f"VUL-0: {', '.join(aliases)}: example-package: fictional summary"
        ),
        "groups": list(groups),
    }


def envelope(bugs: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """A response root carrying `bugs`."""
    return {"bugs": [dict(item) for item in bugs]}


def bug_reference_url(bug_id: int) -> str:
    """The reference URL of a bug (cve-sync-bugzilla.md, Bug Reference)."""
    return f"https://{BUGZILLA_HOST}/show_bug.cgi?id={bug_id}"


Responder = Callable[[httpx.Request], httpx.Response]


def raising(error: Exception) -> Responder:
    """A responder that raises `error` (for example `httpx.ConnectError`)."""

    def respond(request: httpx.Request) -> httpx.Response:
        raise error

    return respond


def status(
    code: int, content: bytes = b"", headers: Mapping[str, str] | None = None
) -> Responder:
    """A responder that answers with `code`, the raw `content`, and
    `headers`."""

    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            code, content=content, headers=dict(headers or {}), request=request
        )

    return respond


def undecodable(code: int) -> Responder:
    """A responder whose body declares `gzip` but is not gzip, so reading it
    raises `httpx.DecodingError`."""

    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            code,
            headers={"Content-Encoding": "gzip"},
            stream=httpx.ByteStream(b"not gzip"),
            request=request,
        )

    return respond


def body(value: Any) -> Responder:
    """A responder that serves the JSON `value` with HTTP 200; a surrogate
    code point travels as its `\\uXXXX` escape."""

    def respond(request: httpx.Request) -> httpx.Response:
        return _json_response(request, value)

    return respond


def html(code: int = 200) -> Responder:
    """A responder that serves the live HTML answer with `code`."""

    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            code,
            content=load_raw_fixture(HTML_FIXTURE),
            headers={"Content-Type": HTML_CONTENT_TYPE},
            request=request,
        )

    return respond


def _json_response(request: httpx.Request, value: Any) -> httpx.Response:
    return httpx.Response(
        200,
        content=json_bytes(value),
        headers={"Content-Type": JSON_CONTENT_TYPE},
        request=request,
    )


def is_bug_request(request: httpx.Request) -> bool:
    """Whether `request` targets `https://bugzilla.suse.com/rest/bug` (no
    explicit port)."""
    url = request.url
    return (
        url.scheme == "https"
        and url.host == BUGZILLA_HOST
        and url.port is None
        and url.path == BUG_PATH
    )


def requested_alias(request: httpx.Request) -> str | None:
    """The `alias` parameter of a single query, or `None` for a page
    request or another endpoint."""
    if not is_bug_request(request):
        return None
    values = request.url.params.get_list("alias")
    return values[0] if len(values) == 1 else None


def requested_after_id(request: httpx.Request) -> int | None:
    """The keyset `v2` of a page request, or `None` for a single query,
    another endpoint, or a non-integer value."""
    if not is_bug_request(request) or "alias" in request.url.params:
        return None
    value = request.url.params.get("v2")
    if value is None or not value.isdigit():
        return None
    return int(value)


class BugzillaServer:
    """A fake `/rest/bug` endpoint for `httpx.MockTransport`.

    A request with an `alias` parameter is a single query:
    `single_responses[alias]` answers it when present; otherwise
    `singles[alias]` (a list of bugs, `[]` when absent) is served with HTTP
    200. Any other request to the endpoint is a page request, numbered from
    0 in arrival order: `page_responses[i]` answers page request `i` when
    present; otherwise the server answers with the bugs of `bugs` whose ID
    is greater than the request's `v2`, in ascending ID order, at most
    `page_cap` of them. A request to another scheme, host, port, or path,
    and a page request without an integer `v2`, are answered with HTTP 404.
    Every request is recorded in `requests`, in order.
    """

    def __init__(
        self,
        bugs: Iterable[Mapping[str, Any]] = (),
        singles: Mapping[str, Sequence[Mapping[str, Any]]] | None = None,
        *,
        page_cap: int = 1000,
    ) -> None:
        self.bugs: list[dict[str, Any]] = [dict(item) for item in bugs]
        self.singles: dict[str, list[dict[str, Any]]] = {
            alias: [dict(item) for item in items]
            for alias, items in (singles or {}).items()
        }
        self.page_cap = page_cap
        self.page_responses: dict[int, Responder] = {}
        self.single_responses: dict[str, Responder] = {}
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if not is_bug_request(request):
            return httpx.Response(404, request=request)
        alias = requested_alias(request)
        if alias is not None:
            if alias in self.single_responses:
                return self.single_responses[alias](request)
            return _json_response(request, envelope(self.singles.get(alias, [])))
        index = len(self.page_requests) - 1
        if index in self.page_responses:
            return self.page_responses[index](request)
        after_id = requested_after_id(request)
        if after_id is None:
            return httpx.Response(404, request=request)
        page = sorted(
            (item for item in self.bugs if item["id"] > after_id),
            key=lambda item: int(item["id"]),
        )[: self.page_cap]
        return _json_response(request, envelope(page))

    def client(self) -> httpx.AsyncClient:
        """A client whose transport is this server (redirects not followed)."""
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handler))

    @property
    def requested_urls(self) -> list[str]:
        return [str(request.url) for request in self.requests]

    @property
    def page_requests(self) -> list[httpx.Request]:
        """The recorded endpoint requests without an `alias` parameter."""
        return [
            request
            for request in self.requests
            if is_bug_request(request) and "alias" not in request.url.params
        ]

    @property
    def single_requests(self) -> list[httpx.Request]:
        """The recorded endpoint requests with an `alias` parameter."""
        return [
            request for request in self.requests if requested_alias(request) is not None
        ]

    @property
    def requested_after_ids(self) -> list[int | None]:
        return [requested_after_id(request) for request in self.page_requests]
