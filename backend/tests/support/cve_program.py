"""Shared CVE Program CNA list fixture and a fake list endpoint.

`backend/tests/fixtures/cve_program/CNAsList.json` is a trimmed copy of the
live CNA list
`GET https://raw.githubusercontent.com/CVEProject/cve-website/main/src/assets/data/CNAsList.json`,
downloaded anonymously on 2026-11-09 without following redirects (HTTP 200,
`text/plain; charset=utf-8`, gzip content coding, 564 entries in 757,202
bytes). It keeps eleven live entries in their live order and member order,
indented like the live file:

- `CERTVDE`: the `CERT` type; `<strong>`, `<br/>`, a link whose text is its
  URL, and `&amp;`;
- `GitHub_M`: three types, no markup;
- `Google`: the `CNA.role` member that two live entries carry besides
  `CNA.roles`;
- `Patchstack`: five types, the most of any live entry;
- `ZTE`: a link whose text differs from its absolute URL;
- `Snow` and `SNOW`: the only two live short names that differ only in case;
- `samsung.tv_appliance`: `&amp;` and a link whose text is its URL;
- `CISA`: the `N/A` type and a relative link;
- `Linux`: the short name of the kernel CNA constant;
- `OAI`: a 77-character type, `<br/><br/>`, and a relative link inside
  `<strong>`.

The consumed members (`shortName`, `organizationName`, `scope`, and
`CNA.type`) are unmodified: they name organizations, products, and public
pages only. Every email address of `contact` and every URL outside the
consumed members (`contact`, `disclosurePolicy`, `securityAdvisories`) was
replaced with a fictional `example.com` value, because the contacts are not
consumed and may name a person (docs/conventions.md, External Integration
Contract Verification; docs/features/tickets/cna.md, Field Mapping).

`CnaListServer` is an in-process `httpx.MockTransport` handler for the list
URL (cna.md, Source): it serves `document` with HTTP 200, or the raw
`response` responder when a test sets one.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any, Final

import httpx

from tests.support.inadmissible import json_bytes

FIXTURE_PATH: Final = (
    Path(__file__).resolve().parents[1] / "fixtures" / "cve_program" / "CNAsList.json"
)

CNA_LIST_URL: Final = (
    "https://raw.githubusercontent.com/CVEProject/cve-website/main/"
    "src/assets/data/CNAsList.json"
)
"""The production URL (cna.md, Fetcher: `sync_mitre_cnas`, Source)."""

FIXTURE_SHORT_NAMES: Final = (
    "CERTVDE",
    "GitHub_M",
    "Google",
    "Patchstack",
    "ZTE",
    "Snow",
    "samsung.tv_appliance",
    "CISA",
    "Linux",
    "SNOW",
    "OAI",
)
"""The fixture entries' `shortName` values, in list order."""


def load_raw_list() -> bytes:
    """The fixture file's bytes, unparsed."""
    return FIXTURE_PATH.read_bytes()


def load_list() -> list[dict[str, Any]]:
    """The fixture list as parsed JSON (a fresh copy)."""
    entries: list[dict[str, Any]] = json.loads(load_raw_list().decode("utf-8"))
    return entries


def fixture_entry(short_name: str) -> dict[str, Any]:
    """The fixture entry whose `shortName` is `short_name` (a fresh copy)."""
    for entry in load_list():
        if entry["shortName"] == short_name:
            return entry
    raise KeyError(short_name)


def entry_for(
    short_name: Any,
    *,
    organization_name: Any = "Example Corporation",
    types: Any = ("Vendor",),
    scope: Any = "Example Corporation products only.",
) -> dict[str, Any]:
    """A live-shaped entry: the unconsumed members of the `GitHub_M` fixture
    entry with the given consumed values. A tuple `types` becomes a list."""
    entry = fixture_entry("GitHub_M")
    entry["shortName"] = short_name
    entry["organizationName"] = organization_name
    entry["CNA"]["type"] = list(types) if isinstance(types, tuple) else types
    entry["scope"] = scope
    return entry


Responder = Callable[[httpx.Request], httpx.Response]


def raising(error: Exception) -> Responder:
    """A responder that raises `error`, for example `httpx.ConnectError`."""

    def respond(request: httpx.Request) -> httpx.Response:
        raise error

    return respond


def status(code: int, content: bytes = b"", **headers: str) -> Responder:
    """A responder that answers with `code`, the raw `content`, and
    `headers` (underscores become hyphens)."""

    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            code,
            content=content,
            headers={key.replace("_", "-"): value for key, value in headers.items()},
            request=request,
        )

    return respond


def raw_body(content: bytes) -> Responder:
    """A responder that serves the raw `content` with HTTP 200, as the live
    host does (`text/plain`)."""
    return status(200, content, content_type="text/plain; charset=utf-8")


class CnaListServer:
    """A fake CNA list endpoint for `httpx.MockTransport`.

    `document` is the decoded JSON served with HTTP 200 (any JSON value;
    tests may replace it). `response`, when set, answers instead. Every
    request is recorded in `requests`, and `on_request`, when set, is called
    with each request before it is answered. A request for another URL is
    answered with HTTP 404.
    """

    def __init__(self, document: Any = None) -> None:
        self.document: Any = load_list() if document is None else document
        self.response: Responder | None = None
        self.requests: list[httpx.Request] = []
        self.on_request: Callable[[httpx.Request], None] | None = None

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.on_request is not None:
            self.on_request(request)
        if str(request.url) != CNA_LIST_URL:
            return httpx.Response(404, request=request)
        if self.response is not None:
            return self.response(request)
        # A surrogate code point travels as its `\\uXXXX` escape.
        return httpx.Response(
            200,
            content=json_bytes(copy.deepcopy(self.document)),
            headers={"Content-Type": "text/plain; charset=utf-8"},
            request=request,
        )

    def client(self) -> httpx.AsyncClient:
        """A client whose transport is this server (redirects not followed)."""
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handler))
