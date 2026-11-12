"""Sanitized Slack `users.lookupByEmail` fixtures and a fake Slack Web API.

The fixtures under `backend/tests/fixtures/slack/` reproduce the structure of
live responses of `POST https://slack.com/api/users.lookupByEmail` with a form
body, obtained on 2026-11-12 from SUSE's workspace with the bot token of the
Sentinel Slack app and consenting accounts
(docs/features/identity/user-avatars.md, Slack Integration). Only the
structure was kept: the member names, their order, their nesting, and their
JSON types are the live ones, and every value is fictional, so no fixture
holds a personal identifier (docs/conventions.md, Example Data in
Documentation; External Integration Contract Verification). Every string
member that the fetcher does not consume carries a distinctive fictional
value, so that a privacy test can search logs for it.

- `lookup_uploaded.json`: a member with a picture uploaded to Slack; every
  `image_*` member is on `avatars.slack-edge.com` without a query, with
  `is_custom_image` and `image_original`.
- `lookup_gravatar.json`: a member without an uploaded picture; every
  `image_*` member is a Gravatar URL whose default image is Slack's generic
  avatar, without `is_custom_image`, `image_original`, and `image_1024`, and
  `avatar_hash` starts with `g`. A member whose Gravatar is Slack's generic
  avatar has the same form.
- `users_not_found.json`, `invalid_auth.json`, `not_authed.json`, and
  `invalid_arguments.json`: the `ok: false` bodies of an unknown address, an
  invalid token, a request without a token, and a request without `email`.

`SlackServer` is an in-process `httpx.MockTransport` handler for the lookup
URL: it serves the response that a test assigns to an email address, records
every request, and answers any other URL with HTTP 404.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any, Final
from urllib.parse import parse_qs

import httpx

from tests.support.inadmissible import json_bytes

FIXTURE_DIR: Final = Path(__file__).resolve().parents[1] / "fixtures" / "slack"

LOOKUP_URL: Final = "https://slack.com/api/users.lookupByEmail"
"""The production lookup URL (user-avatars.md, Lookup Request)."""

UPLOADED_PICTURE: Final = (
    "https://avatars.slack-edge.com/2026-01-15/"
    "1000000000001_0f1c7e00000000000000_192.jpg"
)
"""The `image_192` of `lookup_uploaded.json`."""

TOKEN: Final = "fictional-slack-bot-token-for-tests"
"""A fictional bot token, printable ASCII without whitespace. It has no
`xoxb-` prefix, so the secret scanner does not mistake it for a real one."""

FIXTURES: Final = (
    "lookup_uploaded",
    "lookup_gravatar",
    "users_not_found",
    "invalid_auth",
    "not_authed",
    "invalid_arguments",
)


def load_raw(name: str) -> bytes:
    """The bytes of the fixture `name` (without `.json`)."""
    return (FIXTURE_DIR / f"{name}.json").read_bytes()


def load(name: str) -> dict[str, Any]:
    """The fixture `name` as parsed JSON (a fresh copy)."""
    document: dict[str, Any] = json.loads(load_raw(name))
    return document


def found(image_192: Any = UPLOADED_PICTURE) -> dict[str, Any]:
    """A live-shaped found body: `lookup_uploaded.json` with `image_192`
    replaced."""
    document = load("lookup_uploaded")
    document["user"]["profile"]["image_192"] = image_192
    return document


def error(code: Any) -> dict[str, Any]:
    """A live-shaped `ok: false` body with the given `error`."""
    return {"ok": False, "error": code}


def unconsumed_strings(document: Any, path: tuple[str, ...] = ()) -> set[str]:
    """Every string value of `document` outside the consumed members `ok`,
    `error`, and `user.profile.image_192` (user-avatars.md, Response
    Contract)."""
    if isinstance(document, dict):
        return {
            value
            for key, item in document.items()
            for value in unconsumed_strings(item, (*path, key))
        }
    if isinstance(document, list):
        return {value for item in document for value in unconsumed_strings(item, path)}
    if isinstance(document, str) and path not in {
        ("error",),
        ("user", "profile", "image_192"),
    }:
        return {document}
    return set()


Responder = Callable[[httpx.Request], httpx.Response]


def body(document: Any, code: int = 200, **headers: str) -> Responder:
    """A responder that serves `document` as JSON with `code` and `headers`
    (underscores become hyphens). A surrogate code point travels as its
    `\\uXXXX` escape."""

    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            code,
            content=json_bytes(copy.deepcopy(document)),
            headers={
                "Content-Type": "application/json; charset=utf-8",
                **{key.replace("_", "-"): value for key, value in headers.items()},
            },
            request=request,
        )

    return respond


def raw(content: bytes, code: int = 200, **headers: str) -> Responder:
    """A responder that serves the raw `content` with `code` and `headers`."""

    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            code,
            content=content,
            headers={key.replace("_", "-"): value for key, value in headers.items()},
            request=request,
        )

    return respond


def raising(exception: Exception) -> Responder:
    """A responder that raises `exception`, for example `httpx.ConnectError`."""

    def respond(request: httpx.Request) -> httpx.Response:
        raise exception

    return respond


class SlackServer:
    """A fake `users.lookupByEmail` endpoint for `httpx.MockTransport`.

    `responses` maps an email address to the responder of its lookup; an
    address without one is answered with `users_not_found`. `response`, when
    set, answers every lookup instead. Every request is recorded in
    `requests`, and `on_request`, when set, is called with each request
    before it is answered.
    """

    def __init__(self) -> None:
        self.responses: dict[str, Responder] = {}
        self.response: Responder | None = None
        self.requests: list[httpx.Request] = []
        self.on_request: Callable[[httpx.Request], None] | None = None

    def emails(self) -> list[str]:
        """The `email` form value of each recorded request, in order."""
        return [form(request)["email"][0] for request in self.requests]

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.on_request is not None:
            self.on_request(request)
        if str(request.url) != LOOKUP_URL:
            return httpx.Response(404, request=request)
        if self.response is not None:
            return self.response(request)
        email = form(request).get("email", [""])[0]
        responder = self.responses.get(email, body(error("users_not_found")))
        return responder(request)

    def client(self) -> httpx.AsyncClient:
        """A client whose transport is this server (redirects not followed)."""
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handler))


def form(request: httpx.Request) -> dict[str, list[str]]:
    """The decoded `application/x-www-form-urlencoded` body of `request`."""
    return parse_qs(request.content.decode("ascii"), keep_blank_values=True)
