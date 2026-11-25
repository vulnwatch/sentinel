"""ASGI middleware for request correlation.

Implements the `X-Request-ID` request tracing contract defined in
`docs/api-spec.md` (Request Tracing) and the `request_id` correlation
binding defined in `docs/features/platform/logging.md`.
"""

from __future__ import annotations

import re
import uuid
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from starlette.types import ASGIApp, Message, Receive, Scope, Send

_REQUEST_ID_HEADER = b"x-request-id"
_RESPONSE_HEADER_NAME = b"x-request-id"
_VALID_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_MAX_REQUEST_ID_LENGTH = 128


def _extract_client_request_id(scope: Scope) -> str | None:
    """Extract and validate the client-supplied `X-Request-ID` header.

    Returns the validated, trimmed value, or `None` if the header is
    absent or fails validation (empty/whitespace-only, longer than 128
    characters after trimming, or containing characters outside
    `[A-Za-z0-9._-]`). Only the first occurrence is considered per
    `docs/api-spec.md` (Request Tracing) — an invalid first occurrence
    is not rescued by a valid subsequent one.
    """
    headers: list[tuple[bytes, bytes]] = scope.get("headers", [])
    for name, value in headers:
        if name.lower() == _REQUEST_ID_HEADER:
            candidate = value.decode("latin-1").strip()
            if (
                candidate
                and len(candidate) <= _MAX_REQUEST_ID_LENGTH
                and _VALID_REQUEST_ID_RE.fullmatch(candidate)
            ):
                return candidate
            return None
    return None


class RequestIDMiddleware:
    """Pure ASGI middleware binding a request-scoped `request_id`.

    Deliberately implemented as raw ASGI middleware rather than
    Starlette's `BaseHTTPMiddleware`: the `try`/`finally` here wraps
    the *entire* scope Starlette executes for the request, including
    any `BackgroundTask` attached to the response (which runs after the
    response body is sent, but within the same downstream `app.__call__`
    invocation). This guarantees log lines emitted by a background task
    still carry `request_id`, and that the context is reset only once
    that full lifecycle completes.

    `app.main` installs it around the whole middleware stack the framework
    builds, outside Starlette's `ServerErrorMiddleware`, rather than with
    `add_middleware`: the `500` that `ServerErrorMiddleware` renders for
    an unhandled exception is then sent through `send_wrapper`, and is
    logged while `request_id` is still bound.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = _extract_client_request_id(scope) or str(uuid.uuid7())

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = message.setdefault("headers", [])
                headers.append((_RESPONSE_HEADER_NAME, request_id.encode("latin-1")))
            await send(message)

        tokens = structlog.contextvars.bind_contextvars(request_id=request_id)
        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            structlog.contextvars.reset_contextvars(**tokens)
