"""Validated retrieval of the names of the SMELT maintained sweep.

Implements `docs/features/packages/maintained-package-names.md` (Fetcher:
`sync_smelt_packages`, Algorithm steps 1 to 5, and Error Handling) under the
origin and authentication contract of
`docs/features/packages/product-catalog.md` (SMELT Integration, Origin,
Authentication, and Pagination): every page request is built from the
configured HTTPS API prefix, is anonymous, and never follows a redirect.
Pages are requested sequentially from page 1, each exactly once, and the
complete sweep is validated before its names are returned; any failure
raises `FetcherError` with a sanitized message and returns no name.

The module performs network I/O only; callers must not hold an open
database transaction while awaiting it. Logs identify the failed page and
the validation category, never a response payload or an upstream value.
"""

from __future__ import annotations

import asyncio
from typing import Any, Final, Literal, NoReturn

import httpx
import structlog
from pydantic import BaseModel, ConfigDict, ValidationError

from app.core.external_strings import contains_inadmissible_character
from app.services.base_fetcher import FetcherError
from app.services.json_decoding import decode_json
from app.services.packages.maintained_package_names import NAME_MAX_LENGTH

logger = structlog.get_logger(__name__)

SWEEP_ENDPOINT_PATH: Final = "experimental/v2/maintained/"
PAGE_SIZE: Final = 200

CONNECTION_FAILED_MESSAGE: Final = "Failed to connect to SMELT"
TIMEOUT_MESSAGE: Final = "SMELT request timed out"
INVALID_RESPONSE_MESSAGE: Final = "SMELT returned invalid maintained package response"
VALIDATION_FAILED_MESSAGE: Final = "SMELT maintained package validation failed"

_CREDENTIAL_HEADERS: Final = ("authorization", "cookie")


class _SweepData(BaseModel):
    """The `data` object of one sweep page (unknown fields ignored).

    Strict: a JSON boolean is not an integer and a number is not a boolean.
    """

    model_config = ConfigDict(strict=True, extra="ignore", frozen=True)

    results: list[Any]
    page: int
    page_size: int
    has_next: bool
    has_previous: bool


class _SweepPage(BaseModel):
    """One JSend sweep page envelope (unknown fields ignored)."""

    model_config = ConfigDict(strict=True, extra="ignore", frozen=True)

    status: Literal["success"]
    data: _SweepData


class _InvalidPageError(Exception):
    """An envelope or pagination violation on one page.

    The message names the page and the violated rule only.
    """


class _InvalidResultError(Exception):
    """A result without a valid `package`, or an empty sweep.

    The message names the page, the result position, and the rule only.
    """


def sweep_page_url(api_url: str, page: int) -> str:
    """Return the URL of one sweep page for a canonical `SMELT_API_URL`.

    The query carries exactly `include_reactive_ltss=true`, the fixed
    `page_size`, and `page` (Algorithm, step 1).
    """
    return (
        f"{api_url}/{SWEEP_ENDPOINT_PATH}"
        f"?include_reactive_ltss=true&page_size={PAGE_SIZE}&page={page}"
    )


async def fetch_maintained_package_names(
    client: httpx.AsyncClient, *, api_url: str, request_delay: float
) -> frozenset[str]:
    """Retrieve and validate the names of the complete maintained sweep.

    `api_url` is the validated, canonical `SMELT_API_URL`; `request_delay`
    is the run's configured delay in seconds, which separates consecutive
    page requests, with no wait before page 1. Returns the non-empty set of
    the `package` values of every result, unchanged. Raises `FetcherError`
    with a sanitized message on any failure (Error Handling); no partial
    set is ever returned.
    """
    names: set[str] = set()
    page = 1
    while True:
        if page > 1 and request_delay > 0:
            await asyncio.sleep(request_delay)
        body = await _get_page(client, sweep_page_url(api_url, page), page)
        try:
            data = _parse_page(body, page)
        except _InvalidPageError as exc:
            _log_invalid(page, exc)
            raise FetcherError(INVALID_RESPONSE_MESSAGE) from exc
        try:
            names.update(_page_names(data.results, page))
        except _InvalidResultError as exc:
            _log_invalid(page, exc)
            raise FetcherError(VALIDATION_FAILED_MESSAGE) from exc
        if not data.has_next:
            break
        page += 1

    if not names:
        empty = _InvalidResultError("the sweep holds no result")
        _log_invalid(page, empty)
        raise FetcherError(VALIDATION_FAILED_MESSAGE) from empty
    return frozenset(names)


async def _get_page(client: httpx.AsyncClient, url: str, page: int) -> Any:
    """Request one page anonymously and return its decoded JSON body.

    Client authentication is disabled and any default credential or cookie
    header is removed, whatever the client's defaults; a redirect is never
    followed and is a non-200 response.
    """
    request = client.build_request("GET", url)
    for header in _CREDENTIAL_HEADERS:
        request.headers.pop(header, None)
    try:
        response = await client.send(request, auth=None, follow_redirects=False)
    except httpx.TimeoutException as exc:
        _log_request_failed(page, "timeout")
        raise FetcherError(TIMEOUT_MESSAGE) from exc
    except httpx.DecodingError:
        invalid = _InvalidPageError(f"page {page}: undecodable body")
        _log_invalid(page, invalid)
        raise FetcherError(INVALID_RESPONSE_MESSAGE) from invalid
    except httpx.RequestError as exc:
        _log_request_failed(page, "connection")
        raise FetcherError(CONNECTION_FAILED_MESSAGE) from exc

    status_code = response.status_code
    if status_code != 200:
        _log_request_failed(page, "http_status", status_code=status_code)
        raise FetcherError(f"SMELT returned HTTP {status_code}")

    try:
        return decode_json(response.content)
    except ValueError:
        invalid = _InvalidPageError(f"page {page}: body is not valid JSON")
        _log_invalid(page, invalid)
        raise FetcherError(INVALID_RESPONSE_MESSAGE) from invalid


def _parse_page(body: Any, page: int) -> _SweepData:
    """Validate the envelope and pagination of one page (step 2)."""
    try:
        data = _SweepPage.model_validate(body).data
    except ValidationError as exc:
        fields = sorted(
            {
                ".".join(str(part) for part in error["loc"][:2])
                for error in exc.errors()
                if error["loc"]
            }
        )
        detail = ", ".join(fields) if fields else "envelope"
        # Raised from None: the validation error renders input values.
        raise _InvalidPageError(
            f"page {page}: invalid response schema ({detail})"
        ) from None
    if data.page != page:
        _invalid_page(page, "page does not equal the requested page")
    if data.page_size != PAGE_SIZE:
        _invalid_page(page, "page_size does not equal the requested page size")
    if data.has_previous is not (page > 1):
        _invalid_page(page, "has_previous must be false exactly on page 1")
    if data.has_next and len(data.results) != PAGE_SIZE:
        _invalid_page(page, "a page with a next page does not hold a full page")
    return data


def _page_names(results: list[Any], page: int) -> list[str]:
    """The `package` value of every result of one page (steps 2 and 3)."""
    names: list[str] = []
    for position, result in enumerate(results):
        if not isinstance(result, dict):
            _invalid_result(page, position, "result is not an object")
        name = result.get("package")
        if not isinstance(name, str) or name == "":
            _invalid_result(page, position, "package must be a non-empty string")
        if len(name) > NAME_MAX_LENGTH:
            _invalid_result(
                page, position, f"package exceeds {NAME_MAX_LENGTH} characters"
            )
        if contains_inadmissible_character(name):
            _invalid_result(
                page, position, "package contains an inadmissible character"
            )
        names.append(name)
    return names


def _invalid_page(page: int, rule: str) -> NoReturn:
    raise _InvalidPageError(f"page {page}: {rule}")


def _invalid_result(page: int, position: int, rule: str) -> NoReturn:
    raise _InvalidResultError(f"page {page}, result {position}: {rule}")


def _log_request_failed(page: int, category: str, **fields: int) -> None:
    logger.warning(
        "smelt_maintained_sweep_request_failed", page=page, category=category, **fields
    )


def _log_invalid(page: int, exc: Exception) -> None:
    logger.warning(
        "smelt_maintained_sweep_response_invalid", page=page, category=str(exc)
    )
