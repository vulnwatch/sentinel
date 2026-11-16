"""`sync_bugzilla_bugs`: SUSE Bugzilla bug-reference enrichment fetcher.

Implements docs/features/tickets/cve-sync-bugzilla.md on the CVE fetcher
contract of docs/features/platform/cve-fetcher-infrastructure.md:

- Every request is an anonymous `GET` of `https://bugzilla.suse.com/rest/bug`
  that selects the four consumed fields with `include_fields`, through the
  shared client (`Accept: application/json`, no redirects followed).
- `execute()` follows template 2 of Session Lifecycle for API-based CVE
  Fetchers with every request before the first per-CVE transaction: the
  derived cursor (`fetcher_execution.get_derived_cursor()`) is read and its
  transaction ended before the first request; a first run and a stale
  cursor return without any request. The window of the bugs with a CVE
  alias changed since 12 hours before the cursor is collected completely
  by keyset pagination on the bug ID, with the run's `request_delay`
  between pages, until a page returns no bug. A request or page failure
  aborts the run with a sanitized `FetcherError`. The public bugs are then
  grouped by exact CVE alias, and each CVE known to Sentinel is processed
  in its own transaction with `commit_and_dispatch()` outside the per-CVE
  catch; an unknown CVE is skipped silently.
- `fetch_single()` sends one `alias` query and links the public bugs that
  carry the CVE ID as an exact alias; every HTTP error status and every
  transport, decoding, and validation failure propagates as its original
  exception, so `is_retryable_condition()` keeps classifying it.
- `catch_up()` is the inherited `BaseCVEFetcher` default.

The fetcher supplies no CVE data: every `upsert_cve()` call carries an
empty `CVEIngestPayload`, and the only effect is one `issue` reference per
bug, titled with the bug summary.

`cve_service`, `reference_service`, and `fetcher_execution` are imported as
module objects and dereferenced at call time: `cve_service` belongs to the
import cycle of `base_cve_fetcher`.
"""

from __future__ import annotations

import asyncio
import uuid
from asyncio import CancelledError
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Final

import httpx
import structlog
from celery.exceptions import SoftTimeLimitExceeded
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import CVESourceFetchStatus, CVESourceType, ReferenceType
from app.models.cve import CVE
from app.services import cve_service, fetcher_execution, reference_service
from app.services.base_cve_fetcher import (
    CVE_FETCH_ITEM_FAILED_EVENT,
    BaseCVEFetcher,
    CVEFetchResult,
    CVENotInSource,
)
from app.services.base_fetcher import FetcherError
from app.services.cve_ingest import CVEIngestPayload
from app.services.json_decoding import decode_json
from app.services.tickets import bugzilla_bug_record
from app.services.tickets.bugzilla_bug_record import BugzillaBug, PageOrderError

logger = structlog.get_logger(__name__)

BUGZILLA_BUG_URL: Final = "https://bugzilla.suse.com/rest/bug"
"""The bug search endpoint of both the periodic query and `fetch_single()`."""

BUG_REFERENCE_URL: Final = "https://bugzilla.suse.com/show_bug.cgi?id={bug_id}"
"""The reference URL of one bug (Bug Reference)."""

INCLUDE_FIELDS: Final = "id,alias,summary,groups"
"""The consumed fields; no other field of a bug is requested."""

PAGE_SIZE: Final = 1000

BUGZILLA_CURSOR_RESET_EVENT: Final = "bugzilla_cursor_reset"
"""The stale-cursor WARNING (Stale Cursor Handling)."""

CONNECTION_FAILED: Final = "Failed to connect to SUSE Bugzilla"
UNPARSEABLE_RESPONSE: Final = "SUSE Bugzilla returned unparseable response"

_LOOKBACK: Final = timedelta(hours=12)
"""The distance between the cursor and the window start (Lookback)."""

_STALE_AFTER: Final = timedelta(days=30)
"""The window-start age beyond which the cursor is reset."""

_WINDOW_FORMAT: Final = "%Y-%m-%dT%H:%M:%SZ"


class BugzillaResponseError(Exception):
    """A `fetch_single()` answer with an HTTP 2xx status other than 200:
    neither a usable response nor an HTTP error. Non-retryable under the
    Error Categorization catch-all; the fixed message carries no upstream
    data."""

    def __init__(self) -> None:
        super().__init__("SUSE Bugzilla returned an unexpected response")


class SyncBugzillaBugs(BaseCVEFetcher):
    """Link CVEs to their public SUSE Bugzilla bugs."""

    name = "sync_bugzilla_bugs"
    cve_source_type = CVESourceType.BUGZILLA
    description = "Link CVEs to their SUSE Bugzilla bugs"
    default_schedule = "0 * * * *"
    default_request_delay = 1.0

    source_reference_url_pattern = None

    async def fetch_single(self, cve_id: str, session: AsyncSession) -> CVEFetchResult:
        """Link one CVE to its public bugs.

        Category A source ingestion into the caller-owned session.

        Q1: `cve_id` is the CVE-ID of an existing CVE; `session` is the
        caller's per-CVE session.

        Q2: a malformed `cve_id` raises `CVENotInSource` before any HTTP
        request.

        Q3: one `GET /rest/bug?include_fields=…&alias={cve_id}`, without
        redirects or request delay. The response is validated, and the
        public bugs whose CVE aliases contain `cve_id` exactly are linked:
        `upsert_cve()` with an empty payload, then `upsert_references()`
        with one `issue` candidate per bug in ascending bug ID order, both
        in `session`. Adds no flush beyond its delegates' own, never
        commits, and records no metric.

        Q4: `CVEFetchResult` with the effective `UpsertResult.action` and no
        package handoff.

        Q5: idempotent through `upsert_cve()` and the reference merge.

        Q6: no bug of the CVE (an empty `bugs`, only restricted bugs, or no
        exact CVE alias) raises `CVENotInSource` before any database work.
        An HTTP error status raises its original `httpx.HTTPStatusError`;
        another 2xx raises `BugzillaResponseError`. Transport errors,
        `httpx.DecodingError`, JSON decoding errors (`ValueError`),
        `pydantic.ValidationError` (schema mismatch), and delegate
        exceptions propagate unchanged.
        """
        if not self._is_valid_cve_id(cve_id):
            raise CVENotInSource()
        response = await self.http_client.get(
            BUGZILLA_BUG_URL,
            params={"include_fields": INCLUDE_FIELDS, "alias": cve_id},
        )
        if response.status_code != 200:
            response.raise_for_status()
            raise BugzillaResponseError()
        document = decode_json(response.content)
        bugs = bugzilla_bug_record.parse_response(document).bugs
        selected = bugzilla_bug_record.bugs_by_cve(bugs).get(cve_id)
        if not selected:
            raise CVENotInSource()
        return await self._ingest(session, cve_id, selected)

    async def execute(self, session: AsyncSession) -> None:
        """Periodic delta: bugs with a CVE alias changed since the last
        successful run, collected with keyset pagination before any
        per-CVE transaction."""
        now = datetime.now(UTC)
        last_sync = await fetcher_execution.get_derived_cursor(session, self.name)
        # End the read transaction before any Bugzilla request.
        await session.rollback()
        if last_sync is None:
            return  # First run: this run's started_at becomes the cursor.
        window_start = last_sync - _LOOKBACK
        if now - window_start > _STALE_AFTER:
            logger.warning(
                BUGZILLA_CURSOR_RESET_EVENT,
                fetcher_name=self.name,
                age_days=(now - window_start).days,
            )
            return
        bugs = await self._collect_window(window_start)
        for cve_id, cve_bugs in bugzilla_bug_record.bugs_by_cve(bugs).items():
            await self._process_cve(session, cve_id, cve_bugs)

    async def _collect_window(self, window_start: datetime) -> list[BugzillaBug]:
        """Algorithm step 4: every page of the window, with no database
        work. Only an empty page ends the collection."""
        request_delay = (
            self.config.request_delay
            if self.config is not None
            else self.default_request_delay
        )
        changed_since = window_start.strftime(_WINDOW_FORMAT)
        bugs: list[BugzillaBug] = []
        after_id = 0
        while True:
            page = await self._get_page(after_id, changed_since)
            if not page:
                return bugs
            bugs.extend(page)
            after_id = page[-1].id
            if request_delay > 0:
                await asyncio.sleep(request_delay)  # before the next request

    async def _get_page(self, after_id: int, changed_since: str) -> list[BugzillaBug]:
        """One validated page request; no database work."""
        client = self.http_client
        try:
            response = await client.get(
                BUGZILLA_BUG_URL, params=_page_params(after_id, changed_since)
            )
        except httpx.DecodingError as e:
            # An undecodable content encoding is a response, not a transport
            # failure.
            raise FetcherError(UNPARSEABLE_RESPONSE) from e
        except httpx.TransportError as e:
            raise FetcherError(CONNECTION_FAILED) from e
        if response.status_code != 200:
            _raise_chained(
                response, f"SUSE Bugzilla returned HTTP {response.status_code}"
            )
        try:
            document = decode_json(response.content)
        except ValueError as e:
            raise FetcherError(UNPARSEABLE_RESPONSE) from e
        try:
            return bugzilla_bug_record.parse_page(document, after_id)
        except ValidationError, PageOrderError:
            # Never chained: a validation error could render page content.
            raise FetcherError(UNPARSEABLE_RESPONSE) from None

    async def _process_cve(
        self, session: AsyncSession, cve_id: str, bugs: Sequence[BugzillaBug]
    ) -> None:
        """Algorithm step 6 for one CVE, in its own transaction."""
        try:
            exists = await self._cve_exists(session, cve_id)
        except CancelledError, SoftTimeLimitExceeded, MemoryError:
            raise  # whole-run signals — never catch per-item
        except Exception as e:
            await self._cve_failed(session, cve_id, e)
            return
        if not exists:
            # Enrichment-only scope: end the read without a write, silently.
            await session.rollback()
            return
        try:
            result = await self._ingest(session, cve_id, bugs)
            await session.flush()
        except CancelledError, SoftTimeLimitExceeded, MemoryError:
            raise  # whole-run signals — never catch per-item
        except Exception as e:
            await self._cve_failed(session, cve_id, e)
        else:
            # Keep finalization outside the pre-commit per-item catch.
            await self.commit_and_dispatch(session, result)

    async def _cve_exists(self, session: AsyncSession, cve_id: str) -> bool:
        """Lock-free lookup of an existing CVE by canonical CVE-ID; the
        lock is `upsert_cve()`'s."""
        cve_uuid: uuid.UUID | None = await session.scalar(
            select(CVE.id).where(CVE.cve_id == cve_id)
        )
        return cve_uuid is not None

    async def _ingest(
        self, session: AsyncSession, cve_id: str, bugs: Sequence[BugzillaBug]
    ) -> CVEFetchResult:
        """Upsert the CVE with an empty payload and link its bugs, up to the
        finalization token; never commits and records no metric."""
        result = await cve_service.upsert_cve(
            session, cve_id, self.cve_source_type, CVEIngestPayload()
        )
        await reference_service.upsert_references(
            session,
            result.ticket.id,
            cve_id,
            self.name,
            None,
            [_bug_reference(item) for item in bugs],
        )
        return CVEFetchResult(result.action, None)

    async def _cve_failed(
        self, session: AsyncSession, cve_id: str, error: Exception
    ) -> None:
        """Batch Error Handling for one selected CVE: rollback, isolated
        `failure` status, one bounded WARNING, and one failed unit."""
        await session.rollback()
        await self._isolated_status_commit(cve_id, CVESourceFetchStatus.FAILURE)
        logger.warning(
            CVE_FETCH_ITEM_FAILED_EVENT,
            cve_id=cve_id,
            fetcher_name=self.name,
            cause=type(error).__name__,
        )
        self.record_failed()


def _page_params(after_id: int, changed_since: str) -> dict[str, str]:
    """The query of one periodic page (Algorithm step 4)."""
    return {
        "include_fields": INCLUDE_FIELDS,
        "f1": "alias",
        "o1": "substring",
        "v1": "CVE-",
        "f2": "bug_id",
        "o2": "greaterthan",
        "v2": str(after_id),
        "last_change_time": changed_since,
        "order": "bug_id",
        "limit": str(PAGE_SIZE),
    }


def _bug_reference(bug: BugzillaBug) -> reference_service.AutomaticReferenceInput:
    """The Bug Reference candidate of one bug."""
    return reference_service.AutomaticReferenceInput(
        url=BUG_REFERENCE_URL.format(bug_id=bug.id),
        title=bug.summary,
        explicit_type=ReferenceType.ISSUE,
    )


def _raise_chained(response: httpx.Response, message: str) -> None:
    """Raise `FetcherError(message)` chained from the response's
    `httpx.HTTPStatusError` when it has one. Its text carries the status
    line, the request URL (no CVE ID in a periodic run), and for a 3xx the
    `Location` value; never bug content."""
    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as e:
        raise FetcherError(message) from e
    raise FetcherError(message)
