"""`sync_mitre_cnas`: names, types, and scopes of the CNAs from the CVE
Program CNA list.

Implements docs/features/tickets/cna.md (Fetcher: `sync_mitre_cnas`) on the
`BaseFetcher` contract of docs/features/platform/fetcher-infrastructure.md.
Each run:

1. downloads the complete list with one `GET`, before any database work,
   and fails the run with a sanitized `FetcherError` on a transport error, a
   status other than 200, or a body that is not a UTF-8 JSON array;
2. selects every array element as one work unit and keeps the valid
   entries (`cna_list.parse_entry()`);
3. in one transaction, reads the CNA rows that have a short name, pairs
   them with the entries (`cna_list.match_entries()`), and, in ascending
   `CNA.id` order, passes each matched row's valid fields to
   `cna_service.update_cna_metadata()`; then commits once;
4. after the commit, records the metrics and emits the bounded warnings.

The fetcher creates no CNA row and writes no short name, `auto_ignore`,
CVE, or Ticket. The warnings carry the row's `org_id` from PostgreSQL and
never a value of the list.
"""

from __future__ import annotations

from typing import Final

import httpx
import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cna import CNA
from app.services import cna_service
from app.services.base_fetcher import BaseFetcher, FetcherError
from app.services.json_decoding import decode_json
from app.services.tickets import cna_list
from app.services.tickets.cna_list import NamedCNA

logger = structlog.get_logger(__name__)

CNA_LIST_URL: Final = (
    "https://raw.githubusercontent.com/CVEProject/cve-website/main/"
    "src/assets/data/CNAsList.json"
)
"""The CNA list of the CVE Program website (Source)."""

CONNECT_FAILED_MESSAGE: Final = "Failed to connect to the CNA list"
TIMED_OUT_MESSAGE: Final = "CNA list request timed out"
UNPARSEABLE_MESSAGE: Final = "CNA list returned unparseable response"

ENTRIES_INVALID_EVENT: Final = "cna_list_entries_invalid"
MATCH_AMBIGUOUS_EVENT: Final = "cna_metadata_match_ambiguous"
FIELD_INVALID_EVENT: Final = "cna_metadata_field_invalid"


class CNAListStructureError(ValueError):
    """The decoded list is not a JSON array. Fixed message, no content."""

    def __init__(self) -> None:
        super().__init__("CNA list is not a JSON array")


class SyncMitreCnas(BaseFetcher):
    """Sync CNA names, types, and scopes from the CVE Program CNA list."""

    name = "sync_mitre_cnas"
    description = "Sync CNA names, types, and scopes from the CVE Program CNA list"
    default_schedule = "0 7 * * *"

    async def execute(self, session: AsyncSession) -> None:
        elements = await self._download()
        entries = [
            entry for entry in map(cna_list.parse_entry, elements) if entry is not None
        ]
        invalid_entries = len(elements) - len(entries)

        rows = await self._named_cnas(session)
        matching = cna_list.match_entries(rows, entries)
        field_warnings: list[tuple[NamedCNA, cna_list.MetadataField]] = []
        changed = 0
        for row, entry in matching.matched:
            metadata = cna_list.map_fields(entry)
            field_warnings.extend((row, field) for field in metadata.invalid_fields)
            if await cna_service.update_cna_metadata(
                session,
                cna_id=row.id,
                organization_name=metadata.organization_name,
                types=metadata.types,
                scope=metadata.scope,
            ):
                changed += 1
        await session.commit()

        self.record_succeeded(len(entries))
        self.record_failed(invalid_entries)
        self.record_updated(changed)
        self._warn(invalid_entries, matching.ambiguous, field_warnings)

    async def _download(self) -> list[object]:
        """Algorithm steps 1-2: one `GET` and the decoded array; no database
        work."""
        try:
            response = await self.http_client.get(CNA_LIST_URL)
        except httpx.DecodingError as e:
            # An undecodable content coding is a response, not a transport
            # failure.
            raise FetcherError(UNPARSEABLE_MESSAGE) from e
        except httpx.TimeoutException as e:
            raise FetcherError(TIMED_OUT_MESSAGE) from e
        except httpx.TransportError as e:
            raise FetcherError(CONNECT_FAILED_MESSAGE) from e
        if response.status_code != 200:
            raise FetcherError(
                f"CNA list returned HTTP {response.status_code}"
            ) from _status_error(response)
        try:
            document = decode_json(response.content.decode("utf-8"))
        except ValueError as e:
            raise FetcherError(UNPARSEABLE_MESSAGE) from e
        if not isinstance(document, list):
            raise FetcherError(UNPARSEABLE_MESSAGE) from CNAListStructureError()
        return document

    @staticmethod
    async def _named_cnas(session: AsyncSession) -> list[NamedCNA]:
        """Algorithm step 4: every CNA row with a short name, in ascending
        `CNA.id` order, the order of the writes and their row locks."""
        rows = await session.execute(
            select(CNA.id, CNA.org_id, CNA.short_name)
            .where(CNA.short_name.is_not(None))
            .order_by(CNA.id)
        )
        return [
            NamedCNA(id=row.id, org_id=row.org_id, short_name=row.short_name)
            for row in rows
        ]

    def _warn(
        self,
        invalid_entries: int,
        ambiguous: tuple[NamedCNA, ...],
        field_warnings: list[tuple[NamedCNA, cna_list.MetadataField]],
    ) -> None:
        """Algorithm step 9: the bounded warnings of Error Handling."""
        if invalid_entries:
            logger.warning(
                ENTRIES_INVALID_EVENT, fetcher_name=self.name, count=invalid_entries
            )
        for row in ambiguous:
            logger.warning(
                MATCH_AMBIGUOUS_EVENT, fetcher_name=self.name, org_id=str(row.org_id)
            )
        for row, field in field_warnings:
            logger.warning(
                FIELD_INVALID_EVENT,
                fetcher_name=self.name,
                org_id=str(row.org_id),
                field=field,
            )


def _status_error(response: httpx.Response) -> httpx.HTTPStatusError:
    """The `httpx.HTTPStatusError` of a status other than 200, carrying the
    status line and URL only. `raise_for_status()` provides it for every
    status outside 2xx; a 2xx other than 200 gets the same form."""
    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as e:
        return e
    return httpx.HTTPStatusError(
        f"Unexpected status '{response.status_code} {response.reason_phrase}' "
        f"for url '{response.request.url}'",
        request=response.request,
        response=response,
    )
