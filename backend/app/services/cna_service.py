"""CNA service: the CNA rows written by ingestion and the CNA reads.

Implements docs/features/tickets/cna.md (Service: `cna_service` — Module
Location, Ownership, Module-Level Defaults, Service Exceptions,
`resolve_ingested_cna()`, `list_cnas()`, `get_cna()`; CNA of a CVE; Short
Name; Concurrency) and the CNA locator of `docs/api-spec.md` (CNA Identifier
Resolution).

This module owns the `CNA` rows and their reads. It does not own
`CVE.cna_id`, which `cve_service.upsert_cve()` writes. Every function
receives the caller-owned `AsyncSession`, flushes only through its own
statements, and never commits or rolls back (`docs/conventions.md`,
Caller-Owned Service Transactions); database and programming exceptions
propagate unchanged. No function performs HTTP, Redis, or Celery I/O or
creates an audit event: ingestion writes are source-owned data without an
audit trail (cna.md, CNA Audit Log).
"""

from __future__ import annotations

import uuid
from collections.abc import Collection
from dataclasses import dataclass
from typing import Any, Final

from sqlalchemy import (
    ColumnElement,
    SQLColumnExpression,
    and_,
    false,
    func,
    or_,
    select,
    true,
    update,
)
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import CNASortField, SortOrder
from app.core.exceptions import ServiceError
from app.core.identifiers import parse_cna_org_id
from app.models.cna import CNA
from app.services.cve_ingest import CNAEntry
from app.services.cve_projection import CODE_POINT_COLLATION
from app.services.sql_patterns import LIKE_ESCAPE, escape_like

MAX_PER_PAGE: Final = 100


# ---------------------------------------------------------------------------
# Service exceptions (cna.md, Service Exceptions)
# ---------------------------------------------------------------------------


class CNAServiceError(ServiceError):
    """Base of every exception of this module."""


class CNANotFoundError(CNAServiceError):
    """The CNA locator is not a UUID in the hyphenated form, or no CNA has
    that `org_id`. Maps to `404 CNA_NOT_FOUND`. The message is static."""

    def __init__(self) -> None:
        super().__init__("CNA not found.")


# ---------------------------------------------------------------------------
# Ingestion writer (cna.md, Ingestion Writers; Short Name; Concurrency)
# ---------------------------------------------------------------------------


def _short_name_applies(entry: CNAEntry) -> ColumnElement[bool]:
    """Whether the entry's short name and date replace the stored ones
    (cna.md, Short Name). Requires an entry with a short name.

    A row without a short name takes the entry's; with a date, a row with
    the same short name and no date takes the date, and a row with another
    short name takes both when it has no date or one not later than the
    entry's. A row whose short name is the same and dated, and an undated
    entry for a row that has a short name, change nothing.
    """
    stored_name = CNA.short_name
    stored_date = CNA.short_name_observed_at
    observed_at = entry.short_name_observed_at
    if observed_at is None:
        return stored_name.is_(None)
    return or_(
        stored_name.is_(None),
        and_(stored_name == entry.short_name, stored_date.is_(None)),
        and_(
            stored_name != entry.short_name,
            or_(stored_date.is_(None), stored_date <= observed_at),
        ),
    )


async def resolve_ingested_cna(db: AsyncSession, entry: CNAEntry) -> CNA:
    """The `CNA` row of the owner of an ingested record, created or with its
    short name maintained.

    Trusted internal boundary (cna.md, `resolve_ingested_cna()`): only
    `cve_service.upsert_cve()` calls it, while it holds the CVE root lock and
    before it locks the Ticket.

    Q1: `entry` is the validated `CNAEntry` of the payload.

    Q3: (1) A plain read selects the row of `entry.org_id`. (2) When none
    exists, `INSERT ... ON CONFLICT (org_id) DO NOTHING` creates it with the
    entry's short name and date, `types = []`, and `auto_ignore = false`.
    PostgreSQL waits for a concurrent uncommitted creation of the same
    `org_id`: when it commits, nothing is inserted and the committed winner
    is used, which (3) then applies; no unique violation is raised and the
    caller's transaction stays usable. (3) For an existing row and an entry
    with a short name, one conditional `UPDATE` writes the short name and its
    date only when the Short Name rules change them, and advances
    `updated_at` only then. Its condition is evaluated on the row this
    transaction reads, so a row it excludes is neither written nor waited
    for; a row it selects waits for a concurrent short-name writer and is
    evaluated again on the committed result. (4) Returns the row as this
    transaction reads it, including `auto_ignore`.

    Q4: no audit event.

    Q5: idempotent: a repeated call with the same entry changes nothing.

    Q6: none of its own. Locking: a creation or an effective update holds
    the CNA row lock until the caller commits; no other lock is acquired.
    """
    cna = await _cna_by_org_id(db, entry.org_id)
    if cna is None:
        inserted = (
            await db.execute(
                pg_insert(CNA)
                .values(
                    org_id=entry.org_id,
                    short_name=entry.short_name,
                    short_name_observed_at=entry.short_name_observed_at,
                )
                .on_conflict_do_nothing(index_elements=[CNA.org_id])
                .returning(CNA.id)
            )
        ).scalar_one_or_none()
        cna = await _cna_by_org_id(db, entry.org_id)
        assert cna is not None, "the inserted row or the committed winner exists"
        if inserted is not None:
            return cna
    if entry.short_name is None:
        return cna
    updated = (
        await db.execute(
            update(CNA)
            .where(CNA.org_id == entry.org_id, _short_name_applies(entry))
            .values(
                short_name=entry.short_name,
                short_name_observed_at=entry.short_name_observed_at,
                updated_at=func.now(),
            )
            .returning(CNA.id)
            .execution_options(synchronize_session=False)
        )
    ).scalar_one_or_none()
    if updated is None:
        return cna
    refreshed = await _cna_by_org_id(db, entry.org_id)
    assert refreshed is not None, "CNA rows are never deleted"
    return refreshed


async def _cna_by_org_id(db: AsyncSession, org_id: uuid.UUID) -> CNA | None:
    """The row of `org_id` as this transaction reads it, refreshed in the
    session; a plain read that takes no lock."""
    return (
        await db.execute(
            select(CNA)
            .where(CNA.org_id == org_id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()


# ---------------------------------------------------------------------------
# Reads (cna.md, `list_cnas()`, `get_cna()`)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CNAListResult:
    """One page of CNAs and the unpaginated total, both derived from one
    PostgreSQL observation."""

    items: tuple[CNA, ...]
    total: int
    page: int
    per_page: int


def _display_name_expression() -> ColumnElement[str | None]:
    """The display name in SQL, as `cve_projection.cna_display_name()`."""
    return func.coalesce(CNA.organization_name, CNA.short_name)


def _sort_key(sort_by: CNASortField) -> ColumnElement[Any]:
    keys: dict[CNASortField, ColumnElement[Any]] = {
        CNASortField.NAME: _display_name_expression().collate(CODE_POINT_COLLATION),
        CNASortField.SHORT_NAME: CNA.short_name.collate(CODE_POINT_COLLATION),
        CNASortField.CREATED_AT: CNA.created_at.expression,
    }
    return keys[sort_by]


def _ordered(
    sort_key: ColumnElement[Any], row_id: ColumnElement[Any], sort_order: SortOrder
) -> tuple[ColumnElement[Any], ColumnElement[Any]]:
    """Primary order with `NULL` last in both directions, then the internal
    primary-key tie-breaker in the same direction."""
    if sort_order is SortOrder.ASC:
        return sort_key.asc().nulls_last(), row_id.asc()
    return sort_key.desc().nulls_last(), row_id.desc()


async def list_cnas(
    db: AsyncSession,
    *,
    search: str | None,
    auto_ignore: bool | None,
    page: int,
    per_page: int,
    sort_by: CNASortField,
    sort_order: SortOrder,
) -> CNAListResult:
    """List the CNAs matching the filters, one page at a time.

    Category B read (cna.md, `list_cnas()`; List CNAs).

    Q1: `search` is the raw free-text input; `auto_ignore` selects the CNAs
    with that value, `None` when omitted. `page` is positive and `per_page`
    is 1-100.

    Q3: trims `search` once; a non-empty term matches a CNA whose
    `short_name` or `organization_name` contains it as a case-insensitive
    substring, with `%`, `_`, and backslash literal. The filters combine with
    AND. Orders by the display name, the short name (both in Unicode
    code-point order), or `created_at`, `NULL` last in both directions, then
    by `CNA.id` in the same direction. In one SQL statement, and therefore
    one PostgreSQL observation, computes the total before page slicing and
    selects the page; a page beyond the last is empty with the correct
    total. Acquires no lock, writes nothing, and never commits or rolls back.

    Q6: raises `ValueError` before any query for `page < 1` or `per_page`
    outside 1-100; no domain exception.
    """
    if page < 1:
        raise ValueError("page must be at least 1")
    if not 1 <= per_page <= MAX_PER_PAGE:
        raise ValueError(f"per_page must be between 1 and {MAX_PER_PAGE}")

    conditions: list[ColumnElement[bool]] = []
    term = search.strip() if search is not None else ""
    if term:
        pattern = f"%{escape_like(term)}%"
        conditions.append(
            or_(
                CNA.short_name.ilike(pattern, escape=LIKE_ESCAPE),
                CNA.organization_name.ilike(pattern, escape=LIKE_ESCAPE),
            )
        )
    if auto_ignore is not None:
        conditions.append(CNA.auto_ignore.is_(true() if auto_ignore else false()))

    filtered = (
        select(CNA.id.label("id"), _sort_key(sort_by).label("sort_key"))
        .where(*conditions)
        .cte("filtered")
    )
    total = select(func.count().label("total")).select_from(filtered).cte("total")
    page_rows = (
        select(filtered)
        .order_by(*_ordered(filtered.c.sort_key, filtered.c.id, sort_order))
        .limit(per_page)
        .offset((page - 1) * per_page)
        .cte("page")
    )
    statement = (
        select(total.c.total, CNA)
        .select_from(total)
        .outerjoin(page_rows, true())
        .outerjoin(CNA, CNA.id == page_rows.c.id)
        .order_by(*_ordered(page_rows.c.sort_key, page_rows.c.id, sort_order))
        .execution_options(populate_existing=True)
    )
    rows = (await db.execute(statement)).all()
    return CNAListResult(
        items=tuple(row.CNA for row in rows if row.CNA is not None),
        total=rows[0].total,
        page=page,
        per_page=per_page,
    )


def cna_filter_condition(
    cna_id: SQLColumnExpression[uuid.UUID | None], org_ids: Collection[uuid.UUID]
) -> ColumnElement[bool]:
    """The `cna` filter of the CVE and Ticket lists: `cna_id` references a
    CNA whose `org_id` is one of `org_ids` (OR). A `NULL` `cna_id` and an
    unknown value match nothing; an empty collection matches nothing.
    Builds the expression only; performs no I/O."""
    values = sorted(set(org_ids))
    if not values:
        return false()
    return cna_id.in_(select(CNA.id).where(CNA.org_id.in_(values)))


async def get_cna(db: AsyncSession, org_id: str) -> CNA:
    """Return one CNA by its `org_id`.

    Category B read (cna.md, `get_cna()`; Get CNA).

    Q1: `org_id` is the raw path value.

    Q3: a value that is not a UUID in the hyphenated form, in either case,
    runs no query; otherwise one statement selects the row by `org_id`,
    compared by value. Acquires no lock and writes nothing.

    Q6: raises `CNANotFoundError` for a malformed or unknown `org_id`.
    """
    parsed = parse_cna_org_id(org_id)
    if parsed is None:
        raise CNANotFoundError()
    cna = (
        await db.execute(select(CNA).where(CNA.org_id == parsed))
    ).scalar_one_or_none()
    if cna is None:
        raise CNANotFoundError()
    return cna
