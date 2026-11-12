"""CNA service: the CNA rows written by ingestion and by the CNA list
synchronization, the auto-ignore policy and its audit trail, and the CNA
reads.

Implements docs/features/tickets/cna.md (Service: `cna_service` — Module
Location, Ownership, Module-Level Defaults, Service Exceptions,
`resolve_ingested_cna()`, `update_cna_metadata()`, `set_cna_auto_ignore()`,
`list_cnas()`, `get_cna()`, `list_cna_audit_events()`; CNA of a CVE; Short
Name; Auto-Ignore Policy, Flag; Concurrency; CNA Audit Log) and the CNA
locator of `docs/api-spec.md` (CNA Identifier Resolution).

This module owns the `CNA` rows, the CNA audit trail (`CNAAuditLog`), and
the CNA reads. It does not own `CVE.cna_id`, which
`cve_service.upsert_cve()` writes, or the Ticket transition that the policy
causes, which `ticket_service.ignore_new_for_cna_policy()` owns. Every
function receives the caller-owned `AsyncSession`, flushes only through its
own statements, and never commits or rolls back (`docs/conventions.md`,
Caller-Owned Service Transactions); database and programming exceptions
propagate unchanged. No function performs HTTP, Redis, or Celery I/O. Only
`set_cna_auto_ignore()` creates an audit event: ingestion and CNA list
writes are source-owned data without an audit trail (cna.md, CNA Audit
Log).
"""

from __future__ import annotations

import uuid
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any, Final

from pydantic import MISSING
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
from sqlalchemy.orm import aliased

from app.core.enums import CNAAuditEventType, CNASortField, SortOrder
from app.core.exceptions import ServiceError
from app.core.external_strings import contains_inadmissible_character
from app.core.identifiers import parse_cna_org_id
from app.models.cna import CNA
from app.models.cna_audit_event import CNAAuditEvent
from app.models.user import User
from app.services.base_audit_log import BaseAuditLog
from app.services.cve_ingest import CNAEntry
from app.services.cve_projection import (
    CODE_POINT_COLLATION,
    CNASummaryProjection,
    cna_display_name,
    cna_summary_columns,
    cna_summary_from_row,
)
from app.services.sql_patterns import LIKE_ESCAPE, escape_like

MAX_PER_PAGE: Final = 100

ORGANIZATION_NAME_MAX_LENGTH: Final = 256
"""`CNA.organization_name` is `VARCHAR(256)` (cna.md, Field Mapping)."""
TYPES_MAX_ITEMS: Final = 16
"""At most 16 CNA types (cna.md, Field Mapping)."""
TYPE_MAX_LENGTH: Final = 128
"""At most 128 characters per CNA type (cna.md, Field Mapping)."""
SCOPE_MAX_LENGTH: Final = 4096
"""At most 4096 characters of plain-text scope (cna.md, Scope Plain Text)."""


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
# CNA list metadata (cna.md, `update_cna_metadata()`; Field Mapping)
# ---------------------------------------------------------------------------


def is_admissible_text(value: object, *, max_length: int) -> bool:
    """Whether `value` is a string that is not empty after trimming, has at
    most `max_length` characters, and contains no inadmissible character
    (`docs/conventions.md`, External String Admissibility). Pure."""
    return (
        isinstance(value, str)
        and bool(value.strip())
        and len(value) <= max_length
        and not contains_inadmissible_character(value)
    )


def _is_admissible_scope(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) <= SCOPE_MAX_LENGTH
        and not contains_inadmissible_character(value)
    )


async def update_cna_metadata(
    db: AsyncSession,
    *,
    cna_id: uuid.UUID,
    organization_name: str | MISSING = MISSING,
    types: Sequence[str] | MISSING = MISSING,
    scope: str | MISSING | None = MISSING,
) -> bool:
    """Write the CNA list metadata of one CNA row.

    System operation (cna.md, `update_cna_metadata()`) that
    `sync_mitre_cnas` calls for each matched row, and the example dataset
    loader in its place.

    Q1: `cna_id` is the internal id of a row that the caller has read in the
    same transaction. An omitted (`MISSING`) field keeps its stored value;
    `scope = None` clears the scope.

    Q2: before any database access, a supplied `organization_name` that is
    empty after trimming or longer than 256 characters, `types` that is a
    string or holds more than 16 items, an item that is empty after trimming
    or longer than 128 characters, a `scope` longer than 4096 characters,
    or any value containing an inadmissible character raises `ValueError`:
    the caller validates first, so this is a programming error.

    Q3: stores the supplied `types` without duplicates in ascending Unicode
    code-point order. One `UPDATE` sets the supplied columns and
    `updated_at` only when at least one supplied value differs from the
    stored one (`IS DISTINCT FROM`), so `updated_at` advances only with an
    effective change. Never writes `org_id`, `short_name`,
    `short_name_observed_at`, or `auto_ignore`, and no CVE or Ticket. When
    nothing changed, one plain read distinguishes an unchanged row from a
    `cna_id` that identifies none. A `CNA` instance already loaded in the
    session is not refreshed. An effective update holds the row lock until
    the caller commits.

    Q4: no audit event. Q5: idempotent; a repeated call returns `False`.

    Q6: raises `ValueError` for a guard of Q2 and for a `cna_id` that
    identifies no row; database exceptions propagate unchanged.
    """
    values: dict[str, Any] = {}
    if organization_name is not MISSING:
        if not is_admissible_text(
            organization_name, max_length=ORGANIZATION_NAME_MAX_LENGTH
        ):
            raise ValueError(
                "organization_name must be 1-256 characters without an "
                "inadmissible character"
            )
        values["organization_name"] = organization_name
    if types is not MISSING:
        if (
            isinstance(types, str)
            or len(types) > TYPES_MAX_ITEMS
            or not all(
                is_admissible_text(item, max_length=TYPE_MAX_LENGTH) for item in types
            )
        ):
            raise ValueError(
                "types must be at most 16 items of 1-128 characters without an "
                "inadmissible character"
            )
        values["types"] = sorted(set(types))
    if scope is not MISSING:
        if scope is not None and not _is_admissible_scope(scope):
            raise ValueError(
                "scope must be at most 4096 characters without an inadmissible "
                "character"
            )
        values["scope"] = scope

    if values:
        changed = (
            await db.execute(
                update(CNA)
                .where(
                    CNA.id == cna_id,
                    or_(
                        *(
                            getattr(CNA, column).is_distinct_from(value)
                            for column, value in values.items()
                        )
                    ),
                )
                .values(**values, updated_at=func.now())
                .returning(CNA.id)
                .execution_options(synchronize_session=False)
            )
        ).scalar_one_or_none()
        if changed is not None:
            return True
    if await db.scalar(select(CNA.id).where(CNA.id == cna_id)) is None:
        raise ValueError("No CNA row has this id.")
    return False


# ---------------------------------------------------------------------------
# Auto-ignore policy and its audit trail (cna.md, Auto-Ignore Policy;
# `set_cna_auto_ignore()`; CNA Audit Log)
# ---------------------------------------------------------------------------

_CNA_NAME_KEY: Final = "cna_name"


class CNAAuditLog(BaseAuditLog):
    """Audit trail for the auto-ignore policy changes of CNAs.

    See `docs/features/tickets/cna.md` (CNA Audit Log).
    """

    name = "cna"
    description = "Auto-ignore policy changes of CNAs"
    model_class = CNAAuditEvent

    @classmethod
    async def log_event(  # type: ignore[override]
        cls,
        session: AsyncSession,
        *,
        event_type: CNAAuditEventType,
        cna_id: uuid.UUID,
        user_id: uuid.UUID | None,
        detail: Mapping[str, str | None],
    ) -> None:
        """Create one `CNAAuditEvent` in the caller's transaction.

        Validates, before any database operation, that `event_type` is a
        `CNAAuditEventType` member (this classification enum has no
        database CHECK constraint), that `user_id` is provided (every
        policy change is made by an administrator), and that `detail` is
        exactly one `cna_name` key with a string or `None` value. Every
        violation raises `ValueError`; no event is inserted.

        Stores `old_value` and `new_value` as `NULL`, creates exactly one
        event, and flushes it before returning. Never commits or rolls
        back. Each invocation creates a new event and is therefore not
        idempotent: callers invoke it only for an effective change.
        Database and flush exceptions propagate to the caller, whose
        transaction rolls back the change and the event together.
        """
        if not isinstance(event_type, CNAAuditEventType):
            raise ValueError(
                f"event_type must be a CNAAuditEventType member, got {event_type!r}"
            )
        if user_id is None:
            raise ValueError("user_id is required for CNA audit events")
        if not isinstance(detail, Mapping) or set(detail) != {_CNA_NAME_KEY}:
            raise ValueError("detail must be exactly one 'cna_name' key")
        cna_name = detail[_CNA_NAME_KEY]
        if cna_name is not None and not isinstance(cna_name, str):
            raise ValueError("detail.cna_name must be a string or None")

        await super().log_event(
            session,
            event_type=event_type.value,
            cna_id=cna_id,
            user_id=user_id,
            old_value=None,
            new_value=None,
            detail={_CNA_NAME_KEY: cna_name},
        )


async def set_cna_auto_ignore(
    db: AsyncSession,
    *,
    org_id: str,
    auto_ignore: bool,
    acting_user_id: uuid.UUID,
) -> CNA:
    """Place a CNA under the auto-ignore policy or remove it.

    Category A administrative mutation (cna.md, `set_cna_auto_ignore()`;
    Set CNA Auto-Ignore; Flag; Concurrency).

    Q1: `org_id` is the raw path value; `auto_ignore` the requested value;
    `acting_user_id` the authenticated administrator, who holds
    `manage_settings` (checked by the caller).

    Q2: before any database access, an `org_id` that is not a UUID in the
    hyphenated form, in either case, raises `CNANotFoundError`, and an
    `auto_ignore` that is not a `bool` raises `ValueError`. The caller owns
    the transaction.

    Q3: (1) selects the row by `org_id` with `FOR NO KEY UPDATE` as the
    first database operation, refreshing any identity-map copy; a missing
    row raises `CNANotFoundError`. (2) When the locked-current
    `auto_ignore` equals the request, returns the row with no write and no
    event. (3) Otherwise sets `auto_ignore` and creates one
    `CNAAuditEvent`: `auto_ignore_enabled` for `True`,
    `auto_ignore_disabled` for `False`, attributed to `acting_user_id`,
    with `detail = {"cna_name": <display name of the locked row or None>}`.
    (4) Flushes and returns the row with its new `updated_at`. Changes no
    Ticket, CVE, or other CNA. The lock is the only root: the foreign-key
    `FOR KEY SHARE` of a CVE write does not conflict with it, and
    concurrent requests serialize on it, each classifying its request
    against the value it observes under the lock.

    Q4: one event per effective change; none for a no-op.

    Q5: idempotent at the value level.

    Q6: raises `CNANotFoundError` and `ValueError` as above; audit,
    database, and flush exceptions propagate and roll back the change and
    the event together.
    """
    parsed = parse_cna_org_id(org_id)
    if parsed is None:
        raise CNANotFoundError()
    if not isinstance(auto_ignore, bool):
        raise ValueError("auto_ignore must be a bool")

    cna = (
        await db.execute(
            select(CNA)
            .where(CNA.org_id == parsed)
            # `key_share=True` renders `FOR NO KEY UPDATE`.
            .with_for_update(key_share=True)
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
    if cna is None:
        raise CNANotFoundError()
    if cna.auto_ignore is auto_ignore:
        return cna

    cna.auto_ignore = auto_ignore
    await CNAAuditLog.log_event(
        db,
        event_type=(
            CNAAuditEventType.AUTO_IGNORE_ENABLED
            if auto_ignore
            else CNAAuditEventType.AUTO_IGNORE_DISABLED
        ),
        cna_id=cna.id,
        user_id=acting_user_id,
        detail={_CNA_NAME_KEY: cna_display_name(cna.organization_name, cna.short_name)},
    )
    # `updated_at` is assigned by the database on UPDATE (`onupdate`), so it
    # is expired after the flush; reload it here, where lazy loading is not
    # available under `AsyncSession`.
    await db.refresh(cna, attribute_names=["updated_at"])
    return cna


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


# ---------------------------------------------------------------------------
# CNA audit read (cna.md, `list_cna_audit_events()`; List CNA Audit Events)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CNAAuditEventActor:
    """The current profile of the administrator who recorded an event
    (`docs/api-spec.md`, User References in Responses): resolved from the
    current `User` row, never an event-time snapshot."""

    id: uuid.UUID
    username: str
    full_name: str | None
    active: bool
    bot: bool
    avatar_url: str | None


@dataclass(frozen=True, slots=True)
class CNAAuditEventItem:
    """One CNA audit event: `cna` is the current reference of its CNA and
    `detail.cna_name` the display name when the event was recorded."""

    id: uuid.UUID
    event_type: str
    cna: CNASummaryProjection
    detail: dict[str, Any]
    actor: CNAAuditEventActor
    created_at: datetime


@dataclass(frozen=True, slots=True)
class CNAAuditEventListResult:
    """One page of CNA audit events and the unpaginated total, both derived
    from one PostgreSQL observation."""

    items: tuple[CNAAuditEventItem, ...]
    total: int
    page: int
    per_page: int


_CNA_AUDIT_EVENT_TYPES: Final = frozenset(member.value for member in CNAAuditEventType)


async def list_cna_audit_events(
    db: AsyncSession,
    *,
    event_type: Sequence[str] | None,
    cna: uuid.UUID | None,
    actor: str | None,
    from_date: date | datetime | None,
    to_date: date | datetime | None,
    page: int,
    per_page: int,
) -> CNAAuditEventListResult:
    """List the CNA audit trail, newest first.

    Category B read (cna.md, `list_cna_audit_events()`; List CNA Audit
    Events).

    Q1: `event_type` is `None` when the filter was not supplied, or its raw
    values; `cna` an `org_id` already validated by the API; `actor` the
    literal `system`, a User UUID, or an exact username; `from_date` and
    `to_date` inclusive bounds already parsed by the API. `page` is
    positive and `per_page` is 1-100.

    Q3: the filters combine with AND. Valid `event_type` values combine
    with OR; a supplied filter without a valid value matches nothing
    (`docs/api-spec.md`, Enum Filter Validation). `cna` selects the events
    of the CNA with that `org_id`, and an unknown value matches nothing.
    `actor` uses `CNAAuditLog.filter_by_actor()` and the dates
    `CNAAuditLog.apply_date_filters()`. In one SQL statement, and therefore
    one PostgreSQL observation, computes the total before page slicing and
    selects the page ordered by `id` descending (UUIDv7, so `created_at`
    descending with a deterministic tie-break), with the current
    `CNASummary` of each event's CNA and the current reference of its
    actor. A page beyond the last is empty with the correct total.
    Acquires no lock, writes nothing, and never commits or rolls back.

    Q6: raises `ValueError` before any query for `page < 1` or `per_page`
    outside 1-100; no domain exception. Database exceptions propagate
    unchanged.
    """
    if page < 1:
        raise ValueError("page must be at least 1")
    if not 1 <= per_page <= MAX_PER_PAGE:
        raise ValueError(f"per_page must be between 1 and {MAX_PER_PAGE}")

    events = select(
        CNAAuditEvent.id,
        CNAAuditEvent.cna_id,
        CNAAuditEvent.event_type,
        CNAAuditEvent.detail,
        CNAAuditEvent.user_id,
        CNAAuditEvent.created_at,
    )
    if event_type is not None:
        values = sorted(set(event_type) & _CNA_AUDIT_EVENT_TYPES)
        events = events.where(
            CNAAuditEvent.event_type.in_(values) if values else false()
        )
    if cna is not None:
        events = events.where(cna_filter_condition(CNAAuditEvent.cna_id, [cna]))
    events = CNAAuditLog.filter_by_actor(events, actor)
    events = CNAAuditLog.apply_date_filters(events, from_date, to_date)
    filtered = events.cte("filtered")

    total = select(func.count().label("total")).select_from(filtered).cte("total")
    page_rows = (
        select(filtered)
        .order_by(filtered.c.id.desc())
        .limit(per_page)
        .offset((page - 1) * per_page)
        .cte("page")
    )
    actor_user = aliased(User, name="actor_user")
    statement = (
        select(
            total.c.total,
            page_rows.c.id.label("event_id"),
            page_rows.c.event_type,
            page_rows.c.detail,
            page_rows.c.created_at,
            *cna_summary_columns(),
            actor_user.id.label("actor_id"),
            actor_user.username.label("actor_username"),
            actor_user.full_name.label("actor_full_name"),
            actor_user.active.label("actor_active"),
            actor_user.bot.label("actor_bot"),
            actor_user.avatar_url.label("actor_avatar_url"),
        )
        .select_from(total)
        .outerjoin(page_rows, true())
        .outerjoin(CNA, CNA.id == page_rows.c.cna_id)
        .outerjoin(actor_user, actor_user.id == page_rows.c.user_id)
        .order_by(page_rows.c.id.desc())
    )
    rows = (await db.execute(statement)).all()
    items: list[CNAAuditEventItem] = []
    for row in rows:
        if row.event_id is None:
            continue
        summary = cna_summary_from_row(row)
        # `cna_id` is NOT NULL with a RESTRICT foreign key, and
        # `CNAAuditLog.log_event()` requires an actor.
        assert summary is not None
        assert row.actor_id is not None
        items.append(
            CNAAuditEventItem(
                id=row.event_id,
                event_type=row.event_type,
                cna=summary,
                detail=row.detail,
                actor=CNAAuditEventActor(
                    id=row.actor_id,
                    username=row.actor_username,
                    full_name=row.actor_full_name,
                    active=row.actor_active,
                    bot=row.actor_bot,
                    avatar_url=row.actor_avatar_url,
                ),
                created_at=row.created_at,
            )
        )
    return CNAAuditEventListResult(
        items=tuple(items), total=rows[0].total, page=page, per_page=per_page
    )
