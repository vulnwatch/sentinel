"""The snapshot of the source package names that SMELT maintains.

Implements `docs/features/packages/maintained-package-names.md`: the
publication boundary `publish_maintained_packages()` (Publication Boundary)
and the search `search_maintained_packages()` (Service). This module is the
only owner of the `MaintainedPackage` table. Its callers are the
`sync_smelt_packages` fetcher and the example dataset loader, which publish,
and `GET /api/v1/maintained-packages`, which searches.

The snapshot only helps a caller find the exact name of a package: it
decides nothing. Add Package to Ticket still resolves every name in SMELT.

This module performs database work only: no network I/O, no audit event, no
post-commit effect, and no task dispatch.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Final

from sqlalchemy import (
    Integer,
    String,
    case,
    delete,
    func,
    insert,
    literal,
    select,
    text,
    true,
)
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.maintained_package import MaintainedPackage
from app.services.sql_patterns import LIKE_ESCAPE, escape_like

MAX_PER_PAGE: Final = 100
"""The largest accepted `per_page` (`docs/api-spec.md`, Pagination)."""


def _name_max_length() -> int:
    column_type = MaintainedPackage.__table__.c.name.type
    if not isinstance(column_type, String) or column_type.length is None:
        raise TypeError("MaintainedPackage.name is not a bounded string column")
    return column_type.length


NAME_MAX_LENGTH: Final = _name_max_length()
"""The longest name that a snapshot holds: the length of the `name` column."""

_CODE_POINT_COLLATION: Final = "C"
"""Collation ordering names by Unicode code point, independent of the
database collation (Service, step 3)."""

_PUBLICATION_LOCK: Final = text(
    "LOCK TABLE maintained_package IN SHARE ROW EXCLUSIVE MODE"
)
"""Serializes publications (Publication Boundary, Q3). The mode conflicts
with itself and with every row write, so a second publication waits until
the first commits or rolls back and then reads the snapshot that it left; it
does not conflict with the `ACCESS SHARE` lock of a plain `SELECT`, so a
search never waits for a publication."""

# Names per DELETE or INSERT statement, far below the PostgreSQL
# bind-parameter limit.
_CHUNK_SIZE: Final = 1000


@dataclass(frozen=True, slots=True)
class MaintainedPackagePublication:
    """The effect of one committed publication (Publication Boundary, Q3).

    `created` names were inserted, `removed` names were deleted, and
    `unchanged` names were present before and after the publication.
    """

    created: int
    removed: int
    unchanged: int


@dataclass(frozen=True, slots=True)
class MaintainedPackagePage:
    """One page of names and the total number of selected names, both from
    one published snapshot (Service, step 4)."""

    names: tuple[str, ...]
    total: int
    page: int
    per_page: int


def _chunks(names: Iterable[str]) -> Iterator[list[str]]:
    batch: list[str] = []
    for name in names:
        batch.append(name)
        if len(batch) == _CHUNK_SIZE:
            yield batch
            batch = []
    if batch:
        yield batch


async def publish_maintained_packages(
    db: AsyncSession,
    names: frozenset[str],
) -> MaintainedPackagePublication:
    """Publish one complete snapshot and commit it once.

    Publication orchestration boundary (Publication Boundary; a named
    exception of `docs/conventions.md`, Caller-Owned Service Transactions).

    Q1: `db` has no open transaction and no pending work. `names` is the
    non-empty set of the snapshot's names, which the caller has validated:
    each a non-empty string of at most 255 characters without an
    inadmissible character.

    Q2: an empty `names` raises `ValueError` before any database operation.

    Q3: in one transaction, which begins here and commits once also when
    nothing changes: lock the table against other publications, read the
    published names, delete every name not in `names`, insert every name of
    `names` that has no row, and commit. Overlapping publications therefore
    run one after the other, and the table holds the snapshot of the one
    that commits last. A reader sees the previous snapshot or the new one,
    never part of a publication. A database error propagates before the
    commit succeeds; the caller rolls the session back.

    Q4: no audit event. Q5: idempotent; publishing the same `names` again
    changes no row and reports every name as unchanged.

    Q6: `ValueError` from Q2; database exceptions propagate unchanged. No
    network I/O, post-commit effect, or task dispatch.
    """
    if not names:
        raise ValueError("a maintained package snapshot must hold at least one name")

    await db.execute(_PUBLICATION_LOCK)
    published = frozenset((await db.scalars(select(MaintainedPackage.name))).all())
    removed = published - names
    created = names - published
    for batch in _chunks(sorted(removed)):
        await db.execute(
            delete(MaintainedPackage).where(MaintainedPackage.name.in_(batch))
        )
    for batch in _chunks(sorted(created)):
        await db.execute(insert(MaintainedPackage), [{"name": name} for name in batch])
    await db.commit()
    return MaintainedPackagePublication(
        created=len(created),
        removed=len(removed),
        unchanged=len(published & names),
    )


async def search_maintained_packages(
    db: AsyncSession,
    *,
    search: str | None = None,
    page: int = 1,
    per_page: int = 20,
) -> MaintainedPackagePage:
    """Search the names of the latest published snapshot, one page at a time.

    Category B read (Service, `search_maintained_packages()`).

    Q1: `search` is the raw term, `None` when omitted; it has passed the
    Query Parameter Length Limit. `page` is positive and `per_page` is
    1-100 (`docs/api-spec.md`, Pagination).

    Q3: trims the outer whitespace of `search` once; an absent or empty
    term selects every name. A term selects the names that contain it
    without regard to letter case, with `%`, `_`, and backslash literal.
    The names that start with the term, compared in the same way, come
    first, then the others; each group, and every name without a term, is
    in ascending Unicode code-point order, independent of the database
    collation. `name` is unique, so the order is total. The page and the
    total come from one SQL statement and therefore describe one published
    snapshot, also when a publication commits during the operation.

    Q4: returns the page of names, the total, and the echoed `page` and
    `per_page`. Before the first publication, and for a page beyond the
    last, the page is empty with the correct total. Creates no audit event,
    acquires no lock, and never flushes, commits, or rolls back.

    Q6: raises `ValueError` before any query for `page < 1` or `per_page`
    outside 1-100. Database exceptions propagate unchanged.
    """
    if page < 1:
        raise ValueError("page must be at least 1")
    if not 1 <= per_page <= MAX_PER_PAGE:
        raise ValueError(f"per_page must be between 1 and {MAX_PER_PAGE}")

    term = search.strip() if search is not None else ""
    query = select(
        MaintainedPackage.name.label("name"),
        MaintainedPackage.name.collate(_CODE_POINT_COLLATION).label("sort_key"),
    )
    if term:
        escaped = escape_like(term)
        query = query.add_columns(
            case(
                (MaintainedPackage.name.ilike(f"{escaped}%", escape=LIKE_ESCAPE), 0),
                else_=1,
            ).label("rank")
        ).where(MaintainedPackage.name.ilike(f"%{escaped}%", escape=LIKE_ESCAPE))
    else:
        query = query.add_columns(literal(0, Integer).label("rank"))

    filtered = query.cte("filtered")
    total = select(func.count().label("total")).select_from(filtered).cte("total")
    page_rows = (
        select(filtered)
        .order_by(filtered.c.rank, filtered.c.sort_key)
        .limit(per_page)
        .offset((page - 1) * per_page)
        .cte("page")
    )
    statement = (
        select(total.c.total, page_rows.c.name)
        .select_from(total)
        .outerjoin(page_rows, true())
        .order_by(page_rows.c.rank, page_rows.c.sort_key)
    )
    rows = (await db.execute(statement)).all()
    return MaintainedPackagePage(
        names=tuple(row.name for row in rows if row.name is not None),
        total=rows[0].total,
        page=page,
        per_page=per_page,
    )
