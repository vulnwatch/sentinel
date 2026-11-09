"""Single-session tests for `cna_service` (backend/app/services/cna_service.py).

Owning specification: docs/features/tickets/cna.md (The CNA Entity; Display
Name; Short Name; Service: `cna_service` — Module-Level Defaults, Service
Exceptions, `resolve_ingested_cna()`, `list_cnas()`, `get_cna()`) and
docs/api-spec.md (CNA Identifier Resolution). The independent-session races
are in `tests/test_services/test_cna_atomicity.py`; the merge of
`CVE.cna_id` through `upsert_cve()` in
`tests/test_services/test_upsert_cve_cna.py`.

Every test runs in the rolled-back `db_session`, so its CNA rows are
invisible to other tests; each uses fictional organization UUIDs and short
names.
"""

from __future__ import annotations

import inspect
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import CNASortField, SortOrder
from app.core.exceptions import ServiceError
from app.models.cna import CNA
from app.models.cve import CVE
from app.models.ticket_audit_event import TicketAuditEvent
from app.services.cna_service import (
    CNAListResult,
    CNANotFoundError,
    CNAServiceError,
    cna_filter_condition,
    get_cna,
    list_cnas,
    resolve_ingested_cna,
)
from app.services.cve_ingest import CNAEntry
from tests.support.module_imports import APP_ROOT, imported_modules

CNAFactory = Callable[..., Awaitable[CNA]]
CVEFactory = Callable[..., Awaitable[CVE]]

OLD = datetime(2022, 12, 28, tzinfo=UTC)
NEW = datetime(2026, 7, 16, tzinfo=UTC)
STALE = datetime(2000, 1, 1, tzinfo=UTC)
"""An `updated_at` far before the transaction's `now()`."""


def _org_id() -> uuid.UUID:
    return uuid.uuid4()


async def _row(db: AsyncSession, org_id: uuid.UUID) -> CNA:
    cna = (
        await db.execute(
            select(CNA)
            .where(CNA.org_id == org_id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    return cna


async def _cna_count(db: AsyncSession, org_id: uuid.UUID) -> int:
    return int(
        await db.scalar(
            select(func.count()).select_from(CNA).where(CNA.org_id == org_id)
        )
        or 0
    )


# ---------------------------------------------------------------------------
# resolve_ingested_cna()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestResolveIngestedCnaCreation:
    async def test_creates_the_row_with_the_entry_and_the_defaults(
        self, db_session: AsyncSession
    ) -> None:
        org_id = _org_id()
        entry = CNAEntry(
            org_id=org_id, short_name="example", short_name_observed_at=NEW
        )

        cna = await resolve_ingested_cna(db_session, entry)

        assert (cna.org_id, cna.short_name, cna.short_name_observed_at) == (
            org_id,
            "example",
            NEW,
        )
        assert (cna.organization_name, cna.types, cna.scope) == (None, [], None)
        assert cna.auto_ignore is False
        assert cna.id.version == 7
        assert await _cna_count(db_session, org_id) == 1

    async def test_creates_a_row_without_a_short_name(
        self, db_session: AsyncSession
    ) -> None:
        org_id = _org_id()

        cna = await resolve_ingested_cna(db_session, CNAEntry(org_id=org_id))

        assert (cna.short_name, cna.short_name_observed_at) == (None, None)

    async def test_repeated_call_returns_the_same_row_and_changes_nothing(
        self, db_session: AsyncSession
    ) -> None:
        org_id = _org_id()
        entry = CNAEntry(
            org_id=org_id, short_name="example", short_name_observed_at=NEW
        )
        first = await resolve_ingested_cna(db_session, entry)
        await db_session.execute(
            update(CNA).where(CNA.id == first.id).values(updated_at=STALE)
        )

        second = await resolve_ingested_cna(db_session, entry)

        assert second.id == first.id
        assert second.updated_at == STALE
        assert await _cna_count(db_session, org_id) == 1

    async def test_returns_auto_ignore_as_the_transaction_reads_it(
        self, db_session: AsyncSession, cna_factory: CNAFactory
    ) -> None:
        stored = await cna_factory(org_id=_org_id(), auto_ignore=True)

        cna = await resolve_ingested_cna(db_session, CNAEntry(org_id=stored.org_id))

        assert cna.id == stored.id
        assert cna.auto_ignore is True

    async def test_never_writes_the_metadata_or_the_policy(
        self, db_session: AsyncSession, cna_factory: CNAFactory
    ) -> None:
        stored = await cna_factory(
            org_id=_org_id(),
            short_name=None,
            organization_name="Example Corporation",
            types=["Vendor"],
            scope="Example products.",
            auto_ignore=True,
        )

        cna = await resolve_ingested_cna(
            db_session,
            CNAEntry(org_id=stored.org_id, short_name="example"),
        )

        assert (cna.organization_name, cna.types, cna.scope, cna.auto_ignore) == (
            "Example Corporation",
            ["Vendor"],
            "Example products.",
            True,
        )
        assert cna.short_name == "example"

    async def test_creates_no_audit_event(self, db_session: AsyncSession) -> None:
        before = await db_session.scalar(
            select(func.count()).select_from(TicketAuditEvent)
        )

        await resolve_ingested_cna(
            db_session, CNAEntry(org_id=_org_id(), short_name="example")
        )

        assert (
            await db_session.scalar(select(func.count()).select_from(TicketAuditEvent))
            == before
        )


# Every row of cna.md (Short Name): (stored short name, stored date, entry
# short name, entry date) -> (resulting short name, resulting date, whether
# the row changed).
_SHORT_NAME_RULES: list[tuple[Any, ...]] = [
    pytest.param("old", OLD, None, None, "old", OLD, False, id="no-entry-name"),
    pytest.param(None, None, None, None, None, None, False, id="nothing-to-nothing"),
    pytest.param(None, None, "new", NEW, "new", NEW, True, id="no-name-dated"),
    pytest.param(None, None, "new", None, "new", None, True, id="no-name-undated"),
    pytest.param("same", None, "same", NEW, "same", NEW, True, id="same-undated-dated"),
    pytest.param("same", OLD, "same", NEW, "same", OLD, False, id="same-dated-later"),
    pytest.param("same", NEW, "same", OLD, "same", NEW, False, id="same-dated-earlier"),
    pytest.param(
        "same", OLD, "same", None, "same", OLD, False, id="same-undated-entry"
    ),
    pytest.param(
        "same", None, "same", None, "same", None, False, id="same-both-undated"
    ),
    pytest.param("old", None, "new", NEW, "new", NEW, True, id="other-undated-dated"),
    pytest.param("old", OLD, "new", NEW, "new", NEW, True, id="other-earlier-dated"),
    pytest.param("old", NEW, "new", NEW, "new", NEW, True, id="other-equal-date"),
    pytest.param("old", NEW, "new", OLD, "old", NEW, False, id="other-later-stored"),
    pytest.param("old", OLD, "new", None, "old", OLD, False, id="other-undated-entry"),
    pytest.param("old", None, "new", None, "old", None, False, id="other-both-undated"),
]


@pytest.mark.integration
class TestShortNameRules:
    @pytest.mark.parametrize(
        (
            "stored_name",
            "stored_date",
            "entry_name",
            "entry_date",
            "name",
            "date",
            "changed",
        ),
        _SHORT_NAME_RULES,
    )
    async def test_short_name_rule_yields_the_specified_row(
        self,
        db_session: AsyncSession,
        cna_factory: CNAFactory,
        stored_name: str | None,
        stored_date: datetime | None,
        entry_name: str | None,
        entry_date: datetime | None,
        name: str | None,
        date: datetime | None,
        changed: bool,
    ) -> None:
        stored = await cna_factory(
            org_id=_org_id(),
            short_name=stored_name,
            short_name_observed_at=stored_date,
        )
        await db_session.execute(
            update(CNA).where(CNA.id == stored.id).values(updated_at=STALE)
        )

        cna = await resolve_ingested_cna(
            db_session,
            CNAEntry(
                org_id=stored.org_id,
                short_name=entry_name,
                short_name_observed_at=entry_date,
            ),
        )

        assert cna.id == stored.id
        assert (cna.short_name, cna.short_name_observed_at) == (name, date)
        # `updated_at` advances only with an effective change.
        assert (cna.updated_at != STALE) is changed

    async def test_old_record_keeps_the_current_short_name_in_any_order(
        self, db_session: AsyncSession
    ) -> None:
        """The `@huntrdev`/`@huntr_ai` case: whichever record arrives first,
        the stored name is the one of the later record."""
        later = CNAEntry(
            org_id=_org_id(), short_name="@huntr_ai", short_name_observed_at=NEW
        )
        earlier = CNAEntry(
            org_id=later.org_id, short_name="@huntrdev", short_name_observed_at=OLD
        )

        await resolve_ingested_cna(db_session, later)
        after_old = await resolve_ingested_cna(db_session, earlier)

        assert (after_old.short_name, after_old.short_name_observed_at) == (
            "@huntr_ai",
            NEW,
        )

        other = CNAEntry(
            org_id=_org_id(), short_name="@huntrdev", short_name_observed_at=OLD
        )
        await resolve_ingested_cna(db_session, other)
        renamed = await resolve_ingested_cna(
            db_session,
            CNAEntry(
                org_id=other.org_id, short_name="@huntr_ai", short_name_observed_at=NEW
            ),
        )

        assert (renamed.short_name, renamed.short_name_observed_at) == (
            "@huntr_ai",
            NEW,
        )

    async def test_kernel_constant_sets_only_a_row_without_a_short_name(
        self, db_session: AsyncSession, cna_factory: CNAFactory
    ) -> None:
        named = await cna_factory(org_id=_org_id(), short_name="Linux-old")
        unnamed = await cna_factory(org_id=_org_id(), short_name=None)

        kept = await resolve_ingested_cna(
            db_session, CNAEntry(org_id=named.org_id, short_name="Linux")
        )
        set_ = await resolve_ingested_cna(
            db_session, CNAEntry(org_id=unnamed.org_id, short_name="Linux")
        )

        assert kept.short_name == "Linux-old"
        assert set_.short_name == "Linux"

    async def test_short_name_comparison_is_case_sensitive(
        self, db_session: AsyncSession, cna_factory: CNAFactory
    ) -> None:
        stored = await cna_factory(
            org_id=_org_id(), short_name="netgear", short_name_observed_at=OLD
        )

        cna = await resolve_ingested_cna(
            db_session,
            CNAEntry(
                org_id=stored.org_id, short_name="NETGEAR", short_name_observed_at=NEW
            ),
        )

        assert cna.short_name == "NETGEAR"


# ---------------------------------------------------------------------------
# list_cnas()
# ---------------------------------------------------------------------------


@pytest.fixture
def token() -> str:
    """A unique fictional search token that isolates the listed CNAs from
    any other row of the database."""
    return f"zq{uuid.uuid4().hex[:10]}"


async def _list(
    db: AsyncSession,
    *,
    search: str | None,
    auto_ignore: bool | None = None,
    page: int = 1,
    per_page: int = 20,
    sort_by: CNASortField = CNASortField.NAME,
    sort_order: SortOrder = SortOrder.ASC,
) -> CNAListResult:
    return await list_cnas(
        db,
        search=search,
        auto_ignore=auto_ignore,
        page=page,
        per_page=per_page,
        sort_by=sort_by,
        sort_order=sort_order,
    )


def _names(result: CNAListResult) -> list[str | None]:
    return [cna.short_name for cna in result.items]


@pytest.mark.integration
class TestListCnas:
    async def test_search_matches_a_substring_of_either_name_case_insensitively(
        self, db_session: AsyncSession, cna_factory: CNAFactory, token: str
    ) -> None:
        short = await cna_factory(short_name=f"{token}-short")
        organization = await cna_factory(
            short_name=f"other-{uuid.uuid4().hex[:8]}",
            organization_name=f"Example {token.upper()} Org",
        )
        await cna_factory(short_name="unrelated", organization_name="Unrelated")

        result = await _list(db_session, search=f"  {token.upper()}  ")

        assert result.total == 2
        # `Example …` sorts before the lowercase short name in code-point order.
        assert [cna.id for cna in result.items] == [organization.id, short.id]

    @pytest.mark.parametrize("literal", ["%", "_", "\\"])
    async def test_pattern_characters_match_literally(
        self,
        db_session: AsyncSession,
        cna_factory: CNAFactory,
        token: str,
        literal: str,
    ) -> None:
        await cna_factory(short_name=f"{token}{literal}x")
        await cna_factory(short_name=f"{token}yx")

        result = await _list(db_session, search=f"{token}{literal}")

        assert _names(result) == [f"{token}{literal}x"]

    async def test_blank_search_applies_no_search(
        self, db_session: AsyncSession, cna_factory: CNAFactory
    ) -> None:
        await cna_factory()
        total = (await _list(db_session, search=None)).total

        assert (await _list(db_session, search="   ")).total == total
        assert total >= 1

    @pytest.mark.parametrize("auto_ignore", [True, False])
    async def test_auto_ignore_filter_combines_with_search(
        self,
        db_session: AsyncSession,
        cna_factory: CNAFactory,
        token: str,
        auto_ignore: bool,
    ) -> None:
        await cna_factory(short_name=f"{token}-on", auto_ignore=True)
        await cna_factory(short_name=f"{token}-off", auto_ignore=False)

        result = await _list(db_session, search=token, auto_ignore=auto_ignore)

        assert _names(result) == [f"{token}-on" if auto_ignore else f"{token}-off"]

    async def test_name_order_uses_the_display_name_in_code_point_order(
        self, db_session: AsyncSession, cna_factory: CNAFactory, token: str
    ) -> None:
        """The organization name wins over the short name; an uppercase
        letter sorts before every lowercase one in code-point order, unlike a
        locale collation."""
        await cna_factory(short_name=f"{token}-1", organization_name=f"a {token}")
        await cna_factory(short_name=f"{token}-2")
        await cna_factory(short_name=f"{token}-3", organization_name=f"B {token}")

        ascending = await _list(db_session, search=token)
        descending = await _list(db_session, search=token, sort_order=SortOrder.DESC)

        assert _names(ascending) == [f"{token}-3", f"{token}-1", f"{token}-2"]
        assert _names(descending) == [f"{token}-2", f"{token}-1", f"{token}-3"]

    @pytest.mark.parametrize("sort_order", [SortOrder.ASC, SortOrder.DESC])
    async def test_null_short_name_sorts_last_in_both_directions(
        self,
        db_session: AsyncSession,
        cna_factory: CNAFactory,
        token: str,
        sort_order: SortOrder,
    ) -> None:
        unnamed = await cna_factory(short_name=None, organization_name=f"{token} org")
        first = await cna_factory(short_name=f"{token}-a")
        second = await cna_factory(short_name=f"{token}-b")

        result = await _list(
            db_session,
            search=token,
            sort_by=CNASortField.SHORT_NAME,
            sort_order=sort_order,
        )

        named = [first.id, second.id]
        if sort_order is SortOrder.DESC:
            named.reverse()
        assert [cna.id for cna in result.items] == [*named, unnamed.id]

    @pytest.mark.parametrize("sort_order", [SortOrder.ASC, SortOrder.DESC])
    async def test_null_display_name_sorts_last_in_both_directions(
        self,
        db_session: AsyncSession,
        cna_factory: CNAFactory,
        sort_order: SortOrder,
    ) -> None:
        """A CNA without a short name has no display name: only a row with a
        short name can match the CNA list (cna.md, Display Name)."""
        unnamed = await cna_factory(short_name=None)
        named = await cna_factory()

        result = await _list(
            db_session, search=None, sort_order=sort_order, per_page=100
        )

        assert result.total <= 100
        ids = [cna.id for cna in result.items]
        assert ids.index(named.id) < ids.index(unnamed.id)
        # Every row after the first unnamed one is unnamed too.
        assert all(
            cna.organization_name is None and cna.short_name is None
            for cna in result.items[ids.index(unnamed.id) :]
        )

    async def test_short_name_order(
        self, db_session: AsyncSession, cna_factory: CNAFactory, token: str
    ) -> None:
        first = await cna_factory(short_name=f"{token}-b")
        second = await cna_factory(short_name=f"{token}-a")

        by_short = await _list(
            db_session, search=token, sort_by=CNASortField.SHORT_NAME
        )

        assert [c.id for c in by_short.items] == [second.id, first.id]

    @pytest.mark.parametrize("sort_order", [SortOrder.ASC, SortOrder.DESC])
    async def test_created_at_order_with_the_id_tie_breaker(
        self,
        db_session: AsyncSession,
        cna_factory: CNAFactory,
        token: str,
        sort_order: SortOrder,
    ) -> None:
        """The later `created_at` sorts by its value, not by its id; two rows
        with an equal `created_at` are ordered by `CNA.id` in the same
        direction."""
        older = await cna_factory(short_name=f"{token}-older")
        tied_a = await cna_factory(short_name=f"{token}-tied-a")
        tied_b = await cna_factory(short_name=f"{token}-tied-b")
        await db_session.execute(
            update(CNA).where(CNA.id == older.id).values(created_at=NEW)
        )
        for cna in (tied_a, tied_b):
            await db_session.execute(
                update(CNA).where(CNA.id == cna.id).values(created_at=OLD)
            )

        result = await _list(
            db_session,
            search=token,
            sort_by=CNASortField.CREATED_AT,
            sort_order=sort_order,
        )

        tied = sorted([tied_a.id, tied_b.id])
        expected = [*tied, older.id]
        if sort_order is SortOrder.DESC:
            expected.reverse()
        assert [c.id for c in result.items] == expected

    async def test_pagination_and_a_page_beyond_the_last(
        self, db_session: AsyncSession, cna_factory: CNAFactory, token: str
    ) -> None:
        for suffix in ("a", "b", "c"):
            await cna_factory(short_name=f"{token}-{suffix}")

        first = await _list(db_session, search=token, per_page=2)
        second = await _list(db_session, search=token, per_page=2, page=2)
        beyond = await _list(db_session, search=token, per_page=2, page=3)

        assert (first.total, second.total, beyond.total) == (3, 3, 3)
        assert _names(first) == [f"{token}-a", f"{token}-b"]
        assert _names(second) == [f"{token}-c"]
        assert beyond.items == ()
        assert (beyond.page, beyond.per_page) == (3, 2)

    async def test_no_match_is_an_empty_page_with_total_zero(
        self, db_session: AsyncSession, token: str
    ) -> None:
        result = await _list(db_session, search=token)

        assert (result.items, result.total) == ((), 0)

    @pytest.mark.parametrize(("page", "per_page"), [(0, 20), (1, 0), (1, 101)])
    async def test_out_of_contract_page_raises_before_any_query(
        self, db_session: AsyncSession, page: int, per_page: int
    ) -> None:
        with pytest.raises(ValueError, match="page"):
            await _list(db_session, search=None, page=page, per_page=per_page)


# ---------------------------------------------------------------------------
# get_cna()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestGetCna:
    async def test_returns_the_row_by_org_id_in_either_case(
        self, db_session: AsyncSession, cna_factory: CNAFactory
    ) -> None:
        stored = await cna_factory(
            org_id=uuid.UUID("00000000-0000-4000-8000-0000000abcde")
        )

        lower = await get_cna(db_session, "00000000-0000-4000-8000-0000000abcde")
        upper = await get_cna(db_session, "00000000-0000-4000-8000-0000000ABCDE")

        assert lower.id == upper.id == stored.id

    async def test_malformed_org_id_raises_not_found_without_a_query(
        self, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Every malformed form is pinned by the Core parser's tests
        (`tests/test_core/test_identifiers.py`); one suffices here."""
        execute = AsyncMock(side_effect=AssertionError("no query expected"))
        monkeypatch.setattr(db_session, "execute", execute)

        with pytest.raises(CNANotFoundError):
            await get_cna(db_session, "000000000000400080000000000abcde")

        execute.assert_not_awaited()

    async def test_unknown_org_id_raises_not_found(
        self, db_session: AsyncSession
    ) -> None:
        with pytest.raises(CNANotFoundError):
            await get_cna(db_session, str(_org_id()))


# ---------------------------------------------------------------------------
# Module contract
# ---------------------------------------------------------------------------


_MODULE = APP_ROOT / "services" / "cna_service.py"


@pytest.mark.unit
class TestModuleContract:
    def test_exceptions_inherit_from_the_service_error_root(self) -> None:
        assert issubclass(CNAServiceError, ServiceError)
        assert issubclass(CNANotFoundError, CNAServiceError)
        assert str(CNANotFoundError()) == "CNA not found."

    def test_module_performs_no_network_redis_or_task_io(self) -> None:
        modules = imported_modules(_MODULE, "app.services")

        assert {
            m
            for m in modules
            for prefix in ("httpx", "redis", "celery", "app.services.task_publication")
            if m == prefix or m.startswith(f"{prefix}.")
        } == set()

    def test_public_functions_have_the_specified_async_shape(self) -> None:
        for function in (resolve_ingested_cna, list_cnas, get_cna):
            assert inspect.iscoroutinefunction(function), function.__name__
        assert not inspect.iscoroutinefunction(cna_filter_condition)

    def test_module_never_commits_or_rolls_back(self) -> None:
        source = _MODULE.read_text(encoding="utf-8")

        assert ".commit(" not in source
        assert ".rollback(" not in source
