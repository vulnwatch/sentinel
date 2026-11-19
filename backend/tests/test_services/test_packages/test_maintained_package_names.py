"""Tests for `app.services.packages.maintained_package_names`.

Owning specification: docs/features/packages/maintained-package-names.md
(Snapshot; Publication Boundary; Service, `search_maintained_packages()`;
Test Requirements, Search and Publication). Shared rules:
docs/api-spec.md (Pagination; Deterministic Pagination Ordering);
docs/features/platform/testing-strategy.md (Concurrency Testing, Lock-Wait
Observation).

Every `db_session` test starts from an empty table (per-test rollback); a
publication through `db_session` commits a savepoint only. The
independent-session tests commit real snapshots and empty the table at
teardown: the publication replaces the whole table, and every test that
commits rows into it (here and the `run()` tests of
`test_sync_smelt_packages.py`) starts from an empty table and empties it.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator, Awaitable, Callable, Coroutine
from typing import Any, Final
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import delete, event, insert, select, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.maintained_package import MaintainedPackage
from app.services.packages.maintained_package_names import (
    MAX_PER_PAGE,
    MaintainedPackagePage,
    MaintainedPackagePublication,
    publish_maintained_packages,
    search_maintained_packages,
)
from tests.support.database import assert_lock_wait

SessionFactory = Callable[[], Awaitable[AsyncSession]]

ROW_LOCKS: Final = ("FOR UPDATE", "FOR NO KEY UPDATE", "FOR SHARE", "FOR KEY SHARE")


async def _store(db: AsyncSession, *names: str) -> None:
    await db.execute(insert(MaintainedPackage), [{"name": name} for name in names])


async def _names(db: AsyncSession, search: str | None = None) -> list[str]:
    """The names of one complete page; the total must equal the page."""
    result = await search_maintained_packages(db, search=search, per_page=MAX_PER_PAGE)
    assert result.total == len(result.names)
    return list(result.names)


async def _table(db: AsyncSession) -> set[str]:
    return set((await db.scalars(select(MaintainedPackage.name))).all())


class _StatementRecorder:
    """Records every SQL statement executed through the session's engine."""

    def __init__(self, db: AsyncSession) -> None:
        self._engine = db.get_bind().engine
        self.statements: list[str] = []

    def _record(self, *args: Any) -> None:
        self.statements.append(args[2])

    def __enter__(self) -> _StatementRecorder:
        event.listen(self._engine, "before_cursor_execute", self._record)
        return self

    def __exit__(self, *exc: object) -> None:
        event.remove(self._engine, "before_cursor_execute", self._record)


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestSearchMatching:
    async def test_matches_part_of_a_name_without_regard_to_letter_case(
        self, db_session: AsyncSession
    ) -> None:
        await _store(
            db_session, "fictional-openssl", "fictional-openssl-3", "fictional-curl"
        )

        assert await _names(db_session, "OPENSS") == [
            "fictional-openssl",
            "fictional-openssl-3",
        ]
        assert await _names(db_session, "SSL-3") == ["fictional-openssl-3"]
        assert await _names(db_session, "no-such-name") == []

    async def test_names_that_differ_only_in_letter_case_are_both_returned(
        self, db_session: AsyncSession
    ) -> None:
        await _store(db_session, "python-FictionalTable", "python-fictionaltable")

        assert await _names(db_session, "fictionaltable") == [
            "python-FictionalTable",
            "python-fictionaltable",
        ]

    @pytest.mark.parametrize(
        ("term", "expected"),
        [
            ("%", ["fictional-100%"]),
            ("_", ["fictional_tool"]),
            ("\\", ["fictional\\path"]),
            ("l_t", ["fictional_tool"]),
            ("l%", []),
        ],
        ids=["percent", "underscore", "backslash", "underscore-inside", "percent-end"],
    )
    async def test_pattern_characters_are_literal(
        self, db_session: AsyncSession, term: str, expected: list[str]
    ) -> None:
        await _store(
            db_session, "fictional-100%", "fictional_tool", "fictional\\path", "flat"
        )

        assert await _names(db_session, term) == expected

    async def test_outer_whitespace_is_trimmed_once(
        self, db_session: AsyncSession
    ) -> None:
        await _store(db_session, "fictional-curl", "fictional-zlib")

        assert await _names(db_session, "  curl\t") == ["fictional-curl"]

    @pytest.mark.parametrize("term", ["", "   ", "\t\n", None])
    async def test_empty_or_whitespace_only_term_is_no_filter(
        self, db_session: AsyncSession, term: str | None
    ) -> None:
        await _store(db_session, "fictional-zlib", "fictional-curl")

        assert await _names(db_session, term) == ["fictional-curl", "fictional-zlib"]


@pytest.mark.integration
class TestSearchOrder:
    async def test_names_that_start_with_the_term_come_first(
        self, db_session: AsyncSession
    ) -> None:
        await _store(
            db_session,
            "libfictional-openssl",
            "fictional-openssl-3",
            "compat-fictional-openssl",
            "fictional-openssl",
        )

        assert await _names(db_session, "fictional-openssl") == [
            "fictional-openssl",
            "fictional-openssl-3",
            "compat-fictional-openssl",
            "libfictional-openssl",
        ]

    async def test_prefix_is_compared_without_regard_to_letter_case(
        self, db_session: AsyncSession
    ) -> None:
        await _store(db_session, "libfictional-imagetool", "Fictional-ImageTool")

        assert await _names(db_session, "fICTIONAL") == [
            "Fictional-ImageTool",
            "libfictional-imagetool",
        ]

    async def test_code_point_order_without_a_term_and_within_each_group(
        self, db_session: AsyncSession
    ) -> None:
        """Code-point order puts uppercase before lowercase and `É` after
        every ASCII letter, which a linguistic collation orders otherwise."""
        # The check is meaningful only where the default collation is not
        # code-point order, whatever its provider.
        assert await db_session.scalar(text("SELECT 'alpha-x' < 'Zeta-x'"))
        await _store(
            db_session, "beta-x", "Zeta-x", "Éclair-x", "alpha-x", "x-Beta", "x-alpha"
        )

        assert await _names(db_session) == [
            "Zeta-x",
            "alpha-x",
            "beta-x",
            "x-Beta",
            "x-alpha",
            "Éclair-x",
        ]
        assert await _names(db_session, "x") == [
            "x-Beta",
            "x-alpha",
            "Zeta-x",
            "alpha-x",
            "beta-x",
            "Éclair-x",
        ]


@pytest.mark.integration
class TestSearchPagination:
    async def test_pages_and_total(self, db_session: AsyncSession) -> None:
        await _store(db_session, *(f"fictional-pkg-{index:02}" for index in range(5)))

        first = await search_maintained_packages(db_session, page=1, per_page=2)
        last = await search_maintained_packages(db_session, page=3, per_page=2)

        assert first == MaintainedPackagePage(
            names=("fictional-pkg-00", "fictional-pkg-01"),
            total=5,
            page=1,
            per_page=2,
        )
        assert last == MaintainedPackagePage(
            names=("fictional-pkg-04",), total=5, page=3, per_page=2
        )

    async def test_page_beyond_the_last_is_empty_with_the_correct_total(
        self, db_session: AsyncSession
    ) -> None:
        await _store(db_session, "fictional-a", "fictional-b", "other")

        assert await search_maintained_packages(
            db_session, search="fictional", page=2, per_page=2
        ) == MaintainedPackagePage(names=(), total=2, page=2, per_page=2)

    @pytest.mark.parametrize("search", [None, "fictional"])
    async def test_no_name_before_the_first_publication(
        self, db_session: AsyncSession, search: str | None
    ) -> None:
        assert await search_maintained_packages(
            db_session, search=search, page=2, per_page=7
        ) == MaintainedPackagePage(names=(), total=0, page=2, per_page=7)

    async def test_boundary_page_sizes(self, db_session: AsyncSession) -> None:
        await _store(db_session, *(f"fictional-pkg-{index:03}" for index in range(101)))

        smallest = await search_maintained_packages(db_session, page=101, per_page=1)
        largest = await search_maintained_packages(db_session, per_page=100)

        assert smallest.names == ("fictional-pkg-100",)
        assert (smallest.total, largest.total) == (101, 101)
        assert len(largest.names) == 100


@pytest.mark.integration
class TestSearchIsReadOnly:
    async def test_one_statement_without_lock_or_write(
        self, db_session: AsyncSession
    ) -> None:
        await _store(db_session, "fictional-a", "fictional-b")

        for search in (None, "fictional", "a"):
            with _StatementRecorder(db_session) as recorder:
                await search_maintained_packages(db_session, search=search)
            (statement,) = recorder.statements
            assert statement.lstrip().upper().startswith(("SELECT", "WITH"))
            for row_lock in ROW_LOCKS:
                assert row_lock not in statement.upper()

        assert not db_session.new
        assert not db_session.dirty
        assert not db_session.deleted
        assert await _table(db_session) == {"fictional-a", "fictional-b"}


@pytest.mark.unit
class TestSearchGuards:
    @pytest.mark.parametrize(
        ("page", "per_page"), [(0, 20), (-1, 20), (1, 0), (1, -1), (1, 101)]
    )
    async def test_out_of_range_pagination_raises_before_any_statement(
        self, page: int, per_page: int
    ) -> None:
        db = AsyncMock(spec=AsyncSession)

        with pytest.raises(ValueError, match="page"):
            await search_maintained_packages(db, page=page, per_page=per_page)

        db.execute.assert_not_awaited()

    async def test_database_error_propagates(self) -> None:
        db = AsyncMock(spec=AsyncSession)
        failure = OperationalError("SELECT 1", {}, Exception("connection lost"))
        db.execute.side_effect = failure

        with pytest.raises(OperationalError) as excinfo:
            await search_maintained_packages(db)

        assert excinfo.value is failure


# ---------------------------------------------------------------------------
# Publication
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestPublication:
    async def test_first_publication_creates_every_name(
        self, db_session: AsyncSession
    ) -> None:
        result = await publish_maintained_packages(
            db_session, frozenset({"fictional-a", "Fictional-B"})
        )

        assert result == MaintainedPackagePublication(created=2, removed=0, unchanged=0)
        assert await _table(db_session) == {"fictional-a", "Fictional-B"}

    async def test_created_removed_and_unchanged_in_one_publication(
        self, db_session: AsyncSession
    ) -> None:
        await publish_maintained_packages(
            db_session, frozenset({"fictional-kept", "fictional-left"})
        )
        kept_before = (
            await db_session.execute(
                select(MaintainedPackage.id, MaintainedPackage.created_at).where(
                    MaintainedPackage.name == "fictional-kept"
                )
            )
        ).one()

        result = await publish_maintained_packages(
            db_session, frozenset({"fictional-kept", "fictional-new"})
        )

        assert result == MaintainedPackagePublication(created=1, removed=1, unchanged=1)
        assert await _table(db_session) == {"fictional-kept", "fictional-new"}
        kept_after = (
            await db_session.execute(
                select(MaintainedPackage.id, MaintainedPackage.created_at).where(
                    MaintainedPackage.name == "fictional-kept"
                )
            )
        ).one()
        assert tuple(kept_after) == tuple(kept_before)

    async def test_name_that_leaves_and_returns_gets_a_new_row(
        self, db_session: AsyncSession
    ) -> None:
        await publish_maintained_packages(db_session, frozenset({"fictional-a"}))
        first_id = await db_session.scalar(select(MaintainedPackage.id))
        await publish_maintained_packages(db_session, frozenset({"fictional-b"}))
        await publish_maintained_packages(db_session, frozenset({"fictional-a"}))

        assert await db_session.scalar(select(MaintainedPackage.id)) != first_id

    async def test_names_that_differ_only_in_letter_case_are_two_names(
        self, db_session: AsyncSession
    ) -> None:
        await publish_maintained_packages(
            db_session, frozenset({"python-FictionalTable"})
        )

        result = await publish_maintained_packages(
            db_session,
            frozenset({"python-FictionalTable", "python-fictionaltable"}),
        )

        assert result == MaintainedPackagePublication(created=1, removed=0, unchanged=1)

    async def test_re_publication_is_idempotent_and_commits_once(
        self, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        names = frozenset({"fictional-a", "fictional-b", "fictional-c"})
        await publish_maintained_packages(db_session, names)
        rows_before = (
            await db_session.execute(
                select(MaintainedPackage.id, MaintainedPackage.name)
            )
        ).all()

        commits = [0]
        original_commit = db_session.commit

        async def counted_commit() -> None:
            commits[0] += 1
            await original_commit()

        monkeypatch.setattr(db_session, "commit", counted_commit)

        result = await publish_maintained_packages(db_session, names)

        assert result == MaintainedPackagePublication(created=0, removed=0, unchanged=3)
        # Q3: the publication commits once also when nothing changes.
        assert commits == [1]
        rows_after = (
            await db_session.execute(
                select(MaintainedPackage.id, MaintainedPackage.name)
            )
        ).all()
        assert set(rows_after) == set(rows_before)

    async def test_large_snapshot_spans_several_statements(
        self, db_session: AsyncSession
    ) -> None:
        """More names than one INSERT or DELETE chunk holds."""
        first = frozenset(f"fictional-a-{index:04}" for index in range(2500))
        second = frozenset(f"fictional-b-{index:04}" for index in range(2100))

        assert await publish_maintained_packages(
            db_session, first
        ) == MaintainedPackagePublication(created=2500, removed=0, unchanged=0)
        assert await publish_maintained_packages(
            db_session, second
        ) == MaintainedPackagePublication(created=2100, removed=2500, unchanged=0)
        assert await _table(db_session) == set(second)


@pytest.mark.unit
class TestPublicationGuards:
    async def test_empty_set_is_rejected_before_any_write(self) -> None:
        db = AsyncMock(spec=AsyncSession)

        with pytest.raises(ValueError, match="at least one name"):
            await publish_maintained_packages(db, frozenset())

        db.execute.assert_not_awaited()
        db.scalars.assert_not_awaited()
        db.commit.assert_not_awaited()


# ---------------------------------------------------------------------------
# Independent sessions: rollback, serialization, and consistent reads
# ---------------------------------------------------------------------------


class _Committed:
    """Independent sessions over an initially empty table, and the tasks
    that run on them (testing-strategy.md, Concurrency Testing).

    Cleanup first cancels every unfinished task and rolls back every
    session, so a test that fails while a publication holds the table lock
    still releases it, then empties the table."""

    def __init__(self, factory: SessionFactory, cleaner: AsyncSession) -> None:
        self._factory = factory
        self._cleaner = cleaner
        self._sessions: list[AsyncSession] = []
        self._tasks: list[asyncio.Task[Any]] = []

    async def session(self) -> AsyncSession:
        session = await self._factory()
        self._sessions.append(session)
        return session

    def start[R](self, coroutine: Coroutine[Any, Any, R]) -> asyncio.Task[R]:
        task = asyncio.create_task(coroutine)
        self._tasks.append(task)
        return task

    async def cleanup(self) -> None:
        for task in self._tasks:
            if not task.done():
                task.cancel()
            with contextlib.suppress(Exception, asyncio.CancelledError):
                await task
        for session in self._sessions:
            with contextlib.suppress(Exception):
                await session.rollback()
        await self._cleaner.rollback()
        await self._cleaner.execute(delete(MaintainedPackage))
        await self._cleaner.commit()


@pytest.fixture
async def committed(db_session_factory: SessionFactory) -> AsyncIterator[_Committed]:
    cleaner = await db_session_factory()
    assert await _table(cleaner) == set()
    await cleaner.rollback()
    state = _Committed(db_session_factory, cleaner)
    try:
        yield state
    finally:
        await state.cleanup()


def _pause_before_commit(
    monkeypatch: pytest.MonkeyPatch, session: AsyncSession
) -> tuple[asyncio.Event, asyncio.Event]:
    """Hold `session`'s publication at its commit: `reached` is set when the
    publication calls `commit()`, which proceeds once `release` is set."""
    reached = asyncio.Event()
    release = asyncio.Event()
    original = session.commit

    async def _commit() -> None:
        reached.set()
        await release.wait()
        await original()

    monkeypatch.setattr(session, "commit", _commit)
    return reached, release


@pytest.mark.integration
class TestPublicationRollback:
    async def test_failed_publication_leaves_the_previous_snapshot(
        self, committed: _Committed, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        setup = await committed.session()
        await publish_maintained_packages(setup, frozenset({"fictional-a"}))
        publisher = await committed.session()
        failure = OperationalError("COMMIT", {}, Exception("connection lost"))

        async def _fail() -> None:
            raise failure

        monkeypatch.setattr(publisher, "commit", _fail)

        with pytest.raises(OperationalError) as excinfo:
            await publish_maintained_packages(
                publisher, frozenset({"fictional-b", "fictional-c"})
            )
        await publisher.rollback()

        assert excinfo.value is failure
        assert await _table(await committed.session()) == {"fictional-a"}


@pytest.mark.integration
class TestOverlappingPublications:
    async def test_later_commit_leaves_its_own_snapshot(
        self, committed: _Committed, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        setup = await committed.session()
        await publish_maintained_packages(setup, frozenset({"fictional-x"}))
        first = await committed.session()
        second = await committed.session()
        reached, release = _pause_before_commit(monkeypatch, first)

        first_task = committed.start(
            publish_maintained_packages(
                first, frozenset({"fictional-a", "fictional-b"})
            )
        )
        await asyncio.wait_for(reached.wait(), timeout=5)
        second_task = committed.start(
            publish_maintained_packages(
                second, frozenset({"fictional-b", "fictional-c"})
            )
        )
        await assert_lock_wait(second_task, waiter=second, blocked_by=first)
        release.set()

        assert await asyncio.wait_for(
            first_task, timeout=5
        ) == MaintainedPackagePublication(created=2, removed=1, unchanged=0)
        # The second publication read the snapshot that the first committed.
        assert await asyncio.wait_for(
            second_task, timeout=5
        ) == MaintainedPackagePublication(created=1, removed=1, unchanged=1)
        assert await _table(await committed.session()) == {
            "fictional-b",
            "fictional-c",
        }


@pytest.mark.integration
class TestConsistentSearch:
    """A search never reads part of a publication and never waits for one.

    The single-statement assertion of `TestSearchIsReadOnly` proves that the
    page and the total come from one observation; this test proves that the
    observation is the previous snapshot whole while a publication is
    uncommitted, without waiting on its lock."""

    async def test_search_during_a_publication_sees_the_previous_snapshot_whole(
        self, committed: _Committed, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        setup = await committed.session()
        await publish_maintained_packages(
            setup, frozenset({"fictional-old-1", "fictional-old-2"})
        )
        publisher = await committed.session()
        reader = await committed.session()
        reached, release = _pause_before_commit(monkeypatch, publisher)

        task = committed.start(
            publish_maintained_packages(
                publisher,
                frozenset({"fictional-new-1", "fictional-new-2", "fictional-new-3"}),
            )
        )
        await asyncio.wait_for(reached.wait(), timeout=5)

        during = await asyncio.wait_for(
            search_maintained_packages(reader, search="fictional"), timeout=5
        )
        await reader.rollback()
        release.set()
        await asyncio.wait_for(task, timeout=5)
        after = await search_maintained_packages(reader, search="fictional")

        assert during == MaintainedPackagePage(
            names=("fictional-old-1", "fictional-old-2"),
            total=2,
            page=1,
            per_page=20,
        )
        assert after == MaintainedPackagePage(
            names=("fictional-new-1", "fictional-new-2", "fictional-new-3"),
            total=3,
            page=1,
            per_page=20,
        )
