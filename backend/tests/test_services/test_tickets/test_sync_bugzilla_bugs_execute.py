"""Tests for the periodic `SyncBugzillaBugs.execute()` and its `run()` metrics
(backend/app/services/tickets/sync_bugzilla_bugs.py).

Owning specifications:

- docs/features/tickets/cve-sync-bugzilla.md (The Bug of a CVE; Bug
  Reference; Algorithm, `execute()` steps 1-6; First Run Behavior; Stale
  Cursor Handling; Lookback; Cursor Mechanism; Payload; Response
  Validation, including External String Admissibility; Error Handling, the
  `execute()` tables and Sanitized error messages; Metrics; Behavioral
  Notes; Security and Privacy).
- docs/features/platform/cve-fetcher-infrastructure.md (`CVEFetchResult`;
  Per-CVE Finalization; Session Lifecycle for API-based CVE Fetchers, the
  inline paginated template, isolated status commit, and metric placement;
  Batch Error Handling, Per-item failure event; Metric Definitions).
- docs/features/platform/fetcher-infrastructure.md (Error Message
  Sanitization; Request Delay; `SoftTimeLimitExceeded` handling
  convention) and docs/features/platform/logging.md (Secrets and PII
  Discipline).
- docs/features/platform/testing-strategy.md (Fetcher Outcome and Effect
  Accounting, the `sync_bugzilla_bugs` mapping; CVE Fetcher
  Infrastructure; External String Admissibility; External JSON Decoding;
  Parallel Execution).

Every test commits real rows: CVEs with or without Tickets of an
`IngestionWorld` (deleted at teardown with their children, references, and
Ticket events, including a Ticket the code under test creates for an
orphan CVE), the `sync_bugzilla_bugs` `FetcherConfig` and its `FetcherRun`
rows, and a test-only "other fetcher" configuration. CVE-IDs that must stay
unknown are drawn from the world too, so a row created by mistake is
deleted as well. The derived cursor is read from the latest
`success`/`partial` `FetcherRun` of the fetcher's own name, so these tests
own every committed row under that name while they run:

- each pytest-xdist worker uses its own PostgreSQL database and runs one
  test at a time (testing-strategy.md, Parallel Execution);
- inside a worker, no other test leaves a committed `sync_bugzilla_bugs`
  row: the reachability tests delete the configuration they seed and create
  no run, and bootstrap tests roll back;
- the `env` fixture asserts that no such row exists before it seeds its own
  and none remains at teardown, and that the number of committed CVEs is
  unchanged, so a leak fails loudly.

`execute()` tests use an independent `db_session_factory` session with real
commits and set the automatic periodic context that `run()` establishes.
HTTP is the in-process `BugzillaServer`; the broker call is the recorded
`task_publication.publish_task`; the isolated status sessions are counted
and `_isolated_status_commit()` is spied; the request-delay sleep is
recorded instead of slept. All identifiers and texts are fictional, except
the public data of the live fixtures.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import (
    AsyncIterator,
    Awaitable,
    Callable,
    Iterable,
    Iterator,
    Mapping,
    Sequence,
)
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Final, NamedTuple

import httpx
import pytest
from celery.exceptions import SoftTimeLimitExceeded
from kombu.exceptions import EncodeError
from sqlalchemy import delete, event, func, select
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession, async_sessionmaker
from structlog.contextvars import merge_contextvars
from structlog.testing import capture_logs

import app.services.base_cve_fetcher as base_cve_fetcher_module
import app.services.base_fetcher as base_fetcher_module
from app.core.enums import CVESourceFetchStatus
from app.models.cve import CVE
from app.models.cve_source import CVESource
from app.models.fetcher_config import FetcherConfig
from app.models.fetcher_run import FetcherRun
from app.models.ticket import Ticket
from app.models.ticket_reference import TicketReference
from app.services import (
    cve_service,
    reference_service,
    task_publication,
    ticket_convergence_publication,
)
from app.services.base_cve_fetcher import CVE_FETCH_ITEM_FAILED_EVENT, CVEFetchResult
from app.services.base_fetcher import FetcherError, FetcherRunConfig
from app.services.cve_ingest import CVEIngestPayload, UpsertAction
from app.services.json_decoding import JSONNestingError
from app.services.tickets import sync_bugzilla_bugs as sync_module
from app.services.tickets.bugzilla_bug_record import BugzillaBug
from app.services.tickets.sync_bugzilla_bugs import (
    BUGZILLA_CURSOR_RESET_EVENT,
    CONNECTION_FAILED,
    UNPARSEABLE_RESPONSE,
    SyncBugzillaBugs,
)
from tests.support.bugzilla import (
    BUG_URL,
    CONSUMED_FIELDS,
    ERROR_400_FIXTURE,
    BugzillaServer,
    Responder,
    bug,
    bug_reference_url,
    envelope,
    html,
    load_raw_fixture,
    page_bugs,
    raising,
    status,
    undecodable,
)
from tests.support.bugzilla import body as json_body
from tests.support.cve_catch_up import Publications
from tests.support.cve_ingest import IngestionWorld
from tests.support.http_client_errors import (
    CONFIGURATION_ERRORS,
    PROXY_SECRET,
    ConfigurationError,
    break_shared_client,
)
from tests.support.inadmissible import INADMISSIBLE_CHARACTERS
from tests.support.json_decoding import (
    NESTED_ARRAY,
    OVERSIZED_INTEGER,
    limit_parser_nesting,
)
from tests.support.ticket_mutations import EventRow, ticket_events_by_id

SessionFactory = Callable[[], Awaitable[AsyncSession]]

NAME: Final = "sync_bugzilla_bugs"
INGESTION_COMMENT: Final = "CVE ingested from SUSE Bugzilla"
PERSONAL_TEXT: Final = "Reported by Alice Example <alice.example@example.invalid>"
SECRET_VALUE: Final = "api_token=Example-Secret-Token-0123456789"
FAILURE_TEXT: Final = f"{PERSONAL_TEXT}; {SECRET_VALUE}"
"""Exception or upstream text that must appear in no log field or error."""

FAILED_EVENT_KEYS: Final = frozenset(
    {"event", "log_level", "cve_id", "fetcher_name", "cause"}
)
LOOKBACK: Final = timedelta(hours=12)
STALE_AFTER: Final = timedelta(days=30)
WINDOW_FORMAT: Final = "%Y-%m-%dT%H:%M:%SZ"
BATCH_DELAY: Final = 0.25
_RUN_CONFIG: Final = FetcherRunConfig(
    hard_time_limit_seconds=3600, request_delay=0.5, custom_settings={}
)


class Counters(NamedTuple):
    succeeded: int
    created: int
    updated: int
    failed: int


def counters(fetcher: SyncBugzillaBugs) -> Counters:
    return Counters(
        fetcher._succeeded, fetcher._created, fetcher._updated, fetcher._failed
    )


def _events(logs: Iterable[Mapping[str, Any]], name: str) -> list[Mapping[str, Any]]:
    return [entry for entry in logs if entry["event"] == name]


def _assert_private(logs: Iterable[Mapping[str, Any]], *values: str) -> None:
    for entry in logs:
        rendered = repr(dict(entry))
        for fragment in (
            FAILURE_TEXT,
            PERSONAL_TEXT,
            SECRET_VALUE,
            "Alice",
            "fictional summary",
            "\\x00",
            "\\ud800",
            *values,
        ):
            assert fragment not in rendered, entry


def _assert_content_free(*values: str | None) -> None:
    for value in values:
        if value is None:
            continue
        for fragment in (FAILURE_TEXT, PERSONAL_TEXT, SECRET_VALUE, "fictional"):
            assert fragment not in value, (fragment, value)


def _failed(cve_id: str, cause: str) -> dict[str, Any]:
    """The exact `cve_fetch_item_failed` WARNING."""
    return {
        "event": CVE_FETCH_ITEM_FAILED_EVENT,
        "log_level": "warning",
        "cve_id": cve_id,
        "fetcher_name": NAME,
        "cause": cause,
    }


def _since(cursor: datetime) -> str:
    return (cursor - LOOKBACK).strftime(WINDOW_FORMAT)


def _page_params(after_id: int, since: str) -> list[tuple[str, str]]:
    """The documented query of one page, in order (Algorithm step 4)."""
    return [
        ("include_fields", CONSUMED_FIELDS),
        ("f1", "alias"),
        ("o1", "substring"),
        ("v1", "CVE-"),
        ("f2", "bug_id"),
        ("o2", "greaterthan"),
        ("v2", str(after_id)),
        ("last_change_time", since),
        ("order", "bug_id"),
        ("limit", "1000"),
    ]


def _outcome(run: FetcherRun) -> tuple[str, int, int, int, int]:
    return (
        run.status,
        run.items_succeeded,
        run.items_created,
        run.items_updated,
        run.items_failed,
    )


_bug_ids = iter(range(1_900_000, 2_000_000))


def _bug(*aliases: str, **members: Any) -> dict[str, Any]:
    """A fictional public bug with the next fictional bug ID."""
    return bug(next(_bug_ids), *aliases, **members)


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


@dataclass
class Env:
    world: IngestionWorld
    factory: async_sessionmaker[AsyncSession]
    server: BugzillaServer
    published: Publications
    cve_baseline: int
    sleeps: list[tuple[float, int]] = field(default_factory=list)
    """Each recorded request-delay sleep and the number of requests made
    before it."""
    status_opened: list[int] = field(default_factory=lambda: [0])
    isolated: list[tuple[str, CVESourceFetchStatus]] = field(default_factory=list)
    other_names: list[str] = field(default_factory=list)

    # -- data ----------------------------------------------------------

    async def cve(self) -> CVE:
        """A committed CVE with an `Analysis` Ticket."""
        cve = await self.world.cve_in()
        await self.world.ticket(cve_id=cve.id)
        return cve

    async def orphan(self) -> CVE:
        """A committed CVE without a Ticket."""
        return await self.world.cve_in()

    def new_cve_id(self) -> str:
        """A CVE-ID absent from the database, deleted at teardown should
        the code under test create it."""
        return self.world.new_cve_id()

    def serve(self, *bugs: Mapping[str, Any]) -> None:
        self.server.bugs = [dict(item) for item in bugs]

    # -- runs ------------------------------------------------------------

    async def seed_run(
        self,
        status_value: str,
        started_at: datetime | None,
        *,
        fetcher_name: str = NAME,
    ) -> uuid.UUID:
        async with self.factory() as session:
            run = FetcherRun(
                fetcher_name=fetcher_name,
                started_at=started_at,
                status=status_value,
                triggered_by="schedule",
            )
            session.add(run)
            await session.commit()
            return run.id

    async def other_fetcher(self) -> str:
        name = f"test_bugzilla_other_{uuid.uuid4().hex[:12]}"
        async with self.factory() as session:
            session.add(FetcherConfig(fetcher_name=name, enabled=True))
            await session.commit()
        self.other_names.append(name)
        return name

    def fetcher(self) -> SyncBugzillaBugs:
        instance = SyncBugzillaBugs()
        instance._http_client = self.server.client()
        return instance

    async def batch(
        self, *, cursor: bool = True, request_delay: float = BATCH_DELAY
    ) -> Batch:
        """An `execute()` harness; `cursor` seeds a `success` run one hour
        ago so that the window is fetched."""
        started_at = None
        if cursor:
            started_at = datetime.now(UTC) - timedelta(hours=1)
            await self.seed_run("success", started_at)
        fetcher = self.fetcher()
        fetcher.config = FetcherRunConfig(
            hard_time_limit_seconds=3600,
            request_delay=request_delay,
            custom_settings={},
        )
        fetcher._periodic_context = True
        return Batch(self, fetcher, await self.world.open_session(), started_at)

    async def run_row(self) -> tuple[SyncBugzillaBugs, uuid.UUID]:
        """A committed `running` FetcherRun, as the atomic acquisition leaves
        it before `run()`."""
        run_id = await self.seed_run("running", datetime.now(UTC))
        return self.fetcher(), run_id

    async def run(self, config: FetcherRunConfig = _RUN_CONFIG) -> FetcherRun:
        """One complete `run()`; returns the finalized FetcherRun."""
        fetcher, run_id = await self.run_row()
        await fetcher.run(run_id=run_id, config=config)
        return await self.run_outcome(run_id)

    async def run_outcome(self, run_id: uuid.UUID) -> FetcherRun:
        async with self.factory() as session:
            run = await session.get(FetcherRun, run_id)
        assert run is not None
        return run

    # -- observation -------------------------------------------------------

    @property
    def page_params(self) -> list[list[tuple[str, str]]]:
        return [request.url.params.multi_items() for request in self.server.requests]

    async def source_status(self, cve: CVE) -> str | None:
        async with self.factory() as session:
            value: str | None = await session.scalar(
                select(CVESource.status).where(
                    CVESource.cve_id == cve.id, CVESource.source == "bugzilla"
                )
            )
        return value

    async def cve_named(self, cve_id: str) -> CVE | None:
        async with self.factory() as session:
            cve: CVE | None = await session.scalar(
                select(CVE).where(CVE.cve_id == cve_id)
            )
        return cve

    async def references(self, cve: CVE) -> list[tuple[str, str | None, str | None]]:
        async with self.factory() as session:
            rows = await session.execute(
                select(TicketReference.url, TicketReference.title, TicketReference.type)
                .join(Ticket, TicketReference.ticket_id == Ticket.id)
                .where(Ticket.cve_id == cve.id)
                .order_by(TicketReference.url)
            )
        return [(url, title, kind) for url, title, kind in rows]

    async def tickets(self, cve: CVE) -> list[Ticket]:
        async with self.factory() as session:
            rows = await session.scalars(select(Ticket).where(Ticket.cve_id == cve.id))
            return list(rows.all())

    async def assert_untouched(self, cve: CVE) -> None:
        """No Bugzilla source status and no reference row."""
        assert await self.source_status(cve) is None
        assert await self.references(cve) == []

    async def committed_rows(self) -> int:
        async with self.factory() as session:
            configs = await session.scalar(
                select(func.count())
                .select_from(FetcherConfig)
                .where(FetcherConfig.fetcher_name == NAME)
            )
            runs = await session.scalar(
                select(func.count())
                .select_from(FetcherRun)
                .where(FetcherRun.fetcher_name == NAME)
            )
        return int(configs or 0) + int(runs or 0)

    async def cleanup(self) -> None:
        try:
            await self.world.cleanup()
        finally:
            names = [NAME, *self.other_names]
            async with self.factory() as session:
                await session.execute(
                    delete(FetcherRun).where(FetcherRun.fetcher_name.in_(names))
                )
                await session.execute(
                    delete(FetcherConfig).where(FetcherConfig.fetcher_name.in_(names))
                )
                await session.commit()
        assert await self.committed_rows() == 0
        assert await _cve_count(self.factory) == self.cve_baseline, "a CVE leaked"


async def _cve_count(factory: async_sessionmaker[AsyncSession]) -> int:
    async with factory() as session:
        return int(await session.scalar(select(func.count()).select_from(CVE)) or 0)


@pytest.fixture
async def env(
    db_session_factory: SessionFactory,
    real_session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[Env]:
    created = Env(
        world=IngestionWorld(db_session_factory, await db_session_factory()),
        factory=real_session_factory,
        server=BugzillaServer(),
        published=Publications(),
        cve_baseline=await _cve_count(real_session_factory),
    )
    # The derived cursor reads every committed run of this name.
    assert await created.committed_rows() == 0

    def status_sessions() -> AsyncSession:
        created.status_opened[0] += 1
        return real_session_factory()

    real_isolated = SyncBugzillaBugs._isolated_status_commit

    async def isolated(
        self: SyncBugzillaBugs, cve_id: str, status_value: CVESourceFetchStatus
    ) -> None:
        created.isolated.append((cve_id, status_value))
        await real_isolated(self, cve_id, status_value)

    async def sleep(delay: float) -> None:
        created.sleeps.append((delay, len(created.server.requests)))

    monkeypatch.setattr(
        base_cve_fetcher_module, "async_session_factory", status_sessions
    )
    monkeypatch.setattr(
        base_fetcher_module, "async_session_factory", real_session_factory
    )
    monkeypatch.setattr(task_publication, "publish_task", created.published)
    monkeypatch.setattr(SyncBugzillaBugs, "_isolated_status_commit", isolated)
    monkeypatch.setattr(sync_module, "asyncio", SimpleNamespace(sleep=sleep))
    try:
        await created.world.ensure_default_setting()
        async with real_session_factory() as session:
            session.add(FetcherConfig(fetcher_name=NAME, enabled=True))
            await session.commit()
        yield created
    finally:
        await created.cleanup()


@dataclass
class Batch:
    """`execute()` invocations on a reusable session with real commits,
    under the automatic periodic context that `run()` establishes."""

    env: Env
    fetcher: SyncBugzillaBugs
    session: AsyncSession
    cursor: datetime | None

    async def execute(self) -> None:
        if self.fetcher._http_client is None:
            self.fetcher._http_client = self.env.server.client()
        try:
            await self.fetcher.execute(self.session)
        finally:
            await self.fetcher._teardown_http_client()


@pytest.fixture
async def batch(env: Env) -> Batch:
    return await env.batch()


@dataclass
class Trace:
    """Per-CVE observation of one `execute()`: the CVE being processed,
    every SQL statement and rollback on the batch session's own connection,
    every `_ingest()` call, and the number of requests made when each CVE
    started, each tagged with the CVE's index."""

    current: list[int] = field(default_factory=lambda: [-1])
    statements: list[tuple[int, str]] = field(default_factory=list)
    rollbacks: list[int] = field(default_factory=list)
    ingested: list[int] = field(default_factory=list)
    processed: list[str] = field(default_factory=list)
    requests_at_start: list[int] = field(default_factory=list)

    def statements_of(self, index: int) -> list[str]:
        return [statement for i, statement in self.statements if i == index]

    @contextmanager
    def recording(self, batch: Batch) -> Iterator[Trace]:
        bind = batch.session.bind
        assert isinstance(bind, AsyncConnection)
        connection = bind.sync_connection
        assert connection is not None

        def record(*args: Any) -> None:
            self.statements.append((self.current[0], args[2]))

        event.listen(connection, "before_cursor_execute", record)
        try:
            yield self
        finally:
            event.remove(connection, "before_cursor_execute", record)


def _trace(monkeypatch: pytest.MonkeyPatch, batch: Batch) -> Trace:
    trace = Trace()
    real_process = batch.fetcher._process_cve
    real_ingest = batch.fetcher._ingest
    real_rollback = batch.session.rollback
    position = [0]

    async def process_cve(
        session: AsyncSession, cve_id: str, bugs: Sequence[BugzillaBug]
    ) -> None:
        trace.current[0] = position[0]
        position[0] += 1
        trace.processed.append(cve_id)
        trace.requests_at_start.append(len(batch.env.server.requests))
        await real_process(session, cve_id, bugs)

    async def ingest(
        session: AsyncSession, cve_id: str, bugs: Sequence[BugzillaBug]
    ) -> CVEFetchResult:
        trace.ingested.append(trace.current[0])
        return await real_ingest(session, cve_id, bugs)

    async def rollback() -> None:
        trace.rollbacks.append(trace.current[0])
        await real_rollback()

    monkeypatch.setattr(batch.fetcher, "_process_cve", process_cve)
    monkeypatch.setattr(batch.fetcher, "_ingest", ingest)
    monkeypatch.setattr(batch.session, "rollback", rollback)
    return trace


def _fail_references_for(
    monkeypatch: pytest.MonkeyPatch, cve_ids: set[str], error: BaseException
) -> None:
    """Make `upsert_references()` raise `error` for `cve_ids` after it has
    written the references in the same transaction."""
    real = reference_service.upsert_references

    async def upsert_references(
        session: AsyncSession, ticket_id: Any, cve_id: str, *args: Any
    ) -> None:
        await real(session, ticket_id, cve_id, *args)
        if cve_id in cve_ids:
            raise error

    monkeypatch.setattr(reference_service, "upsert_references", upsert_references)


async def _run_expecting(env: Env, error: type[BaseException]) -> FetcherRun:
    fetcher, run_id = await env.run_row()
    with pytest.raises(error):
        await fetcher.run(run_id=run_id, config=_RUN_CONFIG)
    return await env.run_outcome(run_id)


def _freeze(monkeypatch: pytest.MonkeyPatch, instant: datetime) -> None:
    """Freeze the `now` captured at `execute()` entry (Algorithm step 1)."""
    monkeypatch.setattr(
        sync_module, "datetime", SimpleNamespace(now=lambda tz: instant)
    )


@pytest.fixture
def frozen_now(monkeypatch: pytest.MonkeyPatch) -> datetime:
    """Freeze `now` at the real instant of fixture setup, so that the runs
    a test dates from it precede the `execute()` entry as in production."""
    now = datetime.now(UTC)
    _freeze(monkeypatch, now)
    return now


# ---------------------------------------------------------------------------
# Derived cursor, first run, and the lookback window (steps 1-3)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCursor:
    async def test_first_run_is_success_without_any_request(self, env: Env) -> None:
        cve = await env.cve()
        env.serve(_bug(cve.cve_id))
        await env.seed_run("failure", datetime.now(UTC) - timedelta(hours=2))
        await env.seed_run("queued", None)

        with capture_logs() as logs:
            run = await env.run()

        assert _outcome(run) == ("success", 0, 0, 0, 0)
        assert run.error_message is None
        assert run.cursor is None
        assert env.server.requests == []
        assert env.sleeps == []
        assert logs == []
        await env.assert_untouched(cve)

    async def test_first_run_execute_returns_after_ending_the_read(
        self, env: Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        batch = await env.batch(cursor=False)
        trace = _trace(monkeypatch, batch)

        with trace.recording(batch):
            await batch.execute()

        assert env.server.requests == []
        assert trace.rollbacks == [-1]
        [statement] = trace.statements_of(-1)
        assert statement.lstrip().startswith("SELECT")
        assert "FROM fetcher_run" in statement
        assert "FOR " not in statement.upper()
        assert counters(batch.fetcher) == Counters(0, 0, 0, 0)

    async def test_first_run_becomes_the_cursor_of_the_second(self, env: Env) -> None:
        first = await env.run()

        second = await env.run()

        assert _outcome(first) == ("success", 0, 0, 0, 0)
        assert first.started_at is not None
        assert _outcome(second) == ("success", 0, 0, 0, 0)
        assert env.page_params == [_page_params(0, _since(first.started_at))]

    async def test_latest_success_or_partial_of_this_fetcher_is_the_cursor(
        self, env: Env
    ) -> None:
        now = datetime.now(UTC)
        other = await env.other_fetcher()
        await env.seed_run("success", now - timedelta(hours=5))
        await env.seed_run("partial", now - timedelta(hours=3))
        await env.seed_run("failure", now - timedelta(hours=2))
        await env.seed_run("queued", None)
        await env.seed_run("running", now - timedelta(hours=1))
        await env.seed_run("success", now - timedelta(minutes=10), fetcher_name=other)
        batch = await env.batch(cursor=False)

        await batch.execute()

        assert env.page_params == [_page_params(0, _since(now - timedelta(hours=3)))]

    async def test_first_request_is_the_documented_query(
        self, env: Env, batch: Batch
    ) -> None:
        assert batch.cursor is not None

        await batch.execute()

        [request] = env.server.requests
        assert request.method == "GET"
        assert str(request.url.copy_with(query=None)) == BUG_URL
        assert request.url.params.multi_items() == _page_params(0, _since(batch.cursor))
        assert "authorization" not in request.headers
        assert "cookie" not in request.headers

    async def test_window_start_is_twelve_hours_before_the_cursor_in_whole_seconds(
        self, env: Env
    ) -> None:
        cursor = datetime(2026, 11, 16, 13, 45, 30, 987654, tzinfo=UTC)
        await env.seed_run("success", cursor)
        batch = await env.batch(cursor=False)

        await batch.execute()

        [params] = env.page_params
        assert dict(params)["last_change_time"] == "2026-11-16T01:45:30Z"

    async def test_read_transaction_ends_before_the_first_request(
        self, env: Env, batch: Batch
    ) -> None:
        in_transaction: list[bool] = []

        def respond(request: httpx.Request) -> httpx.Response:
            in_transaction.append(batch.session.in_transaction())
            return httpx.Response(200, json={"bugs": []}, request=request)

        env.server.page_responses[0] = respond

        await batch.execute()

        assert in_transaction == [False]

    async def test_current_run_is_never_its_own_cursor(self, env: Env) -> None:
        previous = datetime.now(UTC) - timedelta(hours=2)
        await env.seed_run("success", previous)

        run = await env.run()

        assert _outcome(run) == ("success", 0, 0, 0, 0)
        assert env.page_params == [_page_params(0, _since(previous))]

    async def test_failed_run_does_not_advance_the_cursor(self, env: Env) -> None:
        previous = datetime.now(UTC) - timedelta(hours=2)
        await env.seed_run("success", previous)
        env.server.page_responses[0] = status(500)
        failed = await _run_expecting(env, FetcherError)
        assert _outcome(failed) == ("failure", 0, 0, 0, 0)
        env.server.page_responses.clear()
        env.server.requests.clear()

        second = await env.run()
        third = await env.run()

        assert _outcome(second) == ("success", 0, 0, 0, 0)
        assert second.started_at is not None
        assert env.page_params == [
            _page_params(0, _since(previous)),
            _page_params(0, _since(second.started_at)),
        ]
        assert third.cursor is None

    async def test_partial_run_advances_the_cursor(self, env: Env) -> None:
        await env.seed_run("success", datetime.now(UTC) - timedelta(hours=2))
        ok, failing = await env.cve(), await env.cve()
        env.serve(_bug(ok.cve_id), _bug(failing.cve_id))
        failing_ids = {failing.cve_id}
        real = reference_service.upsert_references

        async def upsert_references(
            session: AsyncSession, ticket_id: Any, cve_id: str, *args: Any
        ) -> None:
            if cve_id in failing_ids:
                raise RuntimeError(FAILURE_TEXT)
            await real(session, ticket_id, cve_id, *args)

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(reference_service, "upsert_references", upsert_references)
            partial = await env.run()
        env.server.requests.clear()

        later = await env.run()

        assert _outcome(partial) == ("partial", 1, 0, 0, 1)
        assert partial.started_at is not None
        assert env.page_params[0] == _page_params(0, _since(partial.started_at))
        # The failed CVE is processed again by the later run whose window
        # still contains its bug, and now succeeds.
        assert _outcome(later) == ("success", 2, 0, 0, 0)
        assert await env.source_status(failing) == CVESourceFetchStatus.SUCCESS


@pytest.mark.integration
class TestLookback:
    async def test_bug_changed_before_its_cve_entered_sentinel_is_linked_later(
        self, env: Env
    ) -> None:
        """A run skips the bug of an unknown CVE; a later run whose window
        still contains the bug's change links it (Lookback)."""
        await env.seed_run("success", datetime.now(UTC) - timedelta(hours=1))
        cve_id = env.new_cve_id()
        item = _bug(cve_id, summary="Bug of a late CVE")
        env.serve(item)

        first = await env.run()
        assert await env.cve_named(cve_id) is None
        cve = await env.world.cve_in()
        await env.world.ticket(cve_id=cve.id)
        item["alias"] = [cve.cve_id]
        item["summary"] = "Bug of a late CVE"
        env.serve(item)

        second = await env.run()

        assert _outcome(first) == ("success", 0, 0, 0, 0)
        assert _outcome(second) == ("success", 1, 0, 0, 0)
        assert await env.references(cve) == [
            (bug_reference_url(item["id"]), "Bug of a late CVE", "issue")
        ]

    async def test_redelivery_within_the_lookback_is_one_unchanged_success(
        self, env: Env
    ) -> None:
        await env.seed_run("success", datetime.now(UTC) - timedelta(hours=1))
        cve = await env.cve()
        item = _bug(cve.cve_id, summary="Bug")
        env.serve(item)
        first = await env.run()

        second = await env.run()

        assert _outcome(first) == ("success", 1, 0, 0, 0)
        assert _outcome(second) == ("success", 1, 0, 0, 0)
        assert first.started_at is not None
        # Each run requests its page and the closing empty page.
        assert len(env.page_params) == 4
        assert env.page_params[2] == _page_params(0, _since(first.started_at))
        assert await env.references(cve) == [
            (bug_reference_url(item["id"]), "Bug", "issue")
        ]
        assert first.cursor is None
        assert second.cursor is None


@pytest.mark.integration
class TestStaleCursor:
    @pytest.mark.parametrize(
        "age",
        [STALE_AFTER, timedelta(days=29, hours=23), timedelta(0)],
        ids=["exactly_30_days", "just_under", "now"],
    )
    async def test_window_start_within_30_days_is_fetched(
        self, age: timedelta, env: Env, frozen_now: datetime
    ) -> None:
        window_start = frozen_now - age
        await env.seed_run("success", window_start + LOOKBACK)
        batch = await env.batch(cursor=False)

        with capture_logs() as logs:
            await batch.execute()

        assert env.page_params == [
            _page_params(0, window_start.strftime(WINDOW_FORMAT))
        ]
        assert _events(logs, BUGZILLA_CURSOR_RESET_EVENT) == []

    @pytest.mark.parametrize(
        ("beyond", "age_days"),
        [
            (timedelta(microseconds=1), 30),
            (timedelta(hours=23), 30),
            (timedelta(days=15), 45),
            (timedelta(days=335), 365),
        ],
        ids=["one_microsecond", "hours", "45_days", "one_year"],
    )
    async def test_older_window_start_resets_without_any_request(
        self,
        beyond: timedelta,
        age_days: int,
        env: Env,
        frozen_now: datetime,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        window_start = frozen_now - STALE_AFTER - beyond
        await env.seed_run("success", window_start + LOOKBACK)
        cve = await env.cve()
        env.serve(_bug(cve.cve_id))
        batch = await env.batch(cursor=False)
        trace = _trace(monkeypatch, batch)

        with capture_logs() as logs:
            await batch.execute()

        assert logs == [
            {
                "event": BUGZILLA_CURSOR_RESET_EVENT,
                "log_level": "warning",
                "fetcher_name": NAME,
                "age_days": age_days,
            }
        ]
        assert env.server.requests == []
        assert env.sleeps == []
        assert trace.processed == []
        assert counters(batch.fetcher) == Counters(0, 0, 0, 0)
        await env.assert_untouched(cve)

    async def test_reset_run_is_success_and_becomes_the_cursor(
        self, env: Env, frozen_now: datetime, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await env.seed_run("success", frozen_now - timedelta(days=90))

        with capture_logs(processors=[merge_contextvars]) as logs:
            reset = await env.run()

        assert _outcome(reset) == ("success", 0, 0, 0, 0)
        assert reset.error_message is None
        assert reset.cursor is None
        assert env.server.requests == []
        [event_entry] = _events(logs, BUGZILLA_CURSOR_RESET_EVENT)
        # The window starts 12 hours before the 90-day-old cursor.
        assert event_entry["age_days"] == 90
        assert reset.started_at is not None

        # The reset run's started_at is now the latest success: the next
        # scheduled run, one hour after it, fetches the window from it.
        _freeze(monkeypatch, reset.started_at + timedelta(hours=1))
        second = await env.run()

        assert _outcome(second) == ("success", 0, 0, 0, 0)
        assert env.page_params == [_page_params(0, _since(reset.started_at))]


# ---------------------------------------------------------------------------
# Keyset pagination and the request delay (step 4)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestPagination:
    async def test_pages_follow_the_last_bug_id_until_an_empty_page(
        self, env: Env, batch: Batch
    ) -> None:
        cves = [await env.cve() for _ in range(5)]
        bugs = [_bug(cve.cve_id) for cve in cves]
        env.serve(*bugs)
        env.server.page_cap = 2
        assert batch.cursor is not None

        await batch.execute()

        since = _since(batch.cursor)
        assert env.page_params == [
            _page_params(after_id, since)
            for after_id in (0, bugs[1]["id"], bugs[3]["id"], bugs[4]["id"])
        ]
        assert counters(batch.fetcher) == Counters(5, 0, 0, 0)
        for cve in cves:
            assert await env.source_status(cve) == CVESourceFetchStatus.SUCCESS

    async def test_every_page_is_collected_before_any_cve_transaction(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cves = [await env.cve() for _ in range(3)]
        env.serve(*(_bug(cve.cve_id) for cve in cves))
        env.server.page_cap = 1
        trace = _trace(monkeypatch, batch)

        with trace.recording(batch):
            await batch.execute()

        # Four requests (three pages and the empty one) precede the first CVE.
        assert trace.requests_at_start == [4, 4, 4]
        assert trace.statements_of(0)
        assert trace.processed == sorted(cve.cve_id for cve in cves)

    async def test_a_short_page_does_not_end_the_collection(
        self, env: Env, batch: Batch
    ) -> None:
        """The server may cap a page below `limit`; only an empty page ends
        the collection."""
        cves = [await env.cve() for _ in range(3)]
        bugs = [_bug(cve.cve_id) for cve in cves]
        env.serve(*bugs)
        env.server.page_responses[0] = json_body(envelope(bugs[:1]))

        await batch.execute()

        assert env.server.requested_after_ids == [0, bugs[0]["id"], bugs[2]["id"]]
        assert counters(batch.fetcher) == Counters(3, 0, 0, 0)

    async def test_live_page_is_collected_and_grouped(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        env.serve(*page_bugs())
        trace = _trace(monkeypatch, batch)

        await batch.execute()

        expected = sorted(
            {
                alias
                for item in page_bugs()
                for alias in item["alias"]
                if alias.startswith("CVE-")
            }
        )
        assert trace.processed == expected
        # None of the live CVEs is known to Sentinel: all are excluded.
        assert trace.ingested == []
        assert counters(batch.fetcher) == Counters(0, 0, 0, 0)

    @pytest.mark.parametrize(
        "ids",
        [[1], [0], [5, 4], [5, 5]],
        ids=["equal_to_cursor", "below_cursor", "descending", "duplicate"],
    )
    async def test_non_ascending_later_page_aborts_before_any_cve(
        self, ids: list[int], env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cve = await env.cve()
        env.server.page_responses[0] = json_body(envelope([bug(1, cve.cve_id)]))
        env.server.page_responses[1] = json_body(
            envelope([bug(bug_id, cve.cve_id, summary=FAILURE_TEXT) for bug_id in ids])
        )
        trace = _trace(monkeypatch, batch)

        with capture_logs() as logs, pytest.raises(FetcherError) as raised:
            await batch.execute()

        assert str(raised.value) == UNPARSEABLE_RESPONSE
        assert raised.value.__cause__ is None
        assert raised.value.__suppress_context__
        assert env.server.requested_after_ids == [0, 1]
        assert trace.processed == []
        assert counters(batch.fetcher) == Counters(0, 0, 0, 0)
        assert logs == []
        await env.assert_untouched(cve)


@pytest.mark.integration
class TestRequestDelay:
    async def test_delay_precedes_each_request_after_the_first(
        self, env: Env, batch: Batch
    ) -> None:
        env.serve(*(_bug(env.new_cve_id()) for _ in range(3)))
        env.server.page_cap = 1

        await batch.execute()

        # Not before the first request, not after the closing empty page.
        assert env.sleeps == [(BATCH_DELAY, 1), (BATCH_DELAY, 2), (BATCH_DELAY, 3)]
        assert len(env.server.requests) == 4

    async def test_single_empty_page_is_never_delayed(
        self, env: Env, batch: Batch
    ) -> None:
        await batch.execute()

        assert len(env.server.requests) == 1
        assert env.sleeps == []

    async def test_zero_delay_never_waits(self, env: Env) -> None:
        batch = await env.batch(request_delay=0.0)
        env.serve(*(_bug(env.new_cve_id()) for _ in range(2)))
        env.server.page_cap = 1

        await batch.execute()

        assert len(env.server.requests) == 3
        assert env.sleeps == []

    async def test_missing_configuration_snapshot_uses_the_class_default(
        self, env: Env, batch: Batch
    ) -> None:
        batch.fetcher.config = None
        env.serve(_bug(env.new_cve_id()))

        await batch.execute()

        assert env.sleeps == [(1.0, 1)]
        assert SyncBugzillaBugs.default_request_delay == 1.0

    async def test_run_uses_its_snapshot_delay(self, env: Env) -> None:
        await env.seed_run("success", datetime.now(UTC) - timedelta(hours=1))
        env.serve(_bug(env.new_cve_id()))

        await env.run(
            FetcherRunConfig(
                hard_time_limit_seconds=3600, request_delay=7.5, custom_settings={}
            )
        )

        assert env.sleeps == [(7.5, 1)]


# ---------------------------------------------------------------------------
# Run-level failures (Error Handling, `execute()` run-level table)
# ---------------------------------------------------------------------------


def _http(code: int) -> str:
    return f"SUSE Bugzilla returned HTTP {code}"


def _with_status(code: int) -> Responder:
    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            code,
            json=envelope([bug(1, "CVE-2099-0001", summary=FAILURE_TEXT)]),
            request=request,
        )

    return respond


_PAGE_FAILURES: Final[list[tuple[Responder, str, type[BaseException] | None]]] = [
    (
        status(400, load_raw_fixture(ERROR_400_FIXTURE)),
        _http(400),
        httpx.HTTPStatusError,
    ),
    (status(401, FAILURE_TEXT.encode()), _http(401), httpx.HTTPStatusError),
    (status(403, FAILURE_TEXT.encode()), _http(403), httpx.HTTPStatusError),
    (status(404, FAILURE_TEXT.encode()), _http(404), httpx.HTTPStatusError),
    (status(429, FAILURE_TEXT.encode()), _http(429), httpx.HTTPStatusError),
    (status(500, FAILURE_TEXT.encode()), _http(500), httpx.HTTPStatusError),
    (status(503), _http(503), httpx.HTTPStatusError),
    (
        status(301, headers={"Location": "https://bugzilla.example.invalid/x"}),
        _http(301),
        httpx.HTTPStatusError,
    ),
    (
        status(302, headers={"Location": f"{BUG_URL}?v2=1"}),
        _http(302),
        httpx.HTTPStatusError,
    ),
    (status(204), _http(204), None),
    (_with_status(201), _http(201), None),
    (_with_status(206), _http(206), None),
    (
        raising(httpx.ConnectError("[Errno 111] Connection refused")),
        CONNECTION_FAILED,
        httpx.ConnectError,
    ),
    (
        raising(httpx.ConnectTimeout("timed out")),
        CONNECTION_FAILED,
        httpx.ConnectTimeout,
    ),
    (raising(httpx.ReadTimeout("timed out")), CONNECTION_FAILED, httpx.ReadTimeout),
    (raising(httpx.ProxyError("tunnel refused")), CONNECTION_FAILED, httpx.ProxyError),
    (
        raising(httpx.RemoteProtocolError("peer closed connection")),
        CONNECTION_FAILED,
        httpx.RemoteProtocolError,
    ),
    (undecodable(200), UNPARSEABLE_RESPONSE, httpx.DecodingError),
    (undecodable(503), UNPARSEABLE_RESPONSE, httpx.DecodingError),
    (status(200, b"{"), UNPARSEABLE_RESPONSE, ValueError),
    (status(200, b""), UNPARSEABLE_RESPONSE, ValueError),
    (html(), UNPARSEABLE_RESPONSE, ValueError),
    (
        status(200, f"<html>{FAILURE_TEXT}</html>".encode()),
        UNPARSEABLE_RESPONSE,
        ValueError,
    ),
    (status(200, b'{"bugs": ["\xff\xfe"]}'), UNPARSEABLE_RESPONSE, UnicodeDecodeError),
    # Rejected by the limited parser that every page-failure case runs with.
    (
        status(200, ('{"bugs": [' + NESTED_ARRAY + "]}").encode()),
        UNPARSEABLE_RESPONSE,
        JSONNestingError,
    ),
    (
        status(200, b'{"bugs": [' + OVERSIZED_INTEGER.encode() + b"]}"),
        UNPARSEABLE_RESPONSE,
        ValueError,
    ),
    (json_body([bug(1, "CVE-2099-0001")]), UNPARSEABLE_RESPONSE, None),
    (json_body({"bugs": None}), UNPARSEABLE_RESPONSE, None),
    (json_body({"total": 1}), UNPARSEABLE_RESPONSE, None),
    (json_body({"bugs": [FAILURE_TEXT]}), UNPARSEABLE_RESPONSE, None),
    (
        json_body(
            {"bugs": [{"id": True, "alias": [], "summary": FAILURE_TEXT, "groups": []}]}
        ),
        UNPARSEABLE_RESPONSE,
        None,
    ),
    (
        json_body(
            {"bugs": [{"id": 1, "alias": FAILURE_TEXT, "summary": "x", "groups": []}]}
        ),
        UNPARSEABLE_RESPONSE,
        None,
    ),
    (
        json_body({"bugs": [{"id": 1, "alias": [], "summary": FAILURE_TEXT}]}),
        UNPARSEABLE_RESPONSE,
        None,
    ),
    (
        json_body({"bugs": [bug(0, "CVE-2099-0001", summary=FAILURE_TEXT)]}),
        UNPARSEABLE_RESPONSE,
        None,
    ),
]
_PAGE_FAILURE_IDS: Final = [
    "http_400",
    "http_401",
    "http_403",
    "http_404",
    "http_429",
    "http_500",
    "http_503",
    "http_301",
    "http_302",
    "http_204",
    "http_201",
    "http_206",
    "connection_refused",
    "connect_timeout",
    "read_timeout",
    "proxy_error",
    "protocol_error",
    "undecodable_200",
    "undecodable_503",
    "truncated_json",
    "empty_body",
    "live_html_answer",
    "html",
    "invalid_utf8",
    "nesting_beyond_the_parser_limit",
    "integer_beyond_the_conversion_limit",
    "array_root",
    "null_bugs",
    "missing_bugs",
    "string_element",
    "boolean_id",
    "string_alias",
    "missing_groups",
    "id_at_the_cursor",
]


@pytest.mark.integration
class TestPageFailures:
    @pytest.mark.parametrize(
        ("responder", "message", "cause"), _PAGE_FAILURES, ids=_PAGE_FAILURE_IDS
    )
    async def test_execute_aborts_with_the_sanitized_chained_error(
        self,
        responder: Responder,
        message: str,
        cause: type[BaseException] | None,
        env: Env,
        batch: Batch,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        limit_parser_nesting(monkeypatch)
        env.server.page_responses[0] = responder
        trace = _trace(monkeypatch, batch)

        with capture_logs() as logs, pytest.raises(FetcherError) as raised:
            await batch.execute()

        assert str(raised.value) == message
        if cause is None:
            assert raised.value.__cause__ is None
        else:
            assert isinstance(raised.value.__cause__, cause)
        # One request; a redirect is not followed and no page is retried.
        assert len(env.server.requests) == 1
        assert env.sleeps == []
        assert trace.processed == []
        assert counters(batch.fetcher) == Counters(0, 0, 0, 0)
        assert logs == []

    @pytest.mark.parametrize(
        ("responder", "message", "cause"), _PAGE_FAILURES, ids=_PAGE_FAILURE_IDS
    )
    async def test_run_failure_has_the_exact_message_and_a_content_free_detail(
        self,
        responder: Responder,
        message: str,
        cause: type[BaseException] | None,
        env: Env,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        limit_parser_nesting(monkeypatch)
        await env.seed_run("success", datetime.now(UTC) - timedelta(hours=1))
        env.server.page_responses[0] = responder

        with capture_logs() as logs:
            run = await _run_expecting(env, FetcherError)

        assert _outcome(run) == ("failure", 0, 0, 0, 0)
        assert run.error_message == message
        if cause is None:
            assert run.error_detail is None
        else:
            assert run.error_detail is not None
        assert run.cursor is None
        _assert_content_free(run.error_message, run.error_detail, run.error_traceback)
        _assert_private(logs)
        assert len(env.server.requests) == 1

    async def test_failure_on_a_later_page_processes_no_cve(self, env: Env) -> None:
        await env.seed_run("success", datetime.now(UTC) - timedelta(hours=1))
        first, later = await env.cve(), await env.cve()
        env.serve(_bug(first.cve_id), _bug(later.cve_id))
        env.server.page_cap = 1
        env.server.page_responses[1] = status(503, FAILURE_TEXT.encode())

        run = await _run_expecting(env, FetcherError)

        assert _outcome(run) == ("failure", 0, 0, 0, 0)
        assert run.error_message == _http(503)
        assert len(env.server.requests) == 2
        assert env.sleeps == [(_RUN_CONFIG.request_delay, 1)]
        await env.assert_untouched(first)
        await env.assert_untouched(later)

    @pytest.mark.parametrize("kind", CONFIGURATION_ERRORS)
    async def test_client_creation_error_propagates_before_any_request(
        self,
        kind: ConfigurationError,
        env: Env,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        await env.seed_run("success", datetime.now(UTC) - timedelta(hours=1))
        cve = await env.cve()
        env.serve(_bug(cve.cve_id))
        fetcher, run_id = await env.run_row()
        await fetcher._teardown_http_client()
        broken = break_shared_client(kind, monkeypatch, tmp_path)

        with capture_logs() as logs, pytest.raises(broken.error):
            await fetcher.run(run_id=run_id, config=_RUN_CONFIG)

        run = await env.run_outcome(run_id)
        assert _outcome(run) == ("failure", 0, 0, 0, 0)
        assert run.error_message == "Unexpected error"
        assert run.error_detail is not None
        assert broken.named in run.error_detail
        assert PROXY_SECRET not in f"{run.error_detail}{run.error_traceback}"
        assert env.server.requests == []
        assert env.status_opened == [0]
        assert _events(logs, CVE_FETCH_ITEM_FAILED_EVENT) == []
        await env.assert_untouched(cve)


# ---------------------------------------------------------------------------
# Selection and grouping (steps 5-6.a)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestSelection:
    async def test_cve_not_in_sentinel_is_excluded_silently(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        unknown = env.new_cve_id()
        known = await env.cve()
        env.serve(_bug(unknown, summary=FAILURE_TEXT), _bug(known.cve_id))
        trace = _trace(monkeypatch, batch)

        with capture_logs() as logs, trace.recording(batch):
            await batch.execute()

        assert sorted(trace.processed) == sorted([unknown, known.cve_id])
        unknown_index = trace.processed.index(unknown)
        assert unknown_index not in trace.ingested
        # One lock-free read, then the read transaction ends without a write.
        [read] = trace.statements_of(unknown_index)
        assert read.lstrip().startswith("SELECT")
        assert "FROM cve" in read
        assert "FOR " not in read.upper()
        assert unknown_index in trace.rollbacks
        assert await env.cve_named(unknown) is None
        assert env.isolated == []
        assert logs == []
        assert counters(batch.fetcher) == Counters(1, 0, 0, 0)

    async def test_restricted_bugs_and_non_canonical_aliases_are_excluded(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        restricted, lowercase, valid = await env.cve(), await env.cve(), await env.cve()
        env.serve(
            _bug(restricted.cve_id, groups=["embargoed"]),
            _bug(lowercase.cve_id.lower(), f"{lowercase.cve_id} "),
            _bug(valid.cve_id, "GHSA-fict-0001-aaaa"),
        )
        trace = _trace(monkeypatch, batch)

        with capture_logs() as logs:
            await batch.execute()

        assert trace.processed == [valid.cve_id]
        assert logs == []
        await env.assert_untouched(restricted)
        await env.assert_untouched(lowercase)
        assert await env.source_status(valid) == CVESourceFetchStatus.SUCCESS
        assert counters(batch.fetcher) == Counters(1, 0, 0, 0)

    async def test_one_bug_links_every_cve_it_names(
        self, env: Env, batch: Batch
    ) -> None:
        first, second = await env.cve(), await env.cve()
        item = _bug(second.cve_id, first.cve_id, summary="Shared bug")
        env.serve(item)

        await batch.execute()

        for cve in (first, second):
            assert await env.references(cve) == [
                (bug_reference_url(item["id"]), "Shared bug", "issue")
            ]
        assert counters(batch.fetcher) == Counters(2, 0, 0, 0)

    async def test_two_bugs_of_one_cve_are_linked_in_ascending_bug_id_order(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An alias that moved between bugs while the window was collected
        makes both bugs name the CVE."""
        cve = await env.cve()
        older, newer = _bug(cve.cve_id, summary="Old"), _bug(cve.cve_id, summary="New")
        env.serve(newer, older)
        candidates: list[list[str]] = []
        real = reference_service.upsert_references

        async def upsert_references(
            session: AsyncSession,
            ticket_id: Any,
            cve_id: str,
            source: str,
            source_reference: Any,
            upstream: Sequence[reference_service.AutomaticReferenceInput],
        ) -> None:
            assert source == NAME
            assert source_reference is None
            candidates.append([str(candidate.url) for candidate in upstream])
            await real(session, ticket_id, cve_id, source, source_reference, upstream)

        monkeypatch.setattr(reference_service, "upsert_references", upsert_references)

        await batch.execute()

        assert candidates == [
            [bug_reference_url(older["id"]), bug_reference_url(newer["id"])]
        ]
        assert await env.references(cve) == sorted(
            [
                (bug_reference_url(older["id"]), "Old", "issue"),
                (bug_reference_url(newer["id"]), "New", "issue"),
            ]
        )
        assert counters(batch.fetcher) == Counters(1, 0, 0, 0)

    async def test_cves_are_processed_in_code_point_order(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cves = [await env.cve() for _ in range(3)]
        env.serve(*(_bug(cve.cve_id) for cve in reversed(cves)))
        trace = _trace(monkeypatch, batch)

        await batch.execute()

        assert trace.processed == sorted(cve.cve_id for cve in cves)


# ---------------------------------------------------------------------------
# Per-CVE success (steps 6.b-e; Payload; Bug Reference)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCveSuccess:
    async def test_bug_is_linked_with_an_empty_payload_and_no_effect(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cve = await env.cve()
        item = _bug(cve.cve_id, summary="VUL-0: example-package: fictional title")
        env.serve(item)
        payloads: list[CVEIngestPayload] = []
        real_upsert = cve_service.upsert_cve

        async def upsert_cve(
            session: AsyncSession, cve_id: str, source: Any, payload: CVEIngestPayload
        ) -> Any:
            payloads.append(payload)
            return await real_upsert(session, cve_id, source, payload)

        monkeypatch.setattr(cve_service, "upsert_cve", upsert_cve)

        await batch.execute()

        assert payloads == [CVEIngestPayload()]
        assert await env.references(cve) == [
            (
                bug_reference_url(item["id"]),
                "VUL-0: example-package: fictional title",
                "issue",
            )
        ]
        assert await env.source_status(cve) == CVESourceFetchStatus.SUCCESS
        assert counters(batch.fetcher) == Counters(1, 0, 0, 0)
        assert env.published.calls == []
        assert env.isolated == []

    async def test_orphan_cve_receives_a_ticket_with_the_bugzilla_label(
        self, env: Env, batch: Batch
    ) -> None:
        cve = await env.orphan()
        item = _bug(cve.cve_id, summary="Bug")
        env.serve(item)

        await batch.execute()

        [ticket] = await env.tickets(cve)
        assert ticket.status == "New"
        async with env.factory() as session:
            events = await ticket_events_by_id(session, ticket.id)
        assert events == [
            EventRow("ticket_created", None, None, None, INGESTION_COMMENT, None),
            EventRow("cve_associated", None, None, cve.cve_id, None, None),
        ]
        assert await env.references(cve) == [
            (bug_reference_url(item["id"]), "Bug", "issue")
        ]
        # A Ticket creation is not a CVE effect.
        assert counters(batch.fetcher) == Counters(1, 0, 0, 0)

    async def test_changed_summary_updates_the_title_without_an_effect(
        self, env: Env, batch: Batch
    ) -> None:
        cve = await env.cve()
        item = _bug(cve.cve_id, summary="Before")
        env.serve(item)
        await batch.execute()
        item["summary"] = "After"
        env.serve(item)
        second = await env.batch(cursor=False)

        await second.execute()

        assert await env.references(cve) == [
            (bug_reference_url(item["id"]), "After", "issue")
        ]
        assert counters(second.fetcher) == Counters(1, 0, 0, 0)


# ---------------------------------------------------------------------------
# Per-CVE failures (Batch Error Handling) and the hard finalization boundary
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCveFailure:
    async def test_existence_read_failure_is_an_isolated_failure(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        failing, later = await env.cve(), await env.cve()
        ordered = sorted([failing, later], key=lambda cve: cve.cve_id)
        env.serve(*(_bug(cve.cve_id) for cve in ordered))
        real_exists = batch.fetcher._cve_exists

        async def cve_exists(session: AsyncSession, cve_id: str) -> bool:
            if cve_id == failing.cve_id:
                raise RuntimeError(FAILURE_TEXT)
            return await real_exists(session, cve_id)

        monkeypatch.setattr(batch.fetcher, "_cve_exists", cve_exists)

        with capture_logs() as logs:
            await batch.execute()

        assert _events(logs, CVE_FETCH_ITEM_FAILED_EVENT) == [
            _failed(failing.cve_id, "RuntimeError")
        ]
        _assert_private(logs)
        assert env.isolated == [(failing.cve_id, CVESourceFetchStatus.FAILURE)]
        assert await env.source_status(failing) == CVESourceFetchStatus.FAILURE
        assert await env.source_status(later) == CVESourceFetchStatus.SUCCESS
        assert counters(batch.fetcher) == Counters(1, 0, 0, 1)

    async def test_upsert_failure_rolls_back_and_writes_isolated_failure(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        failing, later = await env.cve(), await env.cve()
        env.serve(_bug(failing.cve_id), _bug(later.cve_id))
        real_upsert = cve_service.upsert_cve

        async def upsert_cve(session: AsyncSession, cve_id: str, *args: Any) -> Any:
            if cve_id == failing.cve_id:
                raise ValueError(FAILURE_TEXT)
            return await real_upsert(session, cve_id, *args)

        monkeypatch.setattr(cve_service, "upsert_cve", upsert_cve)

        with capture_logs() as logs:
            await batch.execute()

        [failed] = _events(logs, CVE_FETCH_ITEM_FAILED_EVENT)
        assert failed == _failed(failing.cve_id, "ValueError")
        assert set(failed) == FAILED_EVENT_KEYS
        assert await env.source_status(failing) == CVESourceFetchStatus.FAILURE
        assert await env.references(failing) == []
        assert await env.source_status(later) == CVESourceFetchStatus.SUCCESS
        assert counters(batch.fetcher) == Counters(1, 0, 0, 1)

    async def test_failure_after_the_references_rolls_back_every_write(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        failing = await env.cve()
        env.serve(_bug(failing.cve_id))
        _fail_references_for(monkeypatch, {failing.cve_id}, RuntimeError(FAILURE_TEXT))

        with capture_logs() as logs:
            await batch.execute()

        # upsert_cve() wrote the success status and the references were
        # written; the rollback discarded both before the isolated failure.
        assert await env.references(failing) == []
        assert await env.source_status(failing) == CVESourceFetchStatus.FAILURE
        assert _events(logs, CVE_FETCH_ITEM_FAILED_EVENT) == [
            _failed(failing.cve_id, "RuntimeError")
        ]
        assert env.status_opened == [1]
        assert counters(batch.fetcher) == Counters(0, 0, 0, 1)
        assert env.published.calls == []

    async def test_orphan_failure_leaves_no_ticket(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        orphan = await env.orphan()
        env.serve(_bug(orphan.cve_id))
        _fail_references_for(monkeypatch, {orphan.cve_id}, RuntimeError(FAILURE_TEXT))

        await batch.execute()

        assert await env.tickets(orphan) == []
        assert await env.source_status(orphan) == CVESourceFetchStatus.FAILURE
        assert counters(batch.fetcher) == Counters(0, 0, 0, 1)

    async def test_own_flush_failure_is_an_isolated_failure(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        first, second = sorted(
            [await env.cve(), await env.cve()], key=lambda cve: cve.cve_id
        )
        env.serve(_bug(first.cve_id), _bug(second.cve_id))
        trace = _trace(monkeypatch, batch)
        traced_ingest = batch.fetcher._ingest
        real_finalize = batch.fetcher.commit_and_dispatch
        real_flush = batch.session.flush
        inside_ingest = [False]
        own_flushes: list[int] = []
        finalized: list[int] = []

        async def ingest(
            session: AsyncSession, cve_id: str, bugs: Sequence[BugzillaBug]
        ) -> CVEFetchResult:
            inside_ingest[0] = True
            try:
                return await traced_ingest(session, cve_id, bugs)
            finally:
                inside_ingest[0] = False

        async def commit_and_dispatch(session: AsyncSession, result: Any) -> None:
            finalized.append(trace.current[0])
            await real_finalize(session, result)

        async def flush(*args: Any, **kwargs: Any) -> None:
            await real_flush(*args, **kwargs)
            # Only the fetcher's own per-CVE flush of the first CVE fails;
            # the delegates' flushes inside _ingest() succeed.
            if not inside_ingest[0]:
                own_flushes.append(trace.current[0])
                if trace.current[0] == 0:
                    raise RuntimeError(FAILURE_TEXT)

        monkeypatch.setattr(batch.fetcher, "_ingest", ingest)
        monkeypatch.setattr(batch.fetcher, "commit_and_dispatch", commit_and_dispatch)
        monkeypatch.setattr(batch.session, "flush", flush)

        with capture_logs() as logs:
            await batch.execute()

        assert own_flushes == [0, 1]
        assert finalized == [1]
        assert _events(logs, CVE_FETCH_ITEM_FAILED_EVENT) == [
            _failed(first.cve_id, "RuntimeError")
        ]
        assert await env.source_status(first) == CVESourceFetchStatus.FAILURE
        assert await env.references(first) == []
        assert await env.source_status(second) == CVESourceFetchStatus.SUCCESS
        assert counters(batch.fetcher) == Counters(1, 0, 0, 1)
        _assert_private(logs)


@pytest.mark.integration
class TestFinalization:
    async def test_flush_precedes_finalization_and_effects_follow_commit(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cve = await env.cve()
        env.serve(_bug(cve.cve_id))
        events: list[str] = []
        pending_at_finalization: list[bool] = []
        tokens: list[Any] = []
        at_commit: list[Counters] = []
        real_ingest = batch.fetcher._ingest
        real_finalize = batch.fetcher.commit_and_dispatch
        real_flush = batch.session.flush
        real_commit = batch.session.commit
        inside_ingest = [False]

        async def ingest(
            session: AsyncSession, cve_id: str, bugs: Sequence[BugzillaBug]
        ) -> CVEFetchResult:
            events.append("ingest")
            inside_ingest[0] = True
            try:
                return await real_ingest(session, cve_id, bugs)
            finally:
                inside_ingest[0] = False

        async def commit_and_dispatch(session: AsyncSession, result: Any) -> None:
            events.append("commit_and_dispatch")
            tokens.append(result)
            pending_at_finalization.append(
                bool(session.new or session.dirty or session.deleted)
            )
            await real_finalize(session, result)

        async def flush(*args: Any, **kwargs: Any) -> None:
            # The delegates' own flushes happen inside _ingest().
            if not inside_ingest[0]:
                events.append("flush")
            await real_flush(*args, **kwargs)

        async def commit() -> None:
            events.append("commit")
            at_commit.append(counters(batch.fetcher))
            await real_commit()

        monkeypatch.setattr(batch.fetcher, "_ingest", ingest)
        monkeypatch.setattr(batch.fetcher, "commit_and_dispatch", commit_and_dispatch)
        monkeypatch.setattr(batch.session, "flush", flush)
        monkeypatch.setattr(batch.session, "commit", commit)

        await batch.execute()

        assert events == ["ingest", "flush", "commit_and_dispatch", "commit"]
        assert pending_at_finalization == [False]
        [token] = tokens
        assert isinstance(token, CVEFetchResult)
        assert token.action is UpsertAction.UNCHANGED
        assert token.post_ingest is None
        assert token._consumed
        # The success is absent until the commit.
        assert at_commit == [Counters(0, 0, 0, 0)]
        assert counters(batch.fetcher) == Counters(1, 0, 0, 0)
        assert env.published.calls == []

    async def test_commit_failure_terminates_without_warning_metric_or_status(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        first, second = sorted(
            [await env.cve(), await env.cve()], key=lambda cve: cve.cve_id
        )
        env.serve(_bug(first.cve_id), _bug(second.cve_id))
        trace = _trace(monkeypatch, batch)
        error = RuntimeError(FAILURE_TEXT)

        async def commit() -> None:
            raise error

        monkeypatch.setattr(batch.session, "commit", commit)

        with capture_logs() as logs, pytest.raises(RuntimeError) as raised:
            await batch.execute()

        assert raised.value is error
        assert trace.ingested == [0]
        assert trace.rollbacks == [-1]
        assert counters(batch.fetcher) == Counters(0, 0, 0, 0)
        assert _events(logs, CVE_FETCH_ITEM_FAILED_EVENT) == []
        await batch.session.rollback()
        await env.assert_untouched(first)
        await env.assert_untouched(second)
        assert env.isolated == []
        assert env.status_opened == [0]

    async def test_ambiguous_commit_terminates_without_metric_or_status(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        first, second = sorted(
            [await env.cve(), await env.cve()], key=lambda cve: cve.cve_id
        )
        env.serve(_bug(first.cve_id), _bug(second.cve_id))
        real_commit = batch.session.commit
        error = ConnectionResetError("commit outcome unknown")

        async def commit() -> None:
            await real_commit()
            raise error

        monkeypatch.setattr(batch.session, "commit", commit)

        with capture_logs() as logs, pytest.raises(ConnectionResetError):
            await batch.execute()

        assert counters(batch.fetcher) == Counters(0, 0, 0, 0)
        assert _events(logs, CVE_FETCH_ITEM_FAILED_EVENT) == []
        # The durable commit is never reclassified as an isolated failure.
        assert await env.source_status(first) == CVESourceFetchStatus.SUCCESS
        await env.assert_untouched(second)
        assert env.isolated == []

    async def test_non_operational_post_commit_error_aborts_and_keeps_success(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        first, second = sorted(
            [await env.cve(), await env.cve()], key=lambda cve: cve.cve_id
        )
        env.serve(_bug(first.cve_id), _bug(second.cve_id))
        error = RuntimeError(FAILURE_TEXT)

        async def drain(session: AsyncSession) -> None:
            raise error

        monkeypatch.setattr(
            ticket_convergence_publication, "drain_ticket_convergence", drain
        )

        with capture_logs() as logs, pytest.raises(RuntimeError) as raised:
            await batch.execute()

        assert raised.value is error
        # The success was recorded after the commit; no failure.
        assert counters(batch.fetcher) == Counters(1, 0, 0, 0)
        assert _events(logs, CVE_FETCH_ITEM_FAILED_EVENT) == []
        assert await env.source_status(first) == CVESourceFetchStatus.SUCCESS
        await env.assert_untouched(second)
        assert env.isolated == []


_SIGNALS: Final = [asyncio.CancelledError, SoftTimeLimitExceeded, MemoryError]


@pytest.mark.integration
class TestWholeRunSignals:
    @pytest.mark.parametrize("stage", ["lookup", "upsert", "references", "flush"])
    @pytest.mark.parametrize("signal_type", _SIGNALS, ids=lambda t: t.__name__)
    async def test_signal_propagates_from_the_cve_boundary(
        self,
        stage: str,
        signal_type: type[BaseException],
        env: Env,
        batch: Batch,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        first, second = sorted(
            [await env.cve(), await env.cve()], key=lambda cve: cve.cve_id
        )
        env.serve(_bug(first.cve_id), _bug(second.cve_id))
        trace = _trace(monkeypatch, batch)
        signal = signal_type()

        async def raise_signal(*args: Any, **kwargs: Any) -> Any:
            raise signal

        if stage == "lookup":
            monkeypatch.setattr(batch.fetcher, "_cve_exists", raise_signal)
        elif stage == "upsert":
            monkeypatch.setattr(cve_service, "upsert_cve", raise_signal)
        elif stage == "references":
            monkeypatch.setattr(reference_service, "upsert_references", raise_signal)
        else:
            real_flush = batch.session.flush
            traced_ingest = batch.fetcher._ingest
            inside_ingest = [False]

            async def ingest(
                session: AsyncSession, cve_id: str, bugs: Sequence[BugzillaBug]
            ) -> CVEFetchResult:
                inside_ingest[0] = True
                try:
                    return await traced_ingest(session, cve_id, bugs)
                finally:
                    inside_ingest[0] = False

            async def flush(*args: Any, **kwargs: Any) -> None:
                await real_flush(*args, **kwargs)
                if not inside_ingest[0]:
                    raise signal

            monkeypatch.setattr(batch.fetcher, "_ingest", ingest)
            monkeypatch.setattr(batch.session, "flush", flush)

        with capture_logs() as logs, pytest.raises(signal_type) as raised:
            await batch.execute()

        assert raised.value is signal
        assert trace.current == [0]
        assert trace.rollbacks == [-1]
        assert counters(batch.fetcher) == Counters(0, 0, 0, 0)
        assert logs == []
        assert env.isolated == []
        await batch.session.rollback()
        await env.assert_untouched(first)
        await env.assert_untouched(second)


# ---------------------------------------------------------------------------
# External String Admissibility (Response Validation)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestExternalStringAdmissibility:
    @pytest.mark.parametrize("character", INADMISSIBLE_CHARACTERS)
    async def test_inadmissible_summary_skips_only_that_candidate(
        self, character: str, env: Env, batch: Batch
    ) -> None:
        cve = await env.cve()
        rejected = _bug(cve.cve_id, summary=f"{FAILURE_TEXT}{character}")
        kept = _bug(cve.cve_id, summary="Kept")
        env.serve(rejected, kept)

        with capture_logs() as logs:
            await batch.execute()

        assert [
            (entry["event"], entry.get("reason"))
            for entry in logs
            if entry["log_level"] == "warning"
        ] == [("automatic_reference_rejected", "invalid_metadata")]
        _assert_private(logs)
        assert await env.references(cve) == [
            (bug_reference_url(kept["id"]), "Kept", "issue")
        ]
        assert await env.source_status(cve) == CVESourceFetchStatus.SUCCESS
        assert counters(batch.fetcher) == Counters(1, 0, 0, 0)

    @pytest.mark.parametrize("character", INADMISSIBLE_CHARACTERS)
    async def test_inadmissible_alias_names_no_cve(
        self, character: str, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cve = await env.cve()
        env.serve(_bug(f"{cve.cve_id}{character}"))
        trace = _trace(monkeypatch, batch)

        with capture_logs() as logs:
            await batch.execute()

        assert trace.processed == []
        assert logs == []
        await env.assert_untouched(cve)
        assert counters(batch.fetcher) == Counters(0, 0, 0, 0)


# ---------------------------------------------------------------------------
# run(): the sync_bugzilla_bugs metric mapping on a finalized FetcherRun
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRunMetrics:
    async def test_window_without_a_known_cve_is_success_with_zero_counters(
        self, env: Env
    ) -> None:
        await env.seed_run("success", datetime.now(UTC) - timedelta(hours=1))
        env.serve(_bug(env.new_cve_id()), _bug(env.new_cve_id(), groups=["x"]))

        run = await env.run()

        assert _outcome(run) == ("success", 0, 0, 0, 0)
        assert run.error_message is None

    async def test_success_counts_each_selected_cve_once_without_effects(
        self, env: Env
    ) -> None:
        await env.seed_run("success", datetime.now(UTC) - timedelta(hours=1))
        first, second, orphan = await env.cve(), await env.cve(), await env.orphan()
        env.serve(
            _bug(first.cve_id, second.cve_id),
            _bug(second.cve_id),
            _bug(orphan.cve_id),
            _bug(env.new_cve_id()),
        )
        env.server.page_cap = 2

        run = await env.run()

        assert _outcome(run) == ("success", 3, 0, 0, 0)
        assert run.error_message is None
        assert run.error_detail is None
        assert run.cursor is None

    async def test_success_plus_failure_is_partial(self, env: Env) -> None:
        await env.seed_run("success", datetime.now(UTC) - timedelta(hours=1))
        ok, failing = await env.cve(), await env.cve()
        env.serve(_bug(ok.cve_id), _bug(failing.cve_id))
        fetcher, run_id = await env.run_row()

        with (
            pytest.MonkeyPatch.context() as patch,
            capture_logs(processors=[merge_contextvars]) as logs,
        ):
            _fail_references_for(patch, {failing.cve_id}, RuntimeError(FAILURE_TEXT))
            await fetcher.run(run_id=run_id, config=_RUN_CONFIG)

        run = await env.run_outcome(run_id)
        assert _outcome(run) == ("partial", 1, 0, 0, 1)
        assert run.error_message is None
        assert run.cursor is None
        # The per-CVE event binds to the run's correlation context.
        assert _events(logs, CVE_FETCH_ITEM_FAILED_EVENT) == [
            {**_failed(failing.cve_id, "RuntimeError"), "fetcher_run_id": str(run_id)}
        ]

    async def test_all_selected_units_failed_is_failure(
        self, env: Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await env.seed_run("success", datetime.now(UTC) - timedelta(hours=1))
        first, second = await env.cve(), await env.cve()
        env.serve(_bug(first.cve_id), _bug(second.cve_id), _bug(env.new_cve_id()))
        _fail_references_for(
            monkeypatch, {first.cve_id, second.cve_id}, RuntimeError(FAILURE_TEXT)
        )

        run = await env.run()

        assert _outcome(run) == ("failure", 0, 0, 0, 2)
        assert run.error_message == "All 2 items failed"
        assert run.error_detail is None
        assert run.cursor is None

    async def test_post_commit_error_fails_the_run_and_keeps_success_metrics(
        self, env: Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await env.seed_run("success", datetime.now(UTC) - timedelta(hours=1))
        cve = await env.cve()
        env.serve(_bug(cve.cve_id))

        async def drain(session: AsyncSession) -> None:
            raise EncodeError(FAILURE_TEXT)

        monkeypatch.setattr(
            ticket_convergence_publication, "drain_ticket_convergence", drain
        )

        run = await _run_expecting(env, EncodeError)

        assert _outcome(run) == ("failure", 1, 0, 0, 0)
        assert run.error_message == "Unexpected error"
        assert await env.source_status(cve) == CVESourceFetchStatus.SUCCESS

    async def test_commit_failure_fails_the_run_without_unit_metrics(
        self, env: Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await env.seed_run("success", datetime.now(UTC) - timedelta(hours=1))
        cve = await env.cve()
        env.serve(_bug(cve.cve_id))
        real_factory = env.factory
        sessions = [0]

        def execution_session() -> AsyncSession:
            session = real_factory()

            async def commit() -> None:
                raise RuntimeError(FAILURE_TEXT)

            monkeypatch.setattr(session, "commit", commit)
            return session

        def factory() -> AsyncSession:
            # Settings/cursor load, then the execution session, then
            # finalization: only the execution session fails to commit.
            sessions[0] += 1
            return execution_session() if sessions[0] == 2 else real_factory()

        monkeypatch.setattr(base_fetcher_module, "async_session_factory", factory)

        run = await _run_expecting(env, RuntimeError)

        assert _outcome(run) == ("failure", 0, 0, 0, 0)
        assert run.error_message == "Unexpected error"
        await env.assert_untouched(cve)
        assert env.isolated == []


# ---------------------------------------------------------------------------
# Privacy across a run (Security and Privacy)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestPrivacy:
    async def test_logs_and_run_fields_carry_no_summary_alias_or_body(
        self, env: Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await env.seed_run("success", datetime.now(UTC) - timedelta(hours=1))
        ok, failing = sorted(
            [await env.cve(), await env.cve()], key=lambda cve: cve.cve_id
        )
        env.serve(
            _bug(ok.cve_id, "GHSA-fict-0001-aaaa", summary=FAILURE_TEXT),
            _bug(ok.cve_id, summary=f"{FAILURE_TEXT}\x00"),
            _bug(failing.cve_id, summary=FAILURE_TEXT),
            _bug(f"cve-{FAILURE_TEXT}", summary=FAILURE_TEXT),
            _bug(env.new_cve_id(), summary=FAILURE_TEXT, groups=[FAILURE_TEXT]),
        )
        _fail_references_for(monkeypatch, {failing.cve_id}, RuntimeError(FAILURE_TEXT))
        fetcher, run_id = await env.run_row()

        with capture_logs(processors=[merge_contextvars]) as logs:
            await fetcher.run(run_id=run_id, config=_RUN_CONFIG)

        run = await env.run_outcome(run_id)
        assert _outcome(run) == ("partial", 1, 0, 0, 1)
        assert {entry["event"] for entry in logs} >= {
            CVE_FETCH_ITEM_FAILED_EVENT,
            "automatic_reference_rejected",
        }
        _assert_private(logs, "GHSA-fict-0001-aaaa", "embargoed")
        _assert_content_free(run.error_message, run.error_detail, run.error_traceback)
        for request in env.server.requests:
            assert ok.cve_id not in str(request.url)
            assert "authorization" not in request.headers
