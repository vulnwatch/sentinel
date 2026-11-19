"""Tests for the `sync_smelt_packages` fetcher.

Contract under test: docs/features/packages/maintained-package-names.md
(Fetcher: `sync_smelt_packages`, properties, Algorithm step 6, Error
Handling, and Metrics; Snapshot; Test Requirements, Fetcher),
docs/features/platform/fetcher-infrastructure.md (BaseFetcher Base Class:
execution-session transaction contract, Finalization, Outcome and effect
accounting; Error Message Sanitization; Naming Convention; Registry), and
docs/features/platform/testing-strategy.md (Fetcher Outcome and Effect
Accounting).

The page validation of the sweep is covered by `test_smelt_maintained_sweep.py`;
here every failure kind is exercised once through `execute()` to prove that
it publishes nothing. Publication tests call `execute(db_session)`: its
commit releases a savepoint of the per-test outer transaction, so every row
is rolled back at teardown. The `run()` lifecycle tests commit through
`real_session_factory` and delete every row they create. SMELT is the fake
server of `tests/support/smelt.py`, injected as the fetcher's HTTP client.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, Final

import httpx
import pytest
from sqlalchemy import delete, event, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from structlog.testing import capture_logs

import app.services.base_fetcher as base_fetcher_module
import app.services.fetcher_discovery  # noqa: F401
from app.config import settings
from app.models.fetcher_config import FetcherConfig
from app.models.fetcher_run import FetcherRun
from app.models.maintained_package import MaintainedPackage
from app.services.base_fetcher import (
    FETCHER_REGISTRY,
    FetcherError,
    FetcherRunConfig,
    get_catch_up_fetchers,
)
from app.services.fetcher_bootstrap import bootstrap_fetcher_configs
from app.services.packages import maintained_package_names, smelt_maintained_sweep
from app.services.packages.sync_smelt_packages import SyncSmeltPackages
from tests.support.smelt import (
    SMELT_TEST_API_URL,
    SmeltServer,
    sweep_page,
    sweep_pages,
)

PUBLICATION_FAILED: Final = "Failed to publish SMELT maintained package names"
INVALID_RESPONSE: Final = "SMELT returned invalid maintained package response"
VALIDATION_FAILED: Final = "SMELT maintained package validation failed"

Metrics = tuple[int, int, int, int]
"""`(succeeded, created, updated, failed)` of one fetcher run."""


@pytest.fixture(autouse=True)
def _fictional_origin(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "smelt_api_url", SMELT_TEST_API_URL)


def _metrics(fetcher: SyncSmeltPackages) -> Metrics:
    return (fetcher._succeeded, fetcher._created, fetcher._updated, fetcher._failed)


def _fetcher(server: SmeltServer) -> SyncSmeltPackages:
    fetcher = SyncSmeltPackages()
    fetcher._http_client = server.client()
    return fetcher


async def _execute(db: AsyncSession, server: SmeltServer) -> SyncSmeltPackages:
    fetcher = _fetcher(server)
    try:
        await fetcher.execute(db)
    finally:
        await fetcher._teardown_http_client()
    return fetcher


async def _execute_failing(
    db: AsyncSession, server: SmeltServer
) -> tuple[FetcherError, SyncSmeltPackages]:
    fetcher = _fetcher(server)
    try:
        with pytest.raises(FetcherError) as raised:
            await fetcher.execute(db)
    finally:
        await fetcher._teardown_http_client()
    return raised.value, fetcher


async def _sync(db: AsyncSession, packages: list[str]) -> Metrics:
    return _metrics(await _execute(db, SmeltServer(sweep_pages(packages))))


async def _table(db: AsyncSession) -> set[str]:
    return set((await db.scalars(select(MaintainedPackage.name))).all())


@pytest.mark.integration
class TestPublication:
    async def test_first_run_publishes_every_distinct_name(
        self, db_session: AsyncSession
    ) -> None:
        packages = ["fictional-a"] * 150 + ["fictional-b"] * 100 + ["Fictional-C"]

        assert await _sync(db_session, packages) == (3, 3, 0, 0)
        assert await _table(db_session) == {"fictional-a", "fictional-b", "Fictional-C"}

    async def test_names_created_removed_and_unchanged(
        self, db_session: AsyncSession
    ) -> None:
        await _sync(db_session, ["fictional-kept", "fictional-left"])

        metrics = await _sync(db_session, ["fictional-kept", "fictional-new"])

        # Selected: the union of both snapshots; a removal is an update.
        assert metrics == (3, 1, 1, 0)
        assert await _table(db_session) == {"fictional-kept", "fictional-new"}

    async def test_unchanged_snapshot_records_no_effect(
        self, db_session: AsyncSession
    ) -> None:
        await _sync(db_session, ["fictional-a", "fictional-b"])

        assert await _sync(db_session, ["fictional-b", "fictional-a"]) == (2, 0, 0, 0)

    async def test_snapshot_whose_name_count_decreased_is_published(
        self, db_session: AsyncSession
    ) -> None:
        await _sync(db_session, [f"fictional-{index}" for index in range(10)])

        assert await _sync(db_session, ["fictional-0"]) == (10, 0, 9, 0)
        assert await _table(db_session) == {"fictional-0"}

    async def test_configured_request_delay_is_applied_between_pages(
        self, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sleeps: list[float] = []

        async def sleep(delay: float) -> None:
            sleeps.append(delay)

        monkeypatch.setattr(
            smelt_maintained_sweep, "asyncio", SimpleNamespace(sleep=sleep)
        )
        fetcher = _fetcher(
            SmeltServer(sweep_pages([f"fictional-{i}" for i in range(450)]))
        )
        fetcher.config = FetcherRunConfig(
            hard_time_limit_seconds=3600, request_delay=0.25, custom_settings={}
        )
        try:
            await fetcher.execute(db_session)
        finally:
            await fetcher._teardown_http_client()

        assert sleeps == [0.25, 0.25]

    async def test_every_request_completes_before_any_database_statement(
        self, db_session: AsyncSession
    ) -> None:
        events: list[tuple[str, str]] = []
        engine = db_session.get_bind().engine

        def record(*args: Any) -> None:
            events.append(("sql", args[2]))

        event.listen(engine, "before_cursor_execute", record)
        try:
            await _execute(
                db_session,
                SmeltServer(
                    sweep_pages([f"fictional-{i}" for i in range(450)]), events=events
                ),
            )
        finally:
            event.remove(engine, "before_cursor_execute", record)

        kinds = [kind for kind, _ in events]
        assert kinds.count("http") == 3
        assert "sql" in kinds
        assert kinds == sorted(kinds)  # every "http" precedes every "sql"


def _failing_server(kind: str) -> SmeltServer:
    server = SmeltServer(sweep_pages([f"fictional-new-{i}" for i in range(450)]))
    if kind == "connection":
        server.responses[2] = _raise(httpx.ConnectError)
    elif kind == "timeout":
        server.responses[2] = _raise(httpx.ReadTimeout)
    elif kind == "http-status":
        server.responses[3] = lambda request: httpx.Response(503)
    elif kind == "invalid-page":
        server.pages[2]["data"]["page"] = 7
    elif kind == "invalid-result":
        server.pages[3]["data"]["results"][0]["package"] = ""
    elif kind == "empty-sweep":
        server.pages = {1: sweep_page(1, [], has_next=False)}
    return server


def _raise(error: type[httpx.TransportError]) -> Callable[[httpx.Request], Any]:
    def respond(request: httpx.Request) -> httpx.Response:
        raise error("example failure to smelt.example.test", request=request)

    return respond


_FAILURES = [
    ("connection", "Failed to connect to SMELT"),
    ("timeout", "SMELT request timed out"),
    ("http-status", "SMELT returned HTTP 503"),
    ("invalid-page", INVALID_RESPONSE),
    ("invalid-result", VALIDATION_FAILED),
    ("empty-sweep", VALIDATION_FAILED),
]


@pytest.mark.integration
class TestFailures:
    @pytest.mark.parametrize(
        ("kind", "message"), _FAILURES, ids=[kind for kind, _ in _FAILURES]
    )
    async def test_failure_publishes_nothing_and_keeps_the_previous_snapshot(
        self, db_session: AsyncSession, kind: str, message: str
    ) -> None:
        await _sync(db_session, ["fictional-old"])

        error, fetcher = await _execute_failing(db_session, _failing_server(kind))

        assert str(error) == message
        assert "smelt.example.test" not in str(error)
        assert _metrics(fetcher) == (0, 0, 0, 0)
        assert await _table(db_session) == {"fictional-old"}

    async def test_publication_database_failure_keeps_the_previous_snapshot(
        self, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await _sync(db_session, ["fictional-old"])
        failure = OperationalError("COMMIT", {}, Exception("connection lost"))

        async def failing_commit() -> None:
            raise failure

        monkeypatch.setattr(db_session, "commit", failing_commit)

        with capture_logs() as logs:
            error, fetcher = await _execute_failing(
                db_session, SmeltServer(sweep_pages(["fictional-new"]))
            )
        await db_session.rollback()

        assert str(error) == PUBLICATION_FAILED
        assert error.__cause__ is failure
        assert _metrics(fetcher) == (0, 0, 0, 0)
        assert await _table(db_session) == {"fictional-old"}
        assert logs == [
            {
                "event": "smelt_maintained_packages_publication_failed",
                "log_level": "warning",
            }
        ]

    async def test_publication_failure_before_commit_publishes_nothing(
        self, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await _sync(db_session, ["fictional-old"])
        failure = OperationalError("INSERT", {}, Exception("connection lost"))
        original = db_session.execute
        calls = [0]

        async def failing_execute(*args: Any, **kwargs: Any) -> Any:
            calls[0] += 1
            if calls[0] == 3:  # the lock, the DELETE, then the INSERT
                raise failure
            return await original(*args, **kwargs)

        monkeypatch.setattr(db_session, "execute", failing_execute)

        error, _ = await _execute_failing(
            db_session, SmeltServer(sweep_pages(["fictional-new"]))
        )
        monkeypatch.setattr(db_session, "execute", original)
        await db_session.rollback()

        assert str(error) == PUBLICATION_FAILED
        assert error.__cause__ is failure
        assert await _table(db_session) == {"fictional-old"}


# ---------------------------------------------------------------------------
# run() lifecycle (committed)
# ---------------------------------------------------------------------------

RunSetup = Callable[[SmeltServer], Awaitable[uuid.UUID]]


@pytest.fixture
async def committed_run(
    real_session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[RunSetup]:
    """Commit a `running` FetcherRun and route `run()` to the test database.

    Every committed row (FetcherConfig, FetcherRun, and the published
    names) is deleted at teardown; the table starts empty.
    """
    monkeypatch.setattr(
        base_fetcher_module, "async_session_factory", real_session_factory
    )
    fetcher_name = f"test_smelt_packages_run_{uuid.uuid4().hex[:12]}"
    async with real_session_factory() as session:
        assert await _table(session) == set()

    async def setup(server: SmeltServer) -> uuid.UUID:
        monkeypatch.setattr(
            base_fetcher_module,
            "create_http_client",
            lambda name, **options: server.client(),
        )
        async with real_session_factory() as session:
            session.add(
                FetcherConfig(
                    fetcher_name=fetcher_name,
                    enabled=True,
                    run_timeout=3600,
                    request_delay=0,
                    custom_settings={},
                )
            )
            run = FetcherRun(
                fetcher_name=fetcher_name,
                started_at=datetime.now(UTC),
                status="running",
                triggered_by="schedule",
            )
            session.add(run)
            await session.commit()
            return run.id

    try:
        yield setup
    finally:
        async with real_session_factory() as session:
            await session.execute(delete(MaintainedPackage))
            await session.execute(
                delete(FetcherRun).where(FetcherRun.fetcher_name == fetcher_name)
            )
            await session.execute(
                delete(FetcherConfig).where(FetcherConfig.fetcher_name == fetcher_name)
            )
            await session.commit()


def _run_config() -> FetcherRunConfig:
    return FetcherRunConfig(
        hard_time_limit_seconds=3600, request_delay=0, custom_settings={}
    )


async def _finalized(
    real_session_factory: async_sessionmaker[AsyncSession], run_id: uuid.UUID
) -> FetcherRun:
    async with real_session_factory() as session:
        run = await session.get(FetcherRun, run_id)
        assert run is not None
        return run


@pytest.mark.integration
class TestRunLifecycle:
    async def test_successful_run_is_finalized_with_exact_counters(
        self,
        committed_run: RunSetup,
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        run_id = await committed_run(
            SmeltServer(sweep_pages(["fictional-a", "fictional-a", "fictional-b"]))
        )

        await SyncSmeltPackages().run(run_id=run_id, config=_run_config())

        run = await _finalized(real_session_factory, run_id)
        assert run.status == "success"
        assert (
            run.items_succeeded,
            run.items_created,
            run.items_updated,
            run.items_failed,
        ) == (2, 2, 0, 0)
        assert (run.error_message, run.error_detail, run.error_traceback) == (
            None,
            None,
            None,
        )
        async with real_session_factory() as session:
            assert await _table(session) == {"fictional-a", "fictional-b"}

    async def test_failed_run_is_finalized_with_the_sanitized_message(
        self,
        committed_run: RunSetup,
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        server = SmeltServer(sweep_pages([f"fictional-{i}" for i in range(450)]))
        server.responses[2] = lambda request: httpx.Response(503)
        run_id = await committed_run(server)

        with pytest.raises(FetcherError, match=r"^SMELT returned HTTP 503$"):
            await SyncSmeltPackages().run(run_id=run_id, config=_run_config())

        run = await _finalized(real_session_factory, run_id)
        assert run.status == "failure"
        assert run.error_message == "SMELT returned HTTP 503"
        assert (
            run.items_succeeded,
            run.items_created,
            run.items_updated,
            run.items_failed,
        ) == (0, 0, 0, 0)
        async with real_session_factory() as session:
            assert await _table(session) == set()


# ---------------------------------------------------------------------------
# Registration and properties
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRegistration:
    def test_discovery_registers_the_fetcher(self) -> None:
        assert FETCHER_REGISTRY["sync_smelt_packages"] is SyncSmeltPackages

    def test_properties_match_the_specification(self) -> None:
        assert SyncSmeltPackages.name == "sync_smelt_packages"
        assert SyncSmeltPackages.description == (
            "Synchronize the names of the source packages that SMELT maintains"
        )
        assert SyncSmeltPackages.default_schedule == "0 0 * * *"
        assert SyncSmeltPackages.default_request_delay == 0
        assert SyncSmeltPackages.participates_in_catch_up is False
        assert SyncSmeltPackages.Settings is None
        assert SyncSmeltPackages.queue is None

    def test_class_name_is_derived_from_the_fetcher_name(self) -> None:
        derived = "".join(
            part.capitalize() for part in SyncSmeltPackages.name.split("_")
        )

        assert derived == SyncSmeltPackages.__name__ == "SyncSmeltPackages"

    def test_fetcher_does_not_participate_in_catch_up(self) -> None:
        assert "sync_smelt_packages" not in get_catch_up_fetchers()

    def test_snapshot_bound_is_the_name_column_length(self) -> None:
        assert maintained_package_names.NAME_MAX_LENGTH == 255


@pytest.mark.integration
class TestBootstrap:
    async def test_bootstrap_creates_the_fetcher_config(
        self, db_session: AsyncSession
    ) -> None:
        assert await db_session.get(FetcherConfig, "sync_smelt_packages") is None

        await bootstrap_fetcher_configs(db_session)

        config = await db_session.get(FetcherConfig, "sync_smelt_packages")
        assert config is not None
        assert config.enabled is True
        assert config.schedule_override is None
        assert config.request_delay == 0
        assert config.run_timeout == 3600
        assert config.custom_settings == {}
