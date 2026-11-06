"""Regression tests: a fetcher run that reaches the Celery soft time limit
is finalized, wherever the signal lands.

See `docs/features/platform/fetcher-infrastructure.md` (`run()` lifecycle,
Soft time limit delivery; Finalization; Exception Propagation) for the
contract under test.

Billiard's prefork child raises `SoftTimeLimitExceeded` from its `SIGUSR1`
handler at whatever bytecode the main thread runs. An asyncio fetcher waits
in the event loop's selector most of the time: there the exception escaped
the event loop, `asyncio.run()` cancelled the task, and `BaseFetcher.run()`
skipped finalization, leaving the `FetcherRun` `running` until stale run
detection. In a loop callback the event loop logged and dropped it, so the
run continued until the hard limit. Each test invokes the real synchronous
`run_fetcher` wrapper with an equivalent `SIGUSR1` handler installed
(`tests/support/soft_time_limit.py`) and sends a real `SIGUSR1`.

Tier 2 (integration): the wrapper's own `asyncio.run()` event loop needs a
dedicated pooled engine against the shared test PostgreSQL server, as in
`test_cross_loop_engine_lifecycle.py`. The tests are synchronous because the
code under test calls `asyncio.run()` (testing-strategy.md, Sync
Entry-Point Tests).
"""

from __future__ import annotations

import asyncio
import signal
import threading
import time
from collections.abc import Awaitable, Callable, Iterator
from dataclasses import dataclass
from typing import Final

import pytest
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

import app.services.base_fetcher as base_fetcher_module
from app.core.enums import FetcherRunStatus
from app.models.fetcher_config import FetcherConfig
from app.models.fetcher_run import FetcherRun
from app.services.base_fetcher import BaseFetcher
from app.tasks import fetchers as fetchers_module
from tests.support.soft_time_limit import (
    SelectorSignal,
    prefork_soft_timeout_handler,
    raise_soft_time_limit,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.usefixtures("isolated_fetcher_registries"),
]

_FETCHER_NAME: Final = "test_soft_time_limit_probe_fetcher"
_HARD_TIME_LIMIT_SECONDS: Final = 3600
_BLOCK_SECONDS: Final = 60
"""How long each await would block if the soft time limit did not stop it."""

_TIMEOUT_MESSAGE: Final = (
    "Execution reached the soft time limit (hard limit for this run: "
    f"{_HARD_TIME_LIMIT_SECONDS}s; 3 items processed). Review "
    f"FetcherConfig.run_timeout for future runs of fetcher '{_FETCHER_NAME}'."
)

Body = Callable[[AsyncSession, SelectorSignal], Awaitable[None]]


class _FakeRequest:
    timelimit = (_HARD_TIME_LIMIT_SECONDS, _HARD_TIME_LIMIT_SECONDS * 0.95)


class _FakeTask:
    """Stand-in for the bound Celery Task: `_run_fetcher_sync` reads only
    `request.timelimit`."""

    request = _FakeRequest()


@dataclass(frozen=True)
class _Harness:
    engine: AsyncEngine
    factory: async_sessionmaker[AsyncSession]

    def runs(self) -> list[FetcherRun]:
        """The probe fetcher's runs, read on an event loop of their own."""

        async def _read() -> list[FetcherRun]:
            async with self.factory() as session:
                rows = await session.scalars(
                    select(FetcherRun).where(FetcherRun.fetcher_name == _FETCHER_NAME)
                )
                runs = list(rows.all())
            await self.engine.dispose()
            return runs

        return asyncio.run(_read())


@pytest.fixture
def harness(
    _engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[_Harness]:
    """Seed the probe fetcher's `FetcherConfig` and point the wrapper and
    `BaseFetcher.run()` at a dedicated pooled engine; delete the committed
    rows afterwards."""
    engine = create_async_engine(
        _engine.url.render_as_string(hide_password=False), echo=False
    )
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def _seed() -> None:
        async with factory() as session:
            session.add(FetcherConfig(fetcher_name=_FETCHER_NAME))
            await session.commit()
        await engine.dispose()

    async def _cleanup() -> None:
        async with factory() as session:
            await session.execute(
                delete(FetcherRun).where(FetcherRun.fetcher_name == _FETCHER_NAME)
            )
            await session.execute(
                delete(FetcherConfig).where(FetcherConfig.fetcher_name == _FETCHER_NAME)
            )
            await session.commit()
        await engine.dispose()

    monkeypatch.setattr(fetchers_module, "engine", engine)
    monkeypatch.setattr(fetchers_module, "async_session_factory", factory)
    monkeypatch.setattr(base_fetcher_module, "async_session_factory", factory)
    asyncio.run(_seed())
    try:
        yield _Harness(engine, factory)
    finally:
        asyncio.run(_cleanup())


def _register(body: Body, selector_signal: SelectorSignal) -> None:
    class _ProbeFetcher(BaseFetcher):
        name = _FETCHER_NAME
        description = "Soft time limit regression probe"
        default_schedule = "0 * * * *"

        async def execute(self, session: AsyncSession) -> None:
            self.record_succeeded(2)
            self.record_failed(1)
            self.record_created(1)
            await body(session, selector_signal)


def _run_fetcher() -> None:
    fetchers_module._run_fetcher_sync(_FakeTask(), _FETCHER_NAME)


async def _await_timer_in_selector(
    session: AsyncSession, selector_signal: SelectorSignal
) -> None:
    selector_signal.start()
    await asyncio.sleep(_BLOCK_SECONDS)


async def _raise_in_loop_callback(
    session: AsyncSession, selector_signal: SelectorSignal
) -> None:
    asyncio.get_running_loop().call_soon(signal.raise_signal, signal.SIGUSR1)
    await asyncio.sleep(_BLOCK_SECONDS)


async def _raise_in_fetcher_code(
    session: AsyncSession, selector_signal: SelectorSignal
) -> None:
    signal.raise_signal(signal.SIGUSR1)
    await asyncio.sleep(_BLOCK_SECONDS)


async def _await_database_query_in_selector(
    session: AsyncSession, selector_signal: SelectorSignal
) -> None:
    # Check out the connection first, so the signal interrupts the query.
    await session.execute(text("SELECT 1"))
    selector_signal.start()
    await session.execute(
        text("SELECT pg_sleep(:seconds)"), {"seconds": _BLOCK_SECONDS}
    )


@pytest.mark.parametrize(
    ("body", "in_selector"),
    [
        pytest.param(_await_timer_in_selector, True, id="selector-awaiting-a-timer"),
        pytest.param(_raise_in_loop_callback, False, id="event-loop-callback"),
        pytest.param(_raise_in_fetcher_code, False, id="fetcher-code"),
        pytest.param(
            _await_database_query_in_selector, True, id="selector-awaiting-a-query"
        ),
    ],
)
def test_soft_time_limit_finalizes_the_run_as_failure(
    harness: _Harness, body: Body, in_selector: bool
) -> None:
    """Wherever `SIGUSR1` lands, the run is finalized as `failure` with the
    enriched timeout message and the counters recorded so far, the task
    raises `SoftTimeLimitExceeded`, the await is stopped instead of
    completing, and the prefork handler is back in place afterwards."""
    selector_signal = SelectorSignal()
    _register(body, selector_signal)

    with prefork_soft_timeout_handler():
        started = time.monotonic()
        with pytest.raises(SoftTimeLimitExceeded):
            _run_fetcher()
        elapsed = time.monotonic() - started
        handler_after_run = signal.getsignal(signal.SIGUSR1)
    selector_signal.join()

    assert selector_signal.sent_in_selector is in_selector
    assert handler_after_run is raise_soft_time_limit
    assert elapsed < _BLOCK_SECONDS / 2
    [run] = harness.runs()
    assert run.status == FetcherRunStatus.FAILURE.value
    assert run.finished_at is not None
    assert run.error_message == _TIMEOUT_MESSAGE
    assert run.error_detail == "SoftTimeLimitExceeded()"
    assert (run.items_succeeded, run.items_failed, run.items_created) == (2, 1, 1)
    assert run.items_updated == 0


def test_system_exit_after_the_soft_time_limit_propagates_unchanged(
    harness: _Harness,
) -> None:
    """A `SystemExit`, as a cold worker shutdown raises in the pool child,
    is not converted: it propagates and the run is not finalized."""

    async def _exit_on_cancellation(
        session: AsyncSession, selector_signal: SelectorSignal
    ) -> None:
        signal.raise_signal(signal.SIGUSR1)
        try:
            await asyncio.sleep(_BLOCK_SECONDS)
        except asyncio.CancelledError:
            raise SystemExit(1) from None

    _register(_exit_on_cancellation, SelectorSignal())

    with prefork_soft_timeout_handler():
        with pytest.raises(SystemExit):
            _run_fetcher()
        handler_after_run = signal.getsignal(signal.SIGUSR1)

    assert handler_after_run is raise_soft_time_limit
    [run] = harness.runs()
    assert run.status == FetcherRunStatus.RUNNING.value
    assert run.finished_at is None


def test_run_outside_the_main_thread_keeps_the_signal_handler(
    harness: _Harness,
) -> None:
    """Outside the main thread no handler can be installed: `run()` leaves
    the main thread's handler in place and finalizes the run from its own
    counters (`partial`)."""
    observed: list[object] = []
    errors: list[BaseException] = []

    async def _observe_handler(
        session: AsyncSession, selector_signal: SelectorSignal
    ) -> None:
        observed.append(signal.getsignal(signal.SIGUSR1))

    def _run_in_thread() -> None:
        try:
            _run_fetcher()
        except BaseException as exc:
            errors.append(exc)

    _register(_observe_handler, SelectorSignal())

    with prefork_soft_timeout_handler():
        thread = threading.Thread(target=_run_in_thread)
        thread.start()
        thread.join(timeout=_BLOCK_SECONDS)

    assert not thread.is_alive()
    assert errors == []
    assert observed == [raise_soft_time_limit]
    [run] = harness.runs()
    assert run.status == FetcherRunStatus.PARTIAL.value
