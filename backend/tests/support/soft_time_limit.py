"""Deliver a real Celery soft time limit signal to code under test.

Billiard's prefork pool child installs a `SIGUSR1` handler that raises
`SoftTimeLimitExceeded` (`billiard.pool.soft_timeout_sighandler`), and the
pool sends `SIGUSR1` to the child when a task reaches its soft time limit.
`prefork_soft_timeout_handler()` installs an equivalent handler for the
duration of a test, so a real signal reaches the code under test as it does
in a worker child. `SelectorSignal` sends that signal while the main thread
is blocked in the event loop's selector, where an asyncio fetcher spends
most of its time. See docs/features/platform/fetcher-infrastructure.md
(`run()` lifecycle, Soft time limit delivery).

Signal handlers run only in the main thread, so callers must run there.
"""

from __future__ import annotations

import contextlib
import selectors
import signal
import sys
import threading
import time
from collections.abc import Iterator
from types import FrameType
from typing import Final, NoReturn

from celery.exceptions import SoftTimeLimitExceeded

_SELECTOR_WAIT_TIMEOUT_SECONDS: Final = 10.0
_POLL_INTERVAL_SECONDS: Final = 0.005


def raise_soft_time_limit(signum: int, frame: FrameType | None) -> NoReturn:
    """The handler billiard installs for `SIGUSR1` in a prefork child."""
    raise SoftTimeLimitExceeded()


@contextlib.contextmanager
def prefork_soft_timeout_handler() -> Iterator[None]:
    """Install `raise_soft_time_limit` for `SIGUSR1`, restoring the
    previous handler on exit."""
    previous = signal.signal(signal.SIGUSR1, raise_soft_time_limit)
    try:
        yield
    finally:
        signal.signal(signal.SIGUSR1, previous)


def _waits_in_selector(frame: FrameType | None) -> bool:
    return (
        frame is not None
        and frame.f_code.co_name == "select"
        and frame.f_code.co_filename == selectors.__file__
    )


class SelectorSignal:
    """Send `SIGUSR1` to the main thread once it waits in the selector.

    `start()` launches a helper thread that polls the main thread's
    innermost frame and signals it as soon as that frame is the selector's
    `select()`, so the signal interrupts the blocked selector call itself.
    Call `start()` immediately before the await that should be
    interrupted. If the main thread does not reach the selector within
    the timeout, the thread signals it anyway and `sent_in_selector`
    stays `False`, so the test fails instead of waiting for the await.
    """

    def __init__(self) -> None:
        self.sent_in_selector = False
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        main_ident = threading.main_thread().ident
        assert main_ident is not None
        assert threading.get_ident() == main_ident, "must start in the main thread"
        self._thread = threading.Thread(
            target=self._signal_in_selector, args=(main_ident,), daemon=True
        )
        self._thread.start()

    def _signal_in_selector(self, main_ident: int) -> None:
        deadline = time.monotonic() + _SELECTOR_WAIT_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            if _waits_in_selector(sys._current_frames().get(main_ident)):
                self.sent_in_selector = True
                break
            time.sleep(_POLL_INTERVAL_SECONDS)
        signal.pthread_kill(main_ident, signal.SIGUSR1)

    def join(self) -> None:
        """Wait for the helper thread, if started."""
        if self._thread is not None:
            self._thread.join(timeout=_SELECTOR_WAIT_TIMEOUT_SECONDS)
            assert not self._thread.is_alive()
