"""Test-only no-op `BaseFetcher` subclass for the local process system suite.

See `docs/features/platform/testing-strategy.md` (Local Process System
Testing) for the full behavioral contract this class satisfies. This
module MUST NOT be imported by any production entrypoint
(`app/services/fetcher_discovery.py`, the API server, the worker, or
Beat outside a test-owned launcher) — see
`docs/features/platform/fetcher-infrastructure.md` (Registry
Maintenance, Test-only system-fetcher exception).

Importing this module registers `EvaluateTestPipeline` into the
process-local `FETCHER_REGISTRY` as a side effect of
`BaseFetcher.__init_subclass__`. Callers control exactly when that
happens (see `system_fetcher_app.py` for the process-launcher use, and
`backend/tests/system/conftest.py` for the pytest-host registration
fixture) — this module performs no registration on its own beyond the
ordinary Python import mechanism.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from app.services.base_fetcher import BaseFetcher

#: Registry name for the test-only fetcher. Referenced by
#: `backend/tests/system/conftest.py` and the image-exclusion assertions
#: in `backend/tests/image/test_celery.py` and
#: `backend/tests/image/test_image_build.py`.
SYSTEM_FETCHER_NAME = "evaluate_test_pipeline"


class EvaluateTestPipeline(BaseFetcher):
    """No-op fetcher used exclusively to validate the generic scheduled
    fetcher pipeline (registration, bootstrap, RedBeat scheduling,
    broker delivery, worker execution, `FetcherRun` finalization,
    read API visibility) end-to-end with real infrastructure.

    `execute()` performs no database writes, network calls, metric
    reporting, or cursor assignment — the expected finalized run has
    all metrics at zero and a `NULL` cursor (see testing-strategy.md,
    Test-Only Fetcher, for the exact expected field values).
    """

    name = SYSTEM_FETCHER_NAME
    description = "Test-only no-op fetcher for local process system validation"
    #: An annual cron expression, rather than a per-minute one, is used
    #: deliberately: the system test forces this schedule due via
    #: `FetcherPipelineHarness.make_due()` rather than waiting for a
    #: real cron boundary, then stops Beat immediately after observing
    #: the finalized run. A per-minute schedule risked a second,
    #: legitimate dispatch firing if the test happened to straddle a
    #: minute boundary between `make_due()` and `stop_beat()`, which
    #: would violate the "exactly one finalized run" assertion. An
    #: annual schedule makes a second occurrence within a single test's
    #: runtime impossible.
    default_schedule = "0 0 1 1 *"

    async def execute(self, session: AsyncSession) -> None:
        """No-op: intentionally performs no work of any kind."""
