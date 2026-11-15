"""Local process system test: a worker discards an expired scheduled run.

See `docs/features/platform/testing-strategy.md` (Local Process System
Testing, Scheduled Run Expiry) for the contract this test proves, and
`docs/features/platform/fetcher-infrastructure.md` (Scheduled Run Expiry)
for the behavior: a real worker acknowledges a scheduled `run_fetcher`
message whose expiry has passed without running the task, so no
`FetcherRun` exists, and logs `scheduled_run_expired`; the next message,
with the entry's own expiry, runs.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from tests.system.conftest import SYSTEM_FETCHER_NAME, FetcherPipelineHarness


@pytest.mark.system
async def test_expired_scheduled_run_is_discarded_without_a_fetcher_run(
    fetcher_pipeline_harness: FetcherPipelineHarness,
) -> None:
    harness = fetcher_pipeline_harness

    harness.start_worker()
    await harness.wait_worker_ready()
    config = await harness.wait_config_row()

    await asyncio.to_thread(
        harness.publish_scheduled_run,
        config,
        expires=datetime.now(UTC) - timedelta(minutes=1),
    )

    await harness.wait_worker_log("scheduled_run_expired", SYSTEM_FETCHER_NAME)
    assert await harness.list_runs() == []

    await asyncio.to_thread(harness.publish_scheduled_run, config)
    run = await harness.wait_finalized_run()

    assert run.status == "success", (
        f"expected a successful run, got {run.status!r}: "
        f"error_message={run.error_message!r}"
    )
    assert run.triggered_by == "schedule"
    runs = await harness.list_runs()
    assert [r.id for r in runs] == [run.id]
    audit_events = await harness.list_audit_events()
    assert audit_events == []
