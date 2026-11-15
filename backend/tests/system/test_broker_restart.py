"""Local process system test: a worker resumes consuming after the broker
restarts.

See `docs/features/platform/testing-strategy.md` (Local Process System
Testing, Broker Restart Recovery) for the contract this test proves, and
`docs/deployment.md` (Kubernetes Workloads, Worker recovery and probes)
for the requirement: a real worker on a dedicated Redis broker executes a
scheduled `run_fetcher` message published after each of several broker
restarts, without exiting. A worker that stays connected but idle after a
restart fails the test with a timeout.
"""

from __future__ import annotations

import asyncio
import uuid

import pytest

from tests.system.conftest import FetcherPipelineHarness

_RESTART_CYCLES = 3
# Long enough for the worker's immediate reconnection attempt and its
# first retry, two seconds later, to fail against the stopped broker,
# as during the outage of the observed case.
_BROKER_OUTAGE_SECONDS = 5.0
# Bounds the reconnection with its growing retry delays plus the run.
_RECOVERY_TIMEOUT = 60.0


@pytest.mark.system
async def test_worker_resumes_consuming_after_each_broker_restart(
    broker_restart_harness: FetcherPipelineHarness,
) -> None:
    harness = broker_restart_harness
    broker = harness.broker
    assert broker is not None

    harness.start_worker()
    await harness.wait_worker_ready()
    worker = harness.worker_process
    assert worker is not None
    config = await harness.wait_config_row()

    observed: set[uuid.UUID] = set()
    for cycle in range(_RESTART_CYCLES + 1):
        if cycle:
            # The stopped container drops every connection, and its start
            # without persistence brings back an empty server.
            await asyncio.to_thread(broker.stop)
            await asyncio.sleep(_BROKER_OUTAGE_SECONDS)
            await asyncio.to_thread(broker.start)

        await asyncio.to_thread(harness.publish_scheduled_run, config)
        run = await harness.wait_finalized_run(
            _RECOVERY_TIMEOUT, exclude=frozenset(observed)
        )

        assert run.status == "success", (
            f"cycle {cycle}: expected a successful run, got {run.status!r}: "
            f"error_message={run.error_message!r}"
        )
        assert run.triggered_by == "schedule"
        assert run.hard_time_limit_seconds == config.run_timeout
        observed.add(run.id)
        # Recovery happened inside the worker that was started first: an
        # exit, which only an orchestrator would answer with a restart,
        # fails the test.
        worker.assert_alive()

    runs = await harness.list_runs()
    assert {r.id for r in runs} == observed
    assert len(observed) == _RESTART_CYCLES + 1
