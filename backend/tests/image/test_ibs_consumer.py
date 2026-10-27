"""OCI artifact probes for the IBS RabbitMQ consumer role.

Focused and system tests own the consumer's connection classification,
reconnect delays, delivery handling, heartbeat contents and validation,
signal handling, and log sanitization. These checks verify only the artifact
facts of the role: the documented command `python -m app.ibs_consumer` starts
from the candidate image, passes its PostgreSQL verification, logs its
startup event, and stays in its reconnect loop against the smoke stack's
refusing endpoint without exposing the URL credentials; and the API role
reports the consumer-written `reconnecting` heartbeat through the packaged
Redis topology to an authenticated caller.

The status endpoint requires authentication like every application read,
and no command of the image creates an API key non-interactively. A
gray-box probe in the `api` container therefore creates a role-less user
and its API key through the user and API key services, as the monitoring
of `docs/deployment.md` (Monitoring Scheduler Liveness) authenticates with
the key of a role-less account. The probe adds rows to the primary stack;
it neither repairs nor removes any.

See ``docs/features/platform/testing-strategy.md`` (Primary and Disposable
Topologies; Process Readiness; Representative Gate Evidence) and
``docs/features/integrations/ibs-rabbitmq-integration.md`` (Startup;
Reconnection; Structured Logs; Status API).
"""

from __future__ import annotations

import subprocess
import time
from collections.abc import Callable

import httpx
import pytest

from tests.image.conftest import json_log_records

_SERVICE = "ibs-consumer"
# The fictional user information of IBS_RABBITMQ_URL in docker-compose.smoke.yml.
_URL_CREDENTIALS = "example:example"
# Bound of the status observation: the readiness phase already saw the first
# reconnect, so the immediate heartbeat write precedes this test.
_STATUS_TIMEOUT_SECONDS = 30.0
_API_KEY_PREFIX = "stl_ak_"

# Creates a role-less local user and its API key, commits both, and prints
# only the key. Every identifier and the password are fictional.
_READER_API_KEY_SCRIPT = """
import asyncio
import uuid

from app.database import async_session_factory, engine
from app.services import api_key_service, user_service


async def main() -> None:
    suffix = uuid.uuid4().hex[:8]
    try:
        async with async_session_factory() as db:
            user = await user_service.create_user(
                db,
                username=f"smoke-reader-{suffix}",
                email=f"smoke-reader-{suffix}@example.com",
                password="fictional-smoke-reader-password",
                acting_user_id=None,
            )
            created = await api_key_service.create_key(
                db, user.id, "image-smoke-status-reader", None
            )
            await db.commit()
        print(created.plaintext_key)
    finally:
        await engine.dispose()


asyncio.run(main())
"""


@pytest.fixture(scope="module")
def reader_headers(
    compose_exec: Callable[..., subprocess.CompletedProcess[str]],
) -> dict[str, str]:
    """The `Authorization` header of a role-less reader's API key."""
    result = compose_exec("api", "python", "-c", _READER_API_KEY_SCRIPT)
    assert result.returncode == 0, (
        f"reader API key probe failed (stderr={result.stderr!r})"
    )
    api_key = result.stdout.strip().splitlines()[-1]
    assert api_key.startswith(_API_KEY_PREFIX), "the probe printed no API key"
    return {"Authorization": f"Bearer {api_key}"}


@pytest.mark.image
def test_ibs_consumer_starts_and_stays_in_its_reconnect_loop(
    compose_logs: Callable[[str], str],
    compose_service_state: Callable[[str], str],
) -> None:
    logs = compose_logs(_SERVICE)
    records = json_log_records(logs)
    events = [record.get("event") for record in records]

    assert "ibs_consumer_started" in events, logs
    assert any(
        record.get("event") == "ibs_consumer_connection_failed"
        and record.get("reason_category") == "network_error"
        for record in records
    ), logs
    assert "ibs_consumer_reconnect_scheduled" in events, logs
    assert _URL_CREDENTIALS not in logs, "IBS_RABBITMQ_URL credentials were logged"
    assert not [record for record in records if "ibs_event_id" in record], logs

    state = compose_service_state(_SERVICE)
    assert state.startswith("running|"), state


@pytest.mark.image
def test_status_endpoint_reports_the_consumer_written_reconnecting(
    http_client: httpx.Client,
    reader_headers: dict[str, str],
) -> None:
    deadline = time.monotonic() + _STATUS_TIMEOUT_SECONDS
    while True:
        response = http_client.get(
            "/api/v1/ibs-consumer/status", headers=reader_headers
        )
        assert response.status_code == 200, response.text
        data = response.json()["data"]
        if data["status"] == "reconnecting" or time.monotonic() >= deadline:
            break
        time.sleep(0.5)

    assert data["status"] == "reconnecting", data
    assert data["process_started_at"] is not None, data
    assert data["heartbeat_at"] is not None, data
    assert _URL_CREDENTIALS not in response.text
