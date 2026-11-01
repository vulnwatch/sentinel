"""Regression tests for the reconnection of the IBS RabbitMQ capture helper
(`scripts/capture-ibs-rabbitmq.py`) after a broker-side loss (issue #1171).

The non-robust aio-pika connection completes `closed()` only when the client
closes it, so the helper must observe a loss through the connection and
channel close callbacks and the broker's `basic.cancel`. The script runs as a
subprocess of the backend interpreter, whose aio-pika is the version that the
script pins (`tests/test_dependency_cooldown.py`), against the in-process
fake AMQP broker (`tests/support/amqp_server.py`) over plain TCP on
127.0.0.1, where aiormq ignores the TLS context. Its JSONL output goes to
`tmp_path`, and SIGTERM ends it through its graceful stop.

Marked `integration` because it uses loopback sockets; no database, Redis,
or external network is used.
"""

from __future__ import annotations

import asyncio
import json
import signal
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from pamqp import commands

from tests.support.amqp_server import FakeAmqpServer, ServerConnection

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT_PATH = REPO_ROOT / "scripts" / "capture-ibs-rabbitmq.py"

_ROUTING_KEY = "suse.obs.package.commit"
_BODY = b'{"project":"example:project","package":"example-package"}'
_EXIT_SECONDS = 10.0
"""Bound of the script's exit after SIGTERM."""


def _records(output: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in output.read_text().splitlines()]


@pytest.mark.parametrize(
    ("lose", "reason"),
    [
        pytest.param(
            lambda server: server.close_connection(
                320, "CONNECTION_FORCED - example shutdown"
            ),
            "connection_lost",
            id="connection-close",
        ),
        pytest.param(ServerConnection.abort, "connection_lost", id="tcp-abort"),
        pytest.param(
            lambda server: server.close_channel(406, "PRECONDITION_FAILED - example"),
            "channel_lost",
            id="channel-close",
        ),
        pytest.param(
            ServerConnection.cancel_consumer,
            "consumer_cancelled",
            id="consumer-cancel",
        ),
    ],
)
async def test_capture_after_broker_side_loss_records_it_and_reconnects(
    tmp_path: Path, lose: Callable[[ServerConnection], None], reason: str
) -> None:
    output = tmp_path / "events.jsonl"
    async with FakeAmqpServer() as broker:
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            str(SCRIPT_PATH),
            "--broker-url",
            broker.url,
            "--routing-key",
            _ROUTING_KEY,
            "--output",
            str(output),
            "--reconnect-initial",
            "1",
            "--reconnect-max",
            "1",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            first = await broker.connection(0)
            await first.wait_for(commands.Basic.Consume)
            lose(first)
            # The lost connection is closed before the reconnection.
            await first.wait_closed()
            second = await broker.connection(1)
            await second.wait_for(commands.Basic.Consume)
            tag = second.deliver(
                _BODY,
                routing_key=_ROUTING_KEY,
                content_type="application/octet-stream",
            )
            ack = await second.wait_for(commands.Basic.Ack)
            process.send_signal(signal.SIGTERM)
            async with asyncio.timeout(_EXIT_SECONDS):
                _, stderr = await process.communicate()
        finally:
            if process.returncode is None:
                process.kill()
                await process.communicate()

    assert process.returncode == 0, stderr.decode(errors="replace")
    assert ack.delivery_tag == tag
    records = _records(output)
    assert [record["record_type"] for record in records] == [
        "session_started",
        "connection_attempt",
        "consumer_ready",
        "connection_lost",
        "reconnect_scheduled",
        "connection_attempt",
        "consumer_ready",
        "message",
        "session_ended",
    ]
    lost, message, ended = records[3], records[7], records[8]
    assert lost["reason"] == reason
    assert message["routing_key"] == _ROUTING_KEY
    assert message["payload"] == json.loads(_BODY)
    assert ended["messages_captured"] == 1
