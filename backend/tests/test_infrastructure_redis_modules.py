"""Regression tests: the Redis servers of the tests load no module.

Sentinel needs no Redis module, and a deployment may run Redis without the
modules that the official `redis` image bundles (docs/deployment.md, Software
Requirements). Every copy of Redis in development, CI, and the tests therefore
starts `redis-server` directly instead of through the image's entrypoint,
which would load them (docs/deployment.md, Workflow Conventions, PostgreSQL
and Redis images; docs/features/platform/testing-strategy.md, Redis Strategy,
Provisioning). Otherwise a use of a module command would pass the suite and
fail only in such a deployment. See issue #1376.

A module that the image's entrypoint loads comes from a file, so `MODULE LIST`
reports its path. A module that the server builds in, such as `vectorset`,
reports an empty path and cannot be unloaded, so it is not one of them.
"""

from __future__ import annotations

from typing import Any

import pytest
import redis
import redis.asyncio as redis_asyncio

from tests.support.redis import dedicated_redis_container


def _modules_loaded_from_files(modules: list[dict[str, Any]]) -> list[str]:
    """The `name: path` of every entry of a decoded `MODULE LIST` reply
    that the server loaded from a file."""
    return [
        f"{module['name']}: {module['path']}" for module in modules if module["path"]
    ]


@pytest.mark.unit
@pytest.mark.parametrize(
    ("modules", "loaded"),
    [
        ([{"name": "vectorset", "ver": 1, "path": "", "args": []}], []),
        (
            [
                {"name": "vectorset", "ver": 1, "path": "", "args": []},
                {
                    "name": "search",
                    "ver": 81001,
                    "path": "/usr/local/lib/redis/modules//redisearch.so",
                    "args": [],
                },
            ],
            ["search: /usr/local/lib/redis/modules//redisearch.so"],
        ),
        ([], []),
    ],
)
def test_modules_loaded_from_files_detects_a_bundled_module(
    modules: list[dict[str, Any]], loaded: list[str]
) -> None:
    # The checks below would pass vacuously if the predicate missed a module.
    # The samples have the shape that the image's entrypoint produces.
    assert _modules_loaded_from_files(modules) == loaded


@pytest.mark.integration
async def test_redis_server_of_the_suite_loads_no_module(
    redis_client: redis_asyncio.Redis,
) -> None:
    # The service container of the workflows, or the session container of a
    # local run.
    modules: list[dict[str, Any]] = await redis_client.module_list()

    assert _modules_loaded_from_files(modules) == []


@pytest.mark.integration
def test_dedicated_redis_container_loads_no_module() -> None:
    with (
        dedicated_redis_container() as container,
        redis.Redis.from_url(container.url, decode_responses=True) as client,
    ):
        modules: list[dict[str, Any]] = client.module_list()

    assert _modules_loaded_from_files(modules) == []
