"""Business logic for the public liveness and readiness probes.

See `docs/features/platform/health-endpoints.md` for the authoritative
contract this module implements. This module has no API-facing
exceptions: every check function catches all failure modes internally
and reports them as a `HealthCheckStatus` (see health-endpoints.md,
Error responses: "This endpoint never produces a 500 response — all
exceptions are caught internally").
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Iterable
from contextlib import suppress
from dataclasses import dataclass
from typing import Final
from urllib.parse import urlsplit

import redis.asyncio as redis_asyncio
import structlog
from redis.exceptions import RedisError
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.enums import HealthCheckStatus

logger = structlog.get_logger(__name__)


@dataclass(frozen=True)
class ReadinessCheckResult:
    """Outcome of a full readiness check run.

    Plain service-layer return type (the Service layer does not depend
    on Schema — see `docs/architecture.md`, Backend Layer Architecture).
    The API layer maps this to the `ReadinessResponse` schema.
    """

    postgresql: HealthCheckStatus
    redis: HealthCheckStatus


# Per-check timeout, in seconds. See health-endpoints.md ("2-second
# timeout per check").
_CHECK_TIMEOUT_SECONDS = 2

# Standard Redis port, used when a discovered URL does not specify one
# explicitly.
_DEFAULT_REDIS_PORT = 6379

# Severity order used to aggregate multiple Redis instance results into
# a single check result. See health-endpoints.md (Readiness — GET
# /ready): "ok (severity 0) < timeout (severity 1) < unreachable
# (severity 2)".
_SEVERITY: Final[frozendict[HealthCheckStatus, int]] = frozendict(
    {
        HealthCheckStatus.OK: 0,
        HealthCheckStatus.TIMEOUT: 1,
        HealthCheckStatus.UNREACHABLE: 2,
    }
)


def discover_redis_targets(urls: Iterable[str]) -> list[str]:
    """Deduplicate Redis connection URLs by their `host:port` pair.

    Preserves the first-seen full URL for each unique `(host, port)`
    pair, in input order. The port defaults to the standard Redis port
    (6379) when a URL does not specify one explicitly. See
    health-endpoints.md (Redis instance discovery).

    A URL that fails to parse (e.g. a malformed port) is never dropped
    silently and never raises: it is kept as its own dedup key (the
    raw string), so it is still passed on to `_check_redis`, whose
    existing `Exception` handler reports it as `UNREACHABLE` — this
    function must never be the source of an unhandled exception, since
    it runs outside `_check_redis`'s per-URL error boundary (see
    health-endpoints.md, Error responses: "never produces a 500
    response").
    """
    seen: set[tuple[str | None, int] | str] = set()
    unique_urls: list[str] = []
    for url in urls:
        try:
            parsed = urlsplit(url)
            key: tuple[str | None, int] | str = (
                parsed.hostname,
                parsed.port or _DEFAULT_REDIS_PORT,
            )
        except ValueError:
            key = url
        if key in seen:
            continue
        seen.add(key)
        unique_urls.append(url)
    return unique_urls


def aggregate_redis_status(
    results: Iterable[HealthCheckStatus],
) -> HealthCheckStatus:
    """Aggregate multiple Redis instance check results into one status.

    Returns the result with the highest severity, per the total order
    `ok < timeout < unreachable` (see health-endpoints.md, Readiness —
    GET /ready). Returns `HealthCheckStatus.OK` when `results` is empty
    (no Redis instance discovered).
    """
    return max(
        results, key=lambda status: _SEVERITY[status], default=HealthCheckStatus.OK
    )


async def _check_postgresql(
    session_factory: async_sessionmaker[AsyncSession],
) -> HealthCheckStatus:
    """Check PostgreSQL connectivity with a `SELECT 1` query.

    Opens a fresh session from `session_factory` and executes
    `SELECT 1` within a 2-second timeout. Never raises: every failure
    mode is caught and translated to a `HealthCheckStatus`. Unexpected
    exceptions (beyond timeout and SQLAlchemy/connection errors) are
    logged at ERROR level with the traceback before being reported as
    `UNREACHABLE` — see health-endpoints.md (Error responses).
    """
    try:
        async with asyncio.timeout(_CHECK_TIMEOUT_SECONDS):
            async with session_factory() as session:
                await session.execute(text("SELECT 1"))
        return HealthCheckStatus.OK
    except TimeoutError:
        return HealthCheckStatus.TIMEOUT
    except SQLAlchemyError, OSError:
        return HealthCheckStatus.UNREACHABLE
    except Exception:
        logger.error(
            "readiness_check_unexpected_error", check="postgresql", exc_info=True
        )
        return HealthCheckStatus.UNREACHABLE


async def _check_redis(url: str) -> HealthCheckStatus:
    """Check a single Redis instance's connectivity with `PING`.

    Connects to `url` and issues `PING` within a 2-second timeout. The
    client is always closed, regardless of outcome. Never raises: every
    failure mode is caught and translated to a `HealthCheckStatus` —
    including a malformed `url` (`Redis.from_url` raises `ValueError`
    synchronously, before any connection attempt). Unexpected
    exceptions (beyond timeout and `RedisError`) are logged at ERROR
    level with the traceback before being reported as `UNREACHABLE` —
    see health-endpoints.md (Error responses).
    """
    client: redis_asyncio.Redis | None = None
    try:
        client = redis_asyncio.Redis.from_url(url)
        async with asyncio.timeout(_CHECK_TIMEOUT_SECONDS):
            await client.ping()
        return HealthCheckStatus.OK
    except TimeoutError:
        return HealthCheckStatus.TIMEOUT
    except RedisError:
        return HealthCheckStatus.UNREACHABLE
    except Exception:
        logger.error("readiness_check_unexpected_error", check="redis", exc_info=True)
        return HealthCheckStatus.UNREACHABLE
    finally:
        if client is not None:
            with suppress(RedisError):
                await client.aclose()


async def check_readiness(
    session_factory: async_sessionmaker[AsyncSession],
    redis_urls: Iterable[str],
) -> ReadinessCheckResult:
    """Run every readiness dependency check concurrently.

    Executes the PostgreSQL check and one Redis `PING` per unique
    instance discovered in `redis_urls` (see `discover_redis_targets`)
    concurrently via `asyncio.gather`. Multiple Redis results are
    aggregated per `aggregate_redis_status`. Always returns a complete
    `ReadinessCheckResult` — no exception escapes this function, since
    both `_check_postgresql` and `_check_redis` catch every failure mode
    internally. Every invocation performs fresh checks; nothing is
    cached (see health-endpoints.md, "No response caching").
    """
    unique_redis_urls = discover_redis_targets(redis_urls)
    checks: list[Awaitable[HealthCheckStatus]] = [
        _check_postgresql(session_factory),
        *(_check_redis(url) for url in unique_redis_urls),
    ]
    postgresql_result, *redis_results = await asyncio.gather(*checks)
    return ReadinessCheckResult(
        postgresql=postgresql_result,
        redis=aggregate_redis_status(redis_results),
    )
