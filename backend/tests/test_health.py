"""End-to-end tests for the public health/readiness endpoints
(`GET /health`, `GET /ready`).

See `docs/features/platform/health-endpoints.md` for the full contract:
exact response bodies, no API envelope, public/root routing, and the
"never a 4xx, never a 500" guarantee. Failure scenarios reuse the same
real-database/real-Redis-vs-fake split established in
`tests/test_services/test_health_service.py` (see that module's
docstring): only the success path touches a real dependency; failure
paths use dependency overrides pointing at deliberately-closed local
ports, which never leave the loopback interface.
"""

from __future__ import annotations

from collections.abc import Generator

import pytest
import redis.asyncio as redis_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.api.health import get_readiness_redis_urls, get_readiness_session_factory
from app.config import settings as app_settings
from app.database import async_session_factory
from app.main import app
from tests.support.redis import redis_url_from_client

# Nothing listens here: connections are refused immediately (see
# tests/test_services/test_health_service.py for the same convention).
_CLOSED_PORT_URL = "redis://localhost:1/0"
_CLOSED_PORT_DATABASE_URL = "postgresql+asyncpg://user:pass@localhost:1/db"


@pytest.fixture
def use_real_readiness_postgresql(
    real_session_factory: async_sessionmaker[AsyncSession],
) -> Generator[None]:
    """Override the readiness PostgreSQL dependency to use the test's
    real database, independent of whichever `DATABASE_URL` happens to
    be configured in the environment running the suite."""
    app.dependency_overrides[get_readiness_session_factory] = lambda: (
        real_session_factory
    )
    try:
        yield
    finally:
        app.dependency_overrides.pop(get_readiness_session_factory, None)


@pytest.fixture
def broken_readiness_postgresql() -> Generator[None]:
    """Override the readiness PostgreSQL dependency to point at a
    closed local port — deterministic `unreachable` without touching
    any real database."""
    from sqlalchemy.ext.asyncio import create_async_engine

    engine = create_async_engine(_CLOSED_PORT_DATABASE_URL)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    app.dependency_overrides[get_readiness_session_factory] = lambda: factory
    try:
        yield
    finally:
        app.dependency_overrides.pop(get_readiness_session_factory, None)


@pytest.fixture
def broken_readiness_redis() -> Generator[None]:
    """Override the readiness Redis dependency to point at a closed
    local port — deterministic `unreachable` without touching any real
    Redis instance."""
    app.dependency_overrides[get_readiness_redis_urls] = lambda: [_CLOSED_PORT_URL]
    try:
        yield
    finally:
        app.dependency_overrides.pop(get_readiness_redis_urls, None)


@pytest.mark.unit
class TestGetReadinessSessionFactory:
    def test_returns_the_shared_application_session_factory(self) -> None:
        """Every readiness test overrides this dependency (via
        `use_real_readiness_postgresql`) to point at the test database
        instead of whatever `DATABASE_URL` the environment running the
        suite happens to have configured — so the default, un-overridden
        implementation is exercised directly here instead."""
        assert get_readiness_session_factory() is async_session_factory


@pytest.mark.e2e
class TestLivenessEndpoint:
    async def test_returns_exact_ok_body(self, client: AsyncClient) -> None:
        response = await client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

    async def test_response_has_no_data_envelope(self, client: AsyncClient) -> None:
        """`/health` is exempt from the standard `{"data": ...}`
        envelope — see docs/api-spec.md (Response Format)."""
        response = await client.get("/health")
        assert "data" not in response.json()

    async def test_requires_no_authentication(self, client: AsyncClient) -> None:
        response = await client.get("/health")
        assert response.status_code == 200

    async def test_performs_no_dependency_io(
        self,
        client: AsyncClient,
        broken_readiness_postgresql: None,
        broken_readiness_redis: None,
    ) -> None:
        """Even with both readiness dependencies pointing at unreachable
        targets, `/health` must still return 200 — it never touches
        readiness dependencies (see health-endpoints.md, Liveness —
        GET /health)."""
        response = await client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

    async def test_stale_credential_is_ignored(self, client: AsyncClient) -> None:
        """`/health` is a Public endpoint (see `docs/api-spec.md`, Public
        Endpoints): it ignores request credentials entirely, so a
        malformed JWT or unknown API key must not affect its probe
        contract — see `docs/features/platform/testing-strategy.md`
        (Authentication and Session)."""
        response = await client.get(
            "/health",
            headers={"Authorization": "Bearer not-a-real-token"},
        )
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

        response = await client.get(
            "/health",
            headers={"Authorization": "Bearer stl_ak_" + "0" * 32},
        )
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


@pytest.mark.e2e
class TestReadinessEndpointSuccess:
    async def test_all_healthy_returns_200(
        self,
        client: AsyncClient,
        use_real_readiness_postgresql: None,
        redis_client: redis_asyncio.Redis,
    ) -> None:
        response = await client.get("/ready")
        assert response.status_code == 200
        assert response.json() == {
            "status": "ok",
            "checks": {"postgresql": "ok", "redis": "ok"},
        }

    async def test_response_has_no_data_envelope(
        self,
        client: AsyncClient,
        use_real_readiness_postgresql: None,
        redis_client: redis_asyncio.Redis,
    ) -> None:
        response = await client.get("/ready")
        assert "data" not in response.json()

    async def test_default_dependency_resolves_from_settings(
        self,
        client: AsyncClient,
        use_real_readiness_postgresql: None,
        redis_client: redis_asyncio.Redis,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Without any override, `get_readiness_redis_urls` reads
        `REDIS_URL`/`CELERY_BROKER_URL` from settings — proven here by
        pointing both at the same real test instance and confirming
        the request still succeeds (also exercises the standard
        single-instance dedup case)."""
        url = redis_url_from_client(redis_client)
        monkeypatch.setattr(app_settings, "redis_url", url)
        monkeypatch.setattr(app_settings, "celery_broker_url", url)
        app.dependency_overrides.pop(get_readiness_redis_urls, None)

        response = await client.get("/ready")

        assert response.status_code == 200
        assert response.json()["checks"]["redis"] == "ok"

    async def test_requires_no_authentication(
        self,
        client: AsyncClient,
        use_real_readiness_postgresql: None,
        redis_client: redis_asyncio.Redis,
    ) -> None:
        response = await client.get("/ready")
        assert response.status_code == 200

    async def test_stale_credential_does_not_affect_result(
        self,
        client: AsyncClient,
        use_real_readiness_postgresql: None,
        redis_client: redis_asyncio.Redis,
    ) -> None:
        """`/ready` is a Public endpoint (see `docs/api-spec.md`, Public
        Endpoints): the result depends only on the readiness checks,
        never on a stale or invalid credential — see
        `docs/features/platform/testing-strategy.md` (Authentication and
        Session)."""
        response = await client.get(
            "/ready",
            headers={"Authorization": "Bearer not-a-real-token"},
        )
        assert response.status_code == 200
        assert response.json() == {
            "status": "ok",
            "checks": {"postgresql": "ok", "redis": "ok"},
        }

        response = await client.get(
            "/ready",
            headers={"Authorization": "Bearer stl_ak_" + "0" * 32},
        )
        assert response.status_code == 200
        assert response.json() == {
            "status": "ok",
            "checks": {"postgresql": "ok", "redis": "ok"},
        }

    async def test_performs_fresh_checks_each_request(
        self,
        client: AsyncClient,
        use_real_readiness_postgresql: None,
        redis_client: redis_asyncio.Redis,
    ) -> None:
        """No caching: the same process must reflect a dependency
        state change between two consecutive requests.

        Restores the override installed by the `redis_client` fixture
        (rather than popping it) so the third request is not left to
        fall through to the endpoint's default dependency
        (`settings.redis_url`/`settings.celery_broker_url`), which
        points at a real Redis instance outside the test harness'
        control."""
        first = await client.get("/ready")
        assert first.status_code == 200

        fixture_override = app.dependency_overrides[get_readiness_redis_urls]
        app.dependency_overrides[get_readiness_redis_urls] = lambda: [_CLOSED_PORT_URL]
        try:
            second = await client.get("/ready")
        finally:
            app.dependency_overrides[get_readiness_redis_urls] = fixture_override
        assert second.status_code == 503

        third = await client.get("/ready")
        assert third.status_code == 200


@pytest.mark.e2e
class TestReadinessEndpointFailure:
    async def test_postgresql_unreachable_returns_503(
        self,
        client: AsyncClient,
        broken_readiness_postgresql: None,
        redis_client: redis_asyncio.Redis,
    ) -> None:
        response = await client.get("/ready")
        assert response.status_code == 503
        assert response.json() == {
            "status": "unavailable",
            "checks": {"postgresql": "unreachable", "redis": "ok"},
        }

    async def test_redis_unreachable_returns_503(
        self,
        client: AsyncClient,
        use_real_readiness_postgresql: None,
        broken_readiness_redis: None,
    ) -> None:
        response = await client.get("/ready")
        assert response.status_code == 503
        assert response.json() == {
            "status": "unavailable",
            "checks": {"postgresql": "ok", "redis": "unreachable"},
        }

    async def test_both_unreachable_returns_503(
        self,
        client: AsyncClient,
        broken_readiness_postgresql: None,
        broken_readiness_redis: None,
    ) -> None:
        response = await client.get("/ready")
        assert response.status_code == 503
        assert response.json() == {
            "status": "unavailable",
            "checks": {"postgresql": "unreachable", "redis": "unreachable"},
        }

    async def test_split_instances_checked_independently(
        self,
        client: AsyncClient,
        use_real_readiness_postgresql: None,
        redis_client: redis_asyncio.Redis,
    ) -> None:
        """One reachable instance and one refused instance: the
        response must surface the failing one, proving both configured
        URLs are actually checked (not just the first)."""
        reachable_url = redis_url_from_client(redis_client)
        app.dependency_overrides[get_readiness_redis_urls] = lambda: [
            reachable_url,
            _CLOSED_PORT_URL,
        ]
        try:
            response = await client.get("/ready")
        finally:
            app.dependency_overrides.pop(get_readiness_redis_urls, None)
        assert response.status_code == 503
        assert response.json()["checks"]["redis"] == "unreachable"

    async def test_unexpected_exception_returns_503_without_leaking_detail(
        self,
        client: AsyncClient,
        use_real_readiness_postgresql: None,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """A malformed Redis URL triggers the "unexpected exception"
        path (see health-endpoints.md, Error responses): logged at
        ERROR, reported as `unreachable`, no exception text in the
        response body."""
        app.dependency_overrides[get_readiness_redis_urls] = lambda: [
            "http://example.com"
        ]
        try:
            with caplog.at_level("ERROR"):
                response = await client.get("/ready")
        finally:
            app.dependency_overrides.pop(get_readiness_redis_urls, None)

        assert response.status_code == 503
        body = response.json()
        assert body == {
            "status": "unavailable",
            "checks": {"postgresql": "ok", "redis": "unreachable"},
        }
        assert "example.com" not in response.text
        assert "readiness_check_unexpected_error" in caplog.text

    async def test_never_returns_a_4xx_status(
        self,
        client: AsyncClient,
        broken_readiness_postgresql: None,
        broken_readiness_redis: None,
    ) -> None:
        response = await client.get("/ready")
        assert response.status_code == 503
        assert not (400 <= response.status_code < 500)


@pytest.mark.e2e
class TestRouting:
    async def test_registered_at_root_not_under_api_v1(
        self,
        client: AsyncClient,
        use_real_readiness_postgresql: None,
        redis_client: redis_asyncio.Redis,
    ) -> None:
        assert (await client.get("/health")).status_code == 200
        assert (await client.get("/ready")).status_code == 200
        assert (await client.get("/api/v1/health")).status_code == 404
        assert (await client.get("/api/v1/ready")).status_code == 404
