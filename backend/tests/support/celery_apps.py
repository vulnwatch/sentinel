"""Test-only construction of Sentinel Celery applications.

Shared by the `celery_test_app` fixtures in `tests/conftest.py`, which
bind an application to the pytest worker's Redis logical database, and by
the local process system suite (`tests/system/conftest.py`), whose broker
restart test binds one to a dedicated Redis container (see
docs/features/platform/testing-strategy.md, Redis Strategy and Local
Process System Testing).
"""

from __future__ import annotations

from celery import Celery

from app.celery_app import create_celery_app
from app.config import Settings


def create_celery_test_app(redis_url: str) -> Celery:
    """Build a Sentinel Celery app whose broker and RedBeat use
    `redis_url`, without initializing `redbeat_conf`.

    The caller removes `CELERY_BROKER_URL` from the environment first:
    Celery's `broker_url` setting reads that variable before the value
    configured here.
    """
    settings = Settings(
        _env_file=None,
        jwt_secret_key="a" * 32,
        app_name="sentinel-test",
        log_level="INFO",
        log_format="json",
        celery_broker_url=redis_url,
        celery_timezone="UTC",
        celery_enable_utc=True,
    )
    return create_celery_app(settings)
