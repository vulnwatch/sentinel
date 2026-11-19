"""Integration tests for the maintained package Alembic migration
(backend/alembic/versions/68d13447760b_add_maintained_package_table.py).

Verifies that upgrading from the previous head creates exactly the
`maintained_package` table documented in `docs/data-model.md`
(MaintainedPackage): columns, types, nullability, server defaults, the
primary key, UNIQUE `name`, no `updated_at`, and no foreign key, CHECK
constraint, or standalone index. Downgrade removes the table and re-upgrade
restores it.

`alembic check` is deliberately not invoked in-process (see
`test_product_catalog_migration.py`); the CI "Check Alembic migration drift"
step runs it from a clean process.
"""

from __future__ import annotations

from typing import Any, TypedDict

import pytest
from sqlalchemy import Dialect, inspect
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.types import DateTime, TypeEngine

from alembic import command
from app.config import settings
from tests.test_migrations.conftest import isolated_alembic_config, run_sync

_PREVIOUS_HEAD = "24109dcbef28"
_REVISION = "68d13447760b"
_TABLE = "maintained_package"

_EXPECTED_COLUMNS = [
    ("id", "UUID", False, "uuidv7()"),
    ("name", "VARCHAR(255)", False, None),
    ("created_at", "TIMESTAMPTZ", False, "now()"),
]


class _TableFacts(TypedDict):
    columns: list[tuple[str, str, bool, str | None]]
    primary_key: list[str]
    foreign_keys: list[dict[str, Any]]
    unique_constraints: set[tuple[str, tuple[str, ...]]]
    checks: list[dict[str, Any]]
    standalone_indexes: list[dict[str, Any]]


class _SchemaFacts(TypedDict):
    tables: set[str]
    table: _TableFacts | None


def _describe_type(column_type: TypeEngine[Any], dialect: Dialect) -> str:
    if isinstance(column_type, DateTime):
        return "TIMESTAMPTZ" if column_type.timezone else "TIMESTAMP"
    return str(column_type.compile(dialect=dialect))


async def _inspect_schema(database_url: str) -> _SchemaFacts:
    engine = create_async_engine(database_url)
    try:
        async with engine.connect() as conn:

            def _sync_inspect(sync_conn: Any) -> _SchemaFacts:
                inspector = inspect(sync_conn)
                tables = set(inspector.get_table_names())
                if _TABLE not in tables:
                    return {"tables": tables, "table": None}
                return {
                    "tables": tables,
                    "table": {
                        "columns": [
                            (
                                column["name"],
                                _describe_type(column["type"], sync_conn.dialect),
                                column["nullable"],
                                column["default"],
                            )
                            for column in inspector.get_columns(_TABLE)
                        ],
                        "primary_key": inspector.get_pk_constraint(_TABLE)[
                            "constrained_columns"
                        ],
                        "foreign_keys": inspector.get_foreign_keys(_TABLE),
                        "unique_constraints": {
                            (constraint["name"], tuple(constraint["column_names"]))
                            for constraint in inspector.get_unique_constraints(_TABLE)
                        },
                        "checks": inspector.get_check_constraints(_TABLE),
                        "standalone_indexes": [
                            index
                            for index in inspector.get_indexes(_TABLE)
                            if not index.get("duplicates_constraint")
                        ],
                    },
                }

            return await conn.run_sync(_sync_inspect)
    finally:
        await engine.dispose()


def _inspect(database_url: str) -> _SchemaFacts:
    return run_sync(_inspect_schema(database_url))


def _assert_schema(facts: _SchemaFacts) -> None:
    table = facts["table"]
    assert table is not None
    assert table["columns"] == _EXPECTED_COLUMNS
    assert table["primary_key"] == ["id"]
    assert table["foreign_keys"] == []
    assert table["unique_constraints"] == {("maintained_package_name_key", ("name",))}
    assert table["checks"] == []
    assert table["standalone_indexes"] == []


@pytest.mark.integration
class TestMaintainedPackageMigration:
    def test_upgrade_downgrade_reupgrade_cycle(
        self,
        alembic_test_database_url: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(settings, "database_url", alembic_test_database_url)
        cfg = isolated_alembic_config()

        command.upgrade(cfg, _PREVIOUS_HEAD)
        before = _inspect(alembic_test_database_url)
        assert before["table"] is None

        command.upgrade(cfg, _REVISION)
        upgraded = _inspect(alembic_test_database_url)
        _assert_schema(upgraded)
        assert upgraded["tables"] == before["tables"] | {_TABLE}

        command.downgrade(cfg, _PREVIOUS_HEAD)
        downgraded = _inspect(alembic_test_database_url)
        assert downgraded["table"] is None
        assert downgraded["tables"] == before["tables"]

        command.upgrade(cfg, _REVISION)
        _assert_schema(_inspect(alembic_test_database_url))
