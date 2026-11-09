"""Integration tests for the CNA Alembic migration
(backend/alembic/versions/b169c9f216f2_add_cna_table_and_cve_cna_id.py).

Verifies that upgrading from the previous head creates the `cna` table with
exactly the columns, defaults, primary key, and `org_id` unique constraint of
`docs/data-model.md` (CNA), and adds the nullable `cve.cna_id` with its
foreign key to `cna.id` ON DELETE RESTRICT and the non-unique index
`ix_cve_cna_id` (docs/data-model.md, CVE, Indexes). An existing CVE survives
the upgrade with no CNA (docs/features/tickets/cna.md, CNA of a CVE: a CVE
has none until a writer ingests its record), a new CNA row takes its
defaults, and the foreign key rejects deleting a referenced CNA. Downgrade
removes exactly what the revision added and keeps every CVE; re-upgrade
restores the schema.

See `tests/test_migrations/conftest.py` for the shared Alembic test
infrastructure (dedicated database fixture, isolated config helper).
"""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import create_async_engine

from alembic import command
from app.config import settings
from tests.test_migrations.conftest import isolated_alembic_config, run_sync

_PREVIOUS_HEAD = "57504b9961b3"
_REVISION = "b169c9f216f2"

_ORG_ID = "00000000-0000-4000-8000-0000000000a1"
_CVE_ID = "CVE-2099-0001"

_EXPECTED_CNA_COLUMNS = {
    "id": ("uuid", "NO", "uuidv7()"),
    "org_id": ("uuid", "NO", None),
    "short_name": ("character varying", "YES", None),
    "short_name_observed_at": ("timestamp with time zone", "YES", None),
    "organization_name": ("character varying", "YES", None),
    "types": ("jsonb", "NO", "'[]'::jsonb"),
    "scope": ("text", "YES", None),
    "auto_ignore": ("boolean", "NO", "false"),
    "created_at": ("timestamp with time zone", "NO", "now()"),
    "updated_at": ("timestamp with time zone", "NO", "now()"),
}
_EXPECTED_LENGTHS = {"short_name": 32, "organization_name": 256}
_EXPECTED_CNA_CONSTRAINTS = {
    "cna_pkey": "PRIMARY KEY (id)",
    "cna_org_id_key": "UNIQUE (org_id)",
}
_EXPECTED_FOREIGN_KEY = "FOREIGN KEY (cna_id) REFERENCES cna(id) ON DELETE RESTRICT"
_EXPECTED_INDEX = "CREATE INDEX ix_cve_cna_id ON public.cve USING btree (cna_id)"


async def _execute_async(database_url: str, sql: str, **params: Any) -> None:
    engine = create_async_engine(database_url)
    try:
        async with engine.begin() as conn:
            await conn.execute(text(sql), params)
    finally:
        await engine.dispose()


def _execute(database_url: str, sql: str, **params: Any) -> None:
    run_sync(_execute_async(database_url, sql, **params))


async def _fetch_async(database_url: str, sql: str) -> list[tuple[Any, ...]]:
    engine = create_async_engine(database_url)
    try:
        async with engine.connect() as conn:
            return [tuple(row) for row in await conn.execute(text(sql))]
    finally:
        await engine.dispose()


def _fetch(database_url: str, sql: str) -> list[tuple[Any, ...]]:
    return run_sync(_fetch_async(database_url, sql))


def _version(url: str) -> str:
    ((version,),) = _fetch(url, "SELECT version_num FROM alembic_version")
    assert isinstance(version, str)
    return version


def _columns(url: str, table: str) -> dict[str, tuple[Any, ...]]:
    rows = _fetch(
        url,
        "SELECT column_name, data_type, is_nullable, column_default, "
        "character_maximum_length FROM information_schema.columns "
        f"WHERE table_name = '{table}'",
    )
    return {row[0]: row[1:] for row in rows}


def _constraints(url: str, table: str) -> dict[str, str]:
    rows = _fetch(
        url,
        "SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint "
        f"WHERE conrelid = '{table}'::regclass AND contype IN ('p', 'u', 'f', 'c')",
    )
    return {str(name): str(definition) for name, definition in rows}


def _indexes(url: str, table: str) -> dict[str, str]:
    rows = _fetch(
        url,
        f"SELECT indexname, indexdef FROM pg_indexes WHERE tablename = '{table}'",
    )
    return {str(name): str(definition) for name, definition in rows}


def _cna_table_exists(url: str) -> bool:
    ((exists,),) = _fetch(url, "SELECT to_regclass('public.cna') IS NOT NULL")
    return bool(exists)


def _cves(url: str) -> list[tuple[Any, ...]]:
    return _fetch(url, "SELECT cve_id, cve_state FROM cve ORDER BY cve_id")


def _assert_upgraded(
    url: str,
    previous_cve_columns: dict[str, tuple[Any, ...]],
    previous_cve_constraints: dict[str, str],
    previous_cve_indexes: dict[str, str],
) -> None:
    assert _version(url) == _REVISION
    columns = _columns(url, "cna")
    assert {
        name: (data_type, nullable, default)
        for name, (data_type, nullable, default, _) in columns.items()
    } == _EXPECTED_CNA_COLUMNS
    assert {
        name: length
        for name, (_, _, _, length) in columns.items()
        if length is not None
    } == _EXPECTED_LENGTHS
    assert _constraints(url, "cna") == _EXPECTED_CNA_CONSTRAINTS

    cve_columns = _columns(url, "cve")
    assert cve_columns == {
        **previous_cve_columns,
        "cna_id": ("uuid", "YES", None, None),
    }
    assert _constraints(url, "cve") == {
        **previous_cve_constraints,
        "cve_cna_id_fkey": _EXPECTED_FOREIGN_KEY,
    }
    assert _indexes(url, "cve") == {
        **previous_cve_indexes,
        "ix_cve_cna_id": _EXPECTED_INDEX,
    }
    assert _fetch(url, "SELECT cve_id, cna_id FROM cve") == [(_CVE_ID, None)]


def _assert_previous(
    url: str,
    previous_cve_columns: dict[str, tuple[Any, ...]],
    previous_cve_constraints: dict[str, str],
    previous_cve_indexes: dict[str, str],
    previous_cves: list[tuple[Any, ...]],
) -> None:
    assert _version(url) == _PREVIOUS_HEAD
    assert not _cna_table_exists(url)
    assert _columns(url, "cve") == previous_cve_columns
    assert _constraints(url, "cve") == previous_cve_constraints
    assert _indexes(url, "cve") == previous_cve_indexes
    assert _cves(url) == previous_cves


@pytest.mark.integration
class TestCNAMigration:
    def test_upgrade_downgrade_reupgrade_cycle(
        self,
        alembic_test_database_url: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Exactly the table, the column, its foreign key, and the index are
        added and removed; the existing CVE keeps every value."""
        monkeypatch.setattr(settings, "database_url", alembic_test_database_url)
        cfg = isolated_alembic_config()
        url = alembic_test_database_url

        command.upgrade(cfg, _PREVIOUS_HEAD)
        _execute(url, "INSERT INTO cve (cve_id) VALUES (:cve_id)", cve_id=_CVE_ID)
        previous = (
            _columns(url, "cve"),
            _constraints(url, "cve"),
            _indexes(url, "cve"),
        )
        previous_cves = _cves(url)
        assert not _cna_table_exists(url)

        command.upgrade(cfg, _REVISION)
        _assert_upgraded(url, *previous)

        command.downgrade(cfg, _PREVIOUS_HEAD)
        _assert_previous(url, *previous, previous_cves)

        command.upgrade(cfg, _REVISION)
        _assert_upgraded(url, *previous)

    def test_new_cna_takes_its_defaults_and_a_referenced_cna_cannot_be_deleted(
        self,
        alembic_test_database_url: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """`types` is `[]`, `auto_ignore` false, and the identifier a UUIDv7;
        a second row with the same `org_id` and the deletion of a CNA that a
        CVE references both fail."""
        monkeypatch.setattr(settings, "database_url", alembic_test_database_url)
        cfg = isolated_alembic_config()
        url = alembic_test_database_url
        command.upgrade(cfg, _REVISION)

        _execute(url, "INSERT INTO cna (org_id) VALUES (:org_id)", org_id=_ORG_ID)
        ((types, auto_ignore, version),) = _fetch(
            url, "SELECT types, auto_ignore, uuid_extract_version(id) FROM cna"
        )
        assert (types, auto_ignore, version) == ([], False, 7)

        with pytest.raises(IntegrityError, match="cna_org_id_key"):
            _execute(url, "INSERT INTO cna (org_id) VALUES (:org_id)", org_id=_ORG_ID)

        _execute(
            url,
            "INSERT INTO cve (cve_id, cna_id) "
            "SELECT :cve_id, id FROM cna WHERE org_id = :org_id",
            cve_id=_CVE_ID,
            org_id=_ORG_ID,
        )
        with pytest.raises(IntegrityError, match="cve_cna_id_fkey"):
            _execute(url, "DELETE FROM cna")
