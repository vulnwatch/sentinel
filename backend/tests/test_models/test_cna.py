"""Integration tests for the CNA model (backend/app/models/cna.py) and the
`cve.cna_id` reference to it (backend/app/models/cve.py).

See docs/data-model.md (CNA; CVE, `cna_id` and Indexes) and
docs/features/tickets/cna.md (The CNA Entity). Only the persistence contract
is covered here; the ingestion writes and the reads belong to
`cna_service` and `cve_service`.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

import pytest
from sqlalchemy import CheckConstraint, delete, insert, null, text, update
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cna import CNA
from app.models.cve import CVE

CNAFactory = Callable[..., Awaitable[CNA]]
CVEFactory = Callable[..., Awaitable[CVE]]

_ORG_ID = uuid.UUID("00000000-0000-4000-8000-0000000000a1")

_DOCUMENTED_COLUMNS = {
    "id",
    "org_id",
    "short_name",
    "short_name_observed_at",
    "organization_name",
    "types",
    "scope",
    "auto_ignore",
    "created_at",
    "updated_at",
}

# Documented VARCHAR lengths (docs/data-model.md, CNA).
_COLUMN_LENGTHS = {"short_name": 32, "organization_name": 256}


@pytest.mark.integration
class TestCNACreation:
    async def test_create_with_defaults(self, db_session: AsyncSession) -> None:
        cna = CNA(org_id=_ORG_ID)
        db_session.add(cna)
        await db_session.flush()
        await db_session.refresh(cna)

        assert cna.id.version == 7
        assert cna.org_id == _ORG_ID
        assert cna.short_name is None
        assert cna.short_name_observed_at is None
        assert cna.organization_name is None
        assert cna.types == []
        assert cna.scope is None
        assert cna.auto_ignore is False
        assert cna.created_at.tzinfo is not None
        assert cna.updated_at.tzinfo is not None

    async def test_create_with_every_column(
        self, db_session: AsyncSession, cna_factory: CNAFactory
    ) -> None:
        observed = datetime(2099, 1, 2, 3, 4, 5, tzinfo=UTC)
        cna = await cna_factory(
            org_id=_ORG_ID,
            short_name="example",
            short_name_observed_at=observed,
            organization_name="Example Corporation",
            types=["Open Source", "Vendor"],
            scope="Example Corporation products only.\nNothing else.",
            auto_ignore=True,
        )
        cna_id = cna.id
        db_session.expunge(cna)

        reloaded = await db_session.get(CNA, cna_id)
        assert reloaded is not None
        assert reloaded.short_name == "example"
        assert reloaded.short_name_observed_at == observed
        assert reloaded.organization_name == "Example Corporation"
        assert reloaded.types == ["Open Source", "Vendor"]
        assert reloaded.scope == "Example Corporation products only.\nNothing else."
        assert reloaded.auto_ignore is True

    async def test_raw_insert_applies_server_defaults(
        self, db_session: AsyncSession
    ) -> None:
        """A raw SQL INSERT bypasses every Python-side default, so the
        `uuidv7()`, `'[]'`, `false`, and `now()` server defaults must
        supply the columns."""
        row = (
            await db_session.execute(
                text(
                    "INSERT INTO cna (org_id) VALUES (:org_id) "
                    "RETURNING id, types, auto_ignore, created_at, updated_at"
                ),
                {"org_id": _ORG_ID},
            )
        ).one()

        assert isinstance(row.id, uuid.UUID)
        assert row.id.version == 7
        assert row.types == []
        assert row.auto_ignore is False
        assert row.created_at.tzinfo is not None
        assert row.updated_at == row.created_at


@pytest.mark.unit
class TestCNASchemaShape:
    def test_columns_match_documented_set(self) -> None:
        assert set(CNA.__table__.columns.keys()) == _DOCUMENTED_COLUMNS

    def test_no_check_constraint_or_standalone_index(self) -> None:
        """docs/data-model.md (CNA): no index beyond the primary key and the
        `org_id` unique constraint."""
        table = CNA.metadata.tables["cna"]

        assert not [c for c in table.constraints if isinstance(c, CheckConstraint)]
        assert table.indexes == set()

    def test_cve_cna_id_is_an_indexed_restrict_foreign_key(self) -> None:
        table = CVE.metadata.tables["cve"]
        column = table.c.cna_id
        (foreign_key,) = column.foreign_keys

        assert column.nullable is True
        assert foreign_key.target_fullname == "cna.id"
        assert foreign_key.ondelete == "RESTRICT"
        indexes = {
            index.name
            for index in table.indexes
            if [c.name for c in index.columns] == ["cna_id"]
        }

        assert indexes == {"ix_cve_cna_id"}


@pytest.mark.integration
class TestCNAConstraints:
    async def test_duplicate_org_id_rejected(
        self, db_session: AsyncSession, cna_factory: CNAFactory
    ) -> None:
        await cna_factory(org_id=_ORG_ID)
        db_session.add(CNA(org_id=_ORG_ID))

        with pytest.raises(IntegrityError, match="cna_org_id_key"):
            await db_session.flush()

    @pytest.mark.parametrize(
        "column", ["org_id", "types", "auto_ignore", "created_at", "updated_at"]
    )
    async def test_explicit_null_rejected(
        self, db_session: AsyncSession, column: str
    ) -> None:
        """A Core INSERT with an explicit SQL NULL bypasses the ORM, which
        would otherwise omit a `None` server-defaulted column (and would
        write a JSON `null`, not SQL `NULL`, for `None` in `types`)."""
        values: dict[str, object] = {"org_id": _ORG_ID, column: null()}

        with pytest.raises(IntegrityError, match="not-null"):
            await db_session.execute(insert(CNA).values(values))

    @pytest.mark.parametrize(("column", "length"), list(_COLUMN_LENGTHS.items()))
    async def test_documented_maximum_accepted(
        self, cna_factory: CNAFactory, column: str, length: int
    ) -> None:
        cna = await cna_factory(**{column: "a" * length})

        assert len(getattr(cna, column)) == length

    @pytest.mark.parametrize(("column", "length"), list(_COLUMN_LENGTHS.items()))
    async def test_value_over_documented_maximum_rejected(
        self, cna_factory: CNAFactory, column: str, length: int
    ) -> None:
        # asyncpg surfaces the truncation as a generic DBAPIError.
        with pytest.raises(DBAPIError, match="value too long"):
            await cna_factory(**{column: "a" * (length + 1)})


@pytest.mark.integration
class TestCVEReference:
    async def test_cve_references_its_cna(
        self,
        db_session: AsyncSession,
        cna_factory: CNAFactory,
        cve_factory: CVEFactory,
    ) -> None:
        cna = await cna_factory()
        cve = await cve_factory(cna_id=cna.id)
        await db_session.refresh(cve, ["cna"])

        assert cve.cna is cna

    async def test_cve_without_cna_is_null(self, cve_factory: CVEFactory) -> None:
        cve = await cve_factory()

        assert cve.cna_id is None

    async def test_unknown_cna_rejected(
        self, db_session: AsyncSession, cve_factory: CVEFactory
    ) -> None:
        with pytest.raises(IntegrityError, match="cve_cna_id_fkey"):
            await cve_factory(cna_id=uuid.uuid7())

    async def test_referenced_cna_cannot_be_deleted(
        self,
        db_session: AsyncSession,
        cna_factory: CNAFactory,
        cve_factory: CVEFactory,
    ) -> None:
        """ON DELETE RESTRICT: CNA rows are retained (cna.md, The CNA
        Entity)."""
        cna = await cna_factory()
        await cve_factory(cna_id=cna.id)

        with pytest.raises(IntegrityError, match="cve_cna_id_fkey"):
            await db_session.execute(delete(CNA).where(CNA.id == cna.id))

    async def test_cna_id_can_be_replaced(
        self,
        db_session: AsyncSession,
        cna_factory: CNAFactory,
        cve_factory: CVEFactory,
    ) -> None:
        """A transfer of the record replaces the reference."""
        first, second = await cna_factory(), await cna_factory()
        cve = await cve_factory(cna_id=first.id)

        await db_session.execute(
            update(CVE).where(CVE.id == cve.id).values(cna_id=second.id)
        )
        await db_session.refresh(cve)

        assert cve.cna_id == second.id
