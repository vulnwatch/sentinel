"""Integration tests for the MaintainedPackage model
(backend/app/models/maintained_package.py).

See docs/data-model.md (MaintainedPackage) and
docs/features/packages/maintained-package-names.md (Data Model). Only the
persistence contract is covered here; the publication and the search are
service behavior (`tests/test_services/test_packages/test_maintained_package_names.py`).
"""

from __future__ import annotations

import pytest
from sqlalchemy import insert, select, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.maintained_package import MaintainedPackage


@pytest.mark.integration
class TestMaintainedPackage:
    async def test_create_with_defaults(self, db_session: AsyncSession) -> None:
        package = MaintainedPackage(name="fictional-openssl-3")
        db_session.add(package)
        await db_session.flush()

        assert package.id.version == 7
        assert package.created_at.tzinfo is not None
        assert not hasattr(package, "updated_at")

    async def test_raw_insert_applies_server_defaults(
        self, db_session: AsyncSession
    ) -> None:
        row = (
            await db_session.execute(
                text(
                    "INSERT INTO maintained_package (name) VALUES ('fictional-zlib') "
                    "RETURNING id, created_at"
                )
            )
        ).one()

        assert row.id.version == 7
        assert row.created_at is not None

    async def test_names_that_differ_only_in_case_are_distinct(
        self, db_session: AsyncSession
    ) -> None:
        await db_session.execute(
            insert(MaintainedPackage),
            [{"name": "python-FictionalTable"}, {"name": "python-fictionaltable"}],
        )

        names = (await db_session.scalars(select(MaintainedPackage.name))).all()
        assert sorted(names) == ["python-FictionalTable", "python-fictionaltable"]

    async def test_duplicate_name_is_rejected(self, db_session: AsyncSession) -> None:
        db_session.add(MaintainedPackage(name="fictional-curl"))
        await db_session.flush()

        db_session.add(MaintainedPackage(name="fictional-curl"))
        with pytest.raises(IntegrityError):
            await db_session.flush()

    async def test_name_longer_than_255_characters_is_rejected(
        self, db_session: AsyncSession
    ) -> None:
        db_session.add(MaintainedPackage(name="a" * 256))
        with pytest.raises(DBAPIError, match="too long"):
            await db_session.flush()
