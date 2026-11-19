"""MaintainedPackage model — one name of the maintained package snapshot.

See `docs/data-model.md` (MaintainedPackage) and
`docs/features/packages/maintained-package-names.md` (Data Model) for the
full specification. This module implements only the persistence; the
publication and the search belong to
`app.services.packages.maintained_package_names`.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, String, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class MaintainedPackage(Base):
    """One source package name of the latest published SMELT snapshot.

    `name` is kept exactly as SMELT returns it and is unique under exact
    comparison, so two names that differ only in letter case are two rows.
    `created_at` is when the name last entered the snapshot. Rows are only
    inserted and deleted by the publication boundary, never updated, so the
    table has no `updated_at` (`docs/data-model.md`, Notes). No other table
    references it.
    """

    __tablename__ = "maintained_package"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid7,
        server_default=text("uuidv7()"),
    )
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
