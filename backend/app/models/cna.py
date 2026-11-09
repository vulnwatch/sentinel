"""CNA model — a CVE Numbering Authority that owns CVE Records.

See `docs/data-model.md` (CNA) and `docs/features/tickets/cna.md` (CNA of a
CVE, The CNA Entity, Short Name, Auto-Ignore Policy) for the full
specification. This module implements only the persistence root; the
ingestion writes, the metadata synchronization, the policy operation, and
the reads belong to `cna_service`.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, String, Text, false, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.cve import CVE


class CNA(Base):
    """One CVE Services organization that owns, or has owned, the record of
    an ingested CVE.

    `org_id` is the public identity and never changes; `id` is internal and
    never exposed. Ingestion creates the row and maintains `short_name` and
    `short_name_observed_at`; the CNA list synchronization writes
    `organization_name`, `types`, and `scope`; only the administrative
    operation writes `auto_ignore`. Rows are retained, never deleted, also
    when a transfer leaves a CNA without a CVE.
    """

    __tablename__ = "cna"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid7,
        server_default=text("uuidv7()"),
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), unique=True, nullable=False
    )
    short_name: Mapped[str | None] = mapped_column(String(32), nullable=True)
    short_name_observed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    organization_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    types: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb")
    )
    scope: Mapped[str | None] = mapped_column(Text, nullable=True)
    auto_ignore: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=false()
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    # passive_deletes="all": CNA rows are retained and `cve.cna_id` uses
    # ON DELETE RESTRICT. Without it SQLAlchemy would null the `cna_id` of
    # loaded CVEs before deleting the CNA; the database FK must reject the
    # delete instead.
    cves: Mapped[list[CVE]] = relationship(
        "CVE", back_populates="cna", passive_deletes="all"
    )
