"""add CNA table and CVE cna_id

Creates the `cna` table documented in `docs/data-model.md` (CNA): a UUIDv7
primary key, the UNIQUE `org_id` that is the public identity of a CNA, the
short name and its observation date written by ingestion, the organization
name, types (JSONB, default `[]`), and scope of the CNA list, and
`auto_ignore` (default false). Adds `cve.cna_id`, the CNA that owns the CVE
Record, as a nullable FK to `cna.id` ON DELETE RESTRICT with the non-unique
index `ix_cve_cna_id` (docs/data-model.md, CVE, Indexes;
docs/features/tickets/cna.md, CNA of a CVE).

Revision ID: b169c9f216f2
Revises: 57504b9961b3
Create Date: 2026-11-09 15:10:00.000000

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b169c9f216f2"
down_revision: str | None = "57504b9961b3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade database schema.

    No backfill: only a later ingestion of a CVE's record supplies its owner,
    so every existing CVE keeps `cna_id = NULL`, as a CVE does until such an
    ingestion (cna.md, CNA of a CVE).
    """
    op.create_table(
        "cna",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuidv7()"), nullable=False),
        sa.Column("org_id", sa.UUID(), nullable=False),
        sa.Column("short_name", sa.String(length=32), nullable=True),
        sa.Column("short_name_observed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("organization_name", sa.String(length=256), nullable=True),
        sa.Column(
            "types",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column("scope", sa.Text(), nullable=True),
        sa.Column(
            "auto_ignore", sa.Boolean(), server_default=sa.false(), nullable=False
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("org_id"),
    )
    op.add_column(
        "cve",
        sa.Column(
            "cna_id",
            sa.UUID(),
            sa.ForeignKey("cna.id", ondelete="RESTRICT"),
            nullable=True,
        ),
    )
    op.create_index("ix_cve_cna_id", "cve", ["cna_id"], unique=False)


def downgrade() -> None:
    """Downgrade database schema.

    Drops the index, `cve.cna_id` with its foreign key, and the `cna`
    table; the previous schema cannot represent the CNA of a CVE, and every
    CVE is kept.
    """
    op.drop_index("ix_cve_cna_id", table_name="cve")
    op.drop_column("cve", "cna_id")
    op.drop_table("cna")
