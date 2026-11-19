"""add maintained_package table

Creates the `maintained_package` table documented in `docs/data-model.md`
(MaintainedPackage): the names of the latest published snapshot of the source
package names that SMELT maintains, with UNIQUE `name`, no `updated_at`, no
foreign key, and no further index
(`docs/features/packages/maintained-package-names.md`, Data Model).

Revision ID: 68d13447760b
Revises: 24109dcbef28
Create Date: 2026-11-19 18:54:07.294675

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "68d13447760b"
down_revision: str | None = "24109dcbef28"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade database schema.

    The table starts empty: the search returns no name until the first
    `sync_smelt_packages` run publishes a snapshot.
    """
    op.create_table(
        "maintained_package",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuidv7()"), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )


def downgrade() -> None:
    """Downgrade database schema.

    Drops the snapshot; the next `sync_smelt_packages` run after a
    re-upgrade publishes it again.
    """
    op.drop_table("maintained_package")
