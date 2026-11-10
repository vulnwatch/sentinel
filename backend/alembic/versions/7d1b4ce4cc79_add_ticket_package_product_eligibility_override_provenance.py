"""add ticket package product eligibility override provenance

Adds the override provenance of a Product's eligibility: who set the
current override (`eligibility_override_by_id`, FK to `user.id` ON DELETE
RESTRICT, not indexed) and when (`eligibility_override_at`), with
`chk_ticket_package_product_eligibility_override_provenance`, which
requires both exactly when `is_eligible_override` is true
(docs/data-model.md, TicketPackageProduct;
docs/features/packages/package-model.md, Override Model).

Revision ID: 7d1b4ce4cc79
Revises: bd5d2327569b
Create Date: 2026-11-10 01:14:00.315558

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "7d1b4ce4cc79"
down_revision: str | None = "bd5d2327569b"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade database schema.

    No backfill: the provenance has no source outside audit history, so the
    CHECK fails the upgrade, which leaves the database at the previous
    revision, when an occurrence holds an override.
    """
    op.add_column(
        "ticket_package_product",
        sa.Column(
            "eligibility_override_by_id",
            sa.UUID(),
            sa.ForeignKey("user.id", ondelete="RESTRICT"),
            nullable=True,
        ),
    )
    op.add_column(
        "ticket_package_product",
        sa.Column("eligibility_override_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_check_constraint(
        "chk_ticket_package_product_eligibility_override_provenance",
        "ticket_package_product",
        "(is_eligible_override = false "
        "AND eligibility_override_by_id IS NULL "
        "AND eligibility_override_at IS NULL) "
        "OR (is_eligible_override = true "
        "AND eligibility_override_by_id IS NOT NULL "
        "AND eligibility_override_at IS NOT NULL)",
    )


def downgrade() -> None:
    """Downgrade database schema.

    Drops the constraint and both columns, with the foreign key of
    `eligibility_override_by_id`; the previous schema cannot represent the
    provenance, and every override is kept.
    """
    op.drop_constraint(
        "chk_ticket_package_product_eligibility_override_provenance",
        "ticket_package_product",
        type_="check",
    )
    op.drop_column("ticket_package_product", "eligibility_override_at")
    op.drop_column("ticket_package_product", "eligibility_override_by_id")
