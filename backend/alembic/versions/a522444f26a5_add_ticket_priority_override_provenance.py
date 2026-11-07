"""add ticket priority override provenance

Adds the override provenance of the Ticket priority: who set the current
override (`priority_override_by_id`, FK to `user.id` ON DELETE RESTRICT, not
indexed) and when (`priority_override_at`), with
`chk_ticket_priority_override_provenance`, which requires both exactly when
`priority_override` is set (docs/data-model.md, Ticket;
docs/features/tickets/ticket-priority.md, Persistence and Effective
Priority).

Revision ID: a522444f26a5
Revises: e1c8a6f82708
Create Date: 2026-11-07 17:49:19.953536

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a522444f26a5"
down_revision: str | None = "e1c8a6f82708"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade database schema.

    No backfill: the provenance has no source outside audit history, so the
    CHECK fails the upgrade, which leaves the database at the previous
    revision, when a Ticket holds an override.
    """
    op.add_column(
        "ticket",
        sa.Column(
            "priority_override_by_id",
            sa.UUID(),
            sa.ForeignKey("user.id", ondelete="RESTRICT"),
            nullable=True,
        ),
    )
    op.add_column(
        "ticket",
        sa.Column("priority_override_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_check_constraint(
        "chk_ticket_priority_override_provenance",
        "ticket",
        "(priority_override IS NULL AND priority_override_by_id IS NULL "
        "AND priority_override_at IS NULL) "
        "OR (priority_override IS NOT NULL "
        "AND priority_override_by_id IS NOT NULL "
        "AND priority_override_at IS NOT NULL)",
    )


def downgrade() -> None:
    """Downgrade database schema.

    Drops the constraint and both columns, with the foreign key of
    `priority_override_by_id`; the previous schema cannot represent the
    provenance, and every override is kept.
    """
    op.drop_constraint(
        "chk_ticket_priority_override_provenance", "ticket", type_="check"
    )
    op.drop_column("ticket", "priority_override_at")
    op.drop_column("ticket", "priority_override_by_id")
