"""add CNA audit event and the cna_policy ignore reason

Creates the `cna_audit_event` table documented in `docs/data-model.md`
(CNAAuditEvent): the `AuditEventMixin` columns with their `created_at` and
`user_id` indexes, `cna_id` as a NOT NULL FK to `cna.id` ON DELETE RESTRICT
with the non-unique index `ix_cna_audit_event_cna_id`, `event_type`,
`old_value`, `new_value`, and `detail`. Recreates
`chk_ticket_ignore_reason_valid` with the TicketIgnoreReason value
`cna_policy` (docs/data-model.md, TicketIgnoreReason Enum;
docs/features/tickets/cna.md, Auto-Ignore Policy).

Revision ID: bd5d2327569b
Revises: b169c9f216f2
Create Date: 2026-11-09 18:08:11.000000

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "bd5d2327569b"
down_revision: str | None = "b169c9f216f2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_IGNORE_REASON_VALID = "chk_ticket_ignore_reason_valid"


def upgrade() -> None:
    """Upgrade database schema.

    No existing row changes: no Ticket holds `cna_policy` before this
    revision, and no CNA audit event exists.
    """
    op.create_table(
        "cna_audit_event",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuidv7()"), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("user_id", sa.UUID(), nullable=True),
        sa.Column("cna_id", sa.UUID(), nullable=False),
        sa.Column("event_type", sa.String(length=50), nullable=False),
        sa.Column("old_value", sa.Text(), nullable=True),
        sa.Column("new_value", sa.Text(), nullable=True),
        sa.Column("detail", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.ForeignKeyConstraint(["cna_id"], ["cna.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_cna_audit_event_created_at", "cna_audit_event", ["created_at"])
    op.create_index("ix_cna_audit_event_user_id", "cna_audit_event", ["user_id"])
    op.create_index("ix_cna_audit_event_cna_id", "cna_audit_event", ["cna_id"])

    op.drop_constraint(_IGNORE_REASON_VALID, "ticket", type_="check")
    op.create_check_constraint(
        _IGNORE_REASON_VALID,
        "ticket",
        "ignore_reason IN ('not_shipped', 'cve_rejected', 'cna_policy', 'other')",
    )


def downgrade() -> None:
    """Downgrade database schema.

    The previous schema cannot represent `cna_policy`: a Ticket ignored with
    it receives `other`, so it stays `Ignored` with a reason that never
    reopens it automatically, as the reason it had. Drops the CNA audit
    trail; every CNA keeps its `auto_ignore` value.
    """
    op.execute(
        "UPDATE ticket SET ignore_reason = 'other' WHERE ignore_reason = 'cna_policy'"
    )
    op.drop_constraint(_IGNORE_REASON_VALID, "ticket", type_="check")
    op.create_check_constraint(
        _IGNORE_REASON_VALID,
        "ticket",
        "ignore_reason IN ('not_shipped', 'cve_rejected', 'other')",
    )

    op.drop_index("ix_cna_audit_event_cna_id", table_name="cna_audit_event")
    op.drop_index("ix_cna_audit_event_user_id", table_name="cna_audit_event")
    op.drop_index("ix_cna_audit_event_created_at", table_name="cna_audit_event")
    op.drop_table("cna_audit_event")
