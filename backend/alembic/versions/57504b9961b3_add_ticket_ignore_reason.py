"""add ticket ignore reason

Adds `Ticket.ignore_reason` (TicketIgnoreReason, `VARCHAR(20)`, nullable,
not indexed) with `chk_ticket_ignore_reason_valid` and
`chk_ticket_ignore_reason_status_coherence`, which requires a reason exactly
while the Ticket is `Ignored` (docs/data-model.md, Ticket, TicketIgnoreReason
Enum; docs/features/tickets/tickets.md, Ignore Reason).

Revision ID: 57504b9961b3
Revises: a522444f26a5
Create Date: 2026-11-09 06:56:05.331300

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "57504b9961b3"
down_revision: str | None = "a522444f26a5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade database schema.

    Every Ticket that is already `Ignored` receives `cve_rejected` when its
    associated CVE is `REJECTED`, which keeps the reopen of a reverted
    rejection for it, and `other` otherwise; `not_shipped` is never
    inferred. No audit event is created and earlier events are unchanged
    (docs/features/tickets/tickets.md, Ignore Reason).
    """
    op.add_column(
        "ticket", sa.Column("ignore_reason", sa.String(length=20), nullable=True)
    )
    op.execute(
        "UPDATE ticket SET ignore_reason = CASE WHEN EXISTS ("
        "SELECT 1 FROM cve WHERE cve.id = ticket.cve_id "
        "AND cve.cve_state = 'REJECTED') "
        "THEN 'cve_rejected' ELSE 'other' END "
        "WHERE status = 'Ignored'"
    )
    op.create_check_constraint(
        "chk_ticket_ignore_reason_valid",
        "ticket",
        "ignore_reason IN ('not_shipped', 'cve_rejected', 'other')",
    )
    op.create_check_constraint(
        "chk_ticket_ignore_reason_status_coherence",
        "ticket",
        "(status = 'Ignored' AND ignore_reason IS NOT NULL) "
        "OR (status != 'Ignored' AND ignore_reason IS NULL)",
    )


def downgrade() -> None:
    """Downgrade database schema.

    Drops both constraints and the column; the previous schema cannot
    represent the reason, and every `Ignored` Ticket stays `Ignored`.
    """
    op.drop_constraint(
        "chk_ticket_ignore_reason_status_coherence", "ticket", type_="check"
    )
    op.drop_constraint("chk_ticket_ignore_reason_valid", "ticket", type_="check")
    op.drop_column("ticket", "ignore_reason")
