"""constrain ticket coordinated release not before creation

Revision ID: e1c8a6f82708
Revises: 24059622568d
Create Date: 2026-11-07 01:00:26.991377

"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e1c8a6f82708"
down_revision: str | None = "24059622568d"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade database schema."""
    op.create_check_constraint(
        "chk_ticket_coordinated_release_not_before_creation",
        "ticket",
        "coordinated_release_at IS NULL OR coordinated_release_at >= created_at",
    )


def downgrade() -> None:
    """Downgrade database schema."""
    op.drop_constraint(
        "chk_ticket_coordinated_release_not_before_creation", "ticket", type_="check"
    )
