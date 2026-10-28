"""add bot to user

Revision ID: 24059622568d
Revises: 6636db334eb1
Create Date: 2026-10-28 12:48:09.055135

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "24059622568d"
down_revision: str | None = "6636db334eb1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade database schema.

    See `docs/data-model.md` (User) and
    `docs/features/identity/user-management.md` (Bot Accounts) for the full
    contract. Adds the bot marker as `BOOLEAN NOT NULL DEFAULT false`.
    Because a non-null column is added to a populated table, the server
    default is required; every existing user reads `false`, with no
    backfill or inference.
    """
    op.add_column(
        "user",
        sa.Column(
            "bot",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )


def downgrade() -> None:
    """Downgrade database schema.

    Drops the bot marker; the previous schema cannot represent it.
    """
    op.drop_column("user", "bot")
