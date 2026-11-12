"""add avatar_url to user

Revision ID: 24109dcbef28
Revises: 7d1b4ce4cc79
Create Date: 2026-11-12 16:05:23.440125

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "24109dcbef28"
down_revision: str | None = "7d1b4ce4cc79"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade database schema.

    See `docs/data-model.md` (User) and
    `docs/features/identity/user-avatars.md` (Avatar URL) for the full
    contract. Adds the picture URL as a nullable `VARCHAR(2048)` without a
    default: every existing user has no picture until the next run of
    `sync_slack_avatars`.
    """
    op.add_column(
        "user",
        sa.Column("avatar_url", sa.String(length=2048), nullable=True),
    )


def downgrade() -> None:
    """Downgrade database schema.

    Drops the picture URL; the previous schema cannot represent it.
    """
    op.drop_column("user", "avatar_url")
