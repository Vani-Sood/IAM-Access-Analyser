"""add task status to analyses

Revision ID: 0003
Revises: 0002
Create Date: 2026-04-28

"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "analyses",
        sa.Column("status", sa.String(16), nullable=False, server_default="completed"),
    )
    op.add_column(
        "analyses",
        sa.Column("task_id", sa.String(255), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("analyses", "task_id")
    op.drop_column("analyses", "status")
