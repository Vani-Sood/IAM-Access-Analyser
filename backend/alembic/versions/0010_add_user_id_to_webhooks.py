"""Add user_id to webhooks and make org_id nullable.

Revision ID: 0010
Revises: 0009
Create Date: 2026-05-19

"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "webhooks",
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("webhooks", "user_id")
