"""add analyses table

Revision ID: 0001
Revises:
Create Date: 2026-04-28

"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "analyses",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("policy_hash", sa.String(length=64), nullable=False),
        sa.Column("policy_json", sa.Text(), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("findings_json", sa.Text(), nullable=False),
        sa.Column("suggestions_json", sa.Text(), nullable=False),
        sa.Column("graph_data_json", sa.Text(), nullable=False),
    )
    op.create_index("ix_analyses_policy_hash", "analyses", ["policy_hash"])


def downgrade() -> None:
    op.drop_index("ix_analyses_policy_hash", table_name="analyses")
    op.drop_table("analyses")
