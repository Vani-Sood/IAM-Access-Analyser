"""Make org_id nullable on api_keys and webhooks (orgs feature removed).

Revision ID: 0009
Revises: 0008
Create Date: 2026-05-19

"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column("api_keys", "org_id", existing_type=sa.Integer(), nullable=True)
    op.alter_column("webhooks", "org_id", existing_type=sa.Integer(), nullable=True)


def downgrade() -> None:
    op.alter_column("api_keys", "org_id", existing_type=sa.Integer(), nullable=False)
    op.alter_column("webhooks", "org_id", existing_type=sa.Integer(), nullable=False)
