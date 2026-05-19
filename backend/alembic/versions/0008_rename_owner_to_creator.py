"""Rename org role 'owner' to 'creator', introduce 'manager'.

Revision ID: 0008
Revises: 0007
Create Date: 2026-05-19

"""
from __future__ import annotations

from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("UPDATE memberships SET role = 'creator' WHERE role = 'owner'")


def downgrade() -> None:
    op.execute("UPDATE memberships SET role = 'owner' WHERE role = 'creator'")
