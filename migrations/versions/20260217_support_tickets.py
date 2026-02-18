"""add support ticket model

Revision ID: 20260217_support_tickets
Revises: 20260217_admin_credentials_seed
Create Date: 2026-02-17 23:58:00
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = "20260217_support_tickets"
down_revision = "20260217_admin_credentials_seed"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    if "support_ticket" in inspector.get_table_names():
        return
    op.create_table(
        "support_ticket",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("order_id", sa.Integer(), nullable=True),
        sa.Column("subject", sa.String(length=150), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False, server_default="open"),
        sa.Column("priority", sa.String(length=20), nullable=False, server_default="normal"),
        sa.Column("admin_note", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["order_id"], ["order.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    if "support_ticket" in inspector.get_table_names():
        op.drop_table("support_ticket")
