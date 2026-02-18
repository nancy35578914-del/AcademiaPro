"""add extended writer profile fields

Revision ID: 20260218_writer_profile_fields
Revises: 20260218_order_pricing_and_publish_flow
Create Date: 2026-02-18 00:42:00
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = "20260218_writer_profile_fields"
down_revision = "20260218_order_pricing_and_publish_flow"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    if "writer" not in inspector.get_table_names():
        return
    cols = {c["name"] for c in inspector.get_columns("writer")}
    if "degree" not in cols:
        op.add_column("writer", sa.Column("degree", sa.String(length=120), nullable=True))
    if "years_experience" not in cols:
        op.add_column("writer", sa.Column("years_experience", sa.Integer(), nullable=True))
    if "portfolio_url" not in cols:
        op.add_column("writer", sa.Column("portfolio_url", sa.String(length=255), nullable=True))
    if "rating" not in cols:
        op.add_column("writer", sa.Column("rating", sa.Float(), nullable=True))


def downgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    if "writer" not in inspector.get_table_names():
        return
    cols = {c["name"] for c in inspector.get_columns("writer")}
    with op.batch_alter_table("writer") as batch_op:
        if "rating" in cols:
            batch_op.drop_column("rating")
        if "portfolio_url" in cols:
            batch_op.drop_column("portfolio_url")
        if "years_experience" in cols:
            batch_op.drop_column("years_experience")
        if "degree" in cols:
            batch_op.drop_column("degree")
