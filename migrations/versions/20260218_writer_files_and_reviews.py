"""add writer portfolio/resume files and order reviews

Revision ID: 20260218_writer_files_and_reviews
Revises: 20260218_order_detail_fields
Create Date: 2026-02-18 03:05:00
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = "20260218_writer_files_and_reviews"
down_revision = "20260218_order_detail_fields"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    if "writer" in inspector.get_table_names():
        cols = {c["name"] for c in inspector.get_columns("writer")}
        if "portfolio_file" not in cols:
            op.add_column("writer", sa.Column("portfolio_file", sa.String(length=255), nullable=True))
        if "resume_file" not in cols:
            op.add_column("writer", sa.Column("resume_file", sa.String(length=255), nullable=True))

    if "order_review" not in inspector.get_table_names():
        op.create_table(
            "order_review",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("order_id", sa.Integer(), nullable=False),
            sa.Column("writer_id", sa.Integer(), nullable=False),
            sa.Column("user_id", sa.Integer(), nullable=False),
            sa.Column("rating", sa.Integer(), nullable=False),
            sa.Column("comment", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=True),
            sa.ForeignKeyConstraint(["order_id"], ["order.id"]),
            sa.ForeignKeyConstraint(["writer_id"], ["writer.id"]),
            sa.ForeignKeyConstraint(["user_id"], ["user.id"]),
            sa.PrimaryKeyConstraint("id"),
        )


def downgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    if "order_review" in inspector.get_table_names():
        op.drop_table("order_review")
    if "writer" in inspector.get_table_names():
        cols = {c["name"] for c in inspector.get_columns("writer")}
        with op.batch_alter_table("writer") as batch_op:
            if "resume_file" in cols:
                batch_op.drop_column("resume_file")
            if "portfolio_file" in cols:
                batch_op.drop_column("portfolio_file")
