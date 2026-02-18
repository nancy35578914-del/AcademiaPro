"""add order detail fields for citation, sources, currency, timezone

Revision ID: 20260218_order_detail_fields
Revises: 20260218_writer_application_fields
Create Date: 2026-02-18 02:50:00
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = "20260218_order_detail_fields"
down_revision = "20260218_writer_application_fields"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    if "order" not in inspector.get_table_names():
        return
    cols = {c["name"] for c in inspector.get_columns("order")}
    add_ops = [
        ("citation_style", sa.String(length=30), True),
        ("sources_count", sa.Integer(), True),
        ("currency", sa.String(length=10), True),
        ("timezone", sa.String(length=50), True),
    ]
    for name, typ, nullable in add_ops:
        if name in cols:
            continue
        op.add_column("order", sa.Column(name, typ, nullable=nullable))


def downgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    if "order" not in inspector.get_table_names():
        return
    cols = {c["name"] for c in inspector.get_columns("order")}
    drop_names = ["timezone", "currency", "sources_count", "citation_style"]
    with op.batch_alter_table("order") as batch_op:
        for name in drop_names:
            if name in cols:
                batch_op.drop_column(name)
