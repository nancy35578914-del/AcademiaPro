"""add order pricing and admin publish flow columns

Revision ID: 20260218_order_pricing_and_publish_flow
Revises: 20260217_support_tickets
Create Date: 2026-02-18 00:20:00
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect, text


revision = "20260218_order_pricing_and_publish_flow"
down_revision = "20260217_support_tickets"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    if "order" not in inspector.get_table_names():
        return

    cols = {c["name"] for c in inspector.get_columns("order")}
    if "task_type" not in cols:
        op.add_column("order", sa.Column("task_type", sa.String(length=60), nullable=True))
    if "price" not in cols:
        op.add_column("order", sa.Column("price", sa.Float(), nullable=True))
    if "job_posted" not in cols:
        op.add_column("order", sa.Column("job_posted", sa.Boolean(), nullable=False, server_default=sa.false()))

    bind.execute(text("UPDATE \"order\" SET job_posted = 1 WHERE status = 'Open'"))


def downgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    if "order" not in inspector.get_table_names():
        return
    cols = {c["name"] for c in inspector.get_columns("order")}
    with op.batch_alter_table("order") as batch_op:
        if "job_posted" in cols:
            batch_op.drop_column("job_posted")
        if "price" in cols:
            batch_op.drop_column("price")
        if "task_type" in cols:
            batch_op.drop_column("task_type")
