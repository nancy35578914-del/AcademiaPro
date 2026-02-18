"""add role column to user and backfill roles

Revision ID: 20260217_user_role
Revises: 20260217_message_is_read
Create Date: 2026-02-17 21:25:00
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect, text


revision = "20260217_user_role"
down_revision = "20260217_message_is_read"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    if "user" not in inspector.get_table_names():
        return

    user_columns = {c["name"] for c in inspector.get_columns("user")}
    if "role" not in user_columns:
        op.add_column(
            "user",
            sa.Column("role", sa.String(length=20), nullable=False, server_default="client"),
        )

    # Keep admin access stable for known admin accounts.
    bind.execute(
        text(
            "UPDATE user SET role='admin' "
            "WHERE lower(email) IN ('bwamistevenez001@gmail.com', 'bwamistevenez@gmail.com')"
        )
    )

    # Promote approved writer applicants to writer role.
    if "application" in inspector.get_table_names():
        bind.execute(
            text(
                "UPDATE user SET role='writer' "
                "WHERE role <> 'admin' AND lower(email) IN "
                "(SELECT lower(email) FROM application WHERE approved = 1)"
            )
        )


def downgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    if "user" not in inspector.get_table_names():
        return
    user_columns = {c["name"] for c in inspector.get_columns("user")}
    if "role" in user_columns:
        with op.batch_alter_table("user") as batch_op:
            batch_op.drop_column("role")
