"""add email verification and otp code table

Revision ID: 20260218_user_verification_otp
Revises: 20260218_blog_ai_content_fields
Create Date: 2026-02-18 19:05:00
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = "20260218_user_verification_otp"
down_revision = "20260218_blog_ai_content_fields"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = inspect(bind)

    if "user" in inspector.get_table_names():
      cols = {c["name"] for c in inspector.get_columns("user")}
      if "email_verified" not in cols:
          op.add_column("user", sa.Column("email_verified", sa.Boolean(), nullable=False, server_default=sa.false()))

    if "otp_code" not in inspector.get_table_names():
        op.create_table(
            "otp_code",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("user_id", sa.Integer(), nullable=True),
            sa.Column("email", sa.String(length=120), nullable=False),
            sa.Column("purpose", sa.String(length=40), nullable=False),
            sa.Column("code", sa.String(length=8), nullable=False),
            sa.Column("is_used", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("expires_at", sa.DateTime(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(["user_id"], ["user.id"]),
        )
        op.create_index("ix_otp_code_email", "otp_code", ["email"], unique=False)
        op.create_index("ix_otp_code_purpose", "otp_code", ["purpose"], unique=False)


def downgrade():
    bind = op.get_bind()
    inspector = inspect(bind)

    if "otp_code" in inspector.get_table_names():
        idx = {i["name"] for i in inspector.get_indexes("otp_code")}
        if "ix_otp_code_email" in idx:
            op.drop_index("ix_otp_code_email", table_name="otp_code")
        if "ix_otp_code_purpose" in idx:
            op.drop_index("ix_otp_code_purpose", table_name="otp_code")
        op.drop_table("otp_code")

    if "user" in inspector.get_table_names():
        cols = {c["name"] for c in inspector.get_columns("user")}
        if "email_verified" in cols:
            op.drop_column("user", "email_verified")
