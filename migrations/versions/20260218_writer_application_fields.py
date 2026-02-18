"""add writer application vetting fields

Revision ID: 20260218_writer_application_fields
Revises: 20260218_sample_metadata_fields
Create Date: 2026-02-18 02:35:00
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = "20260218_writer_application_fields"
down_revision = "20260218_sample_metadata_fields"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    if "application" not in inspector.get_table_names():
        return
    cols = {c["name"] for c in inspector.get_columns("application")}
    add_ops = [
        ("education_level", sa.String(length=50), True),
        ("years_experience", sa.Integer(), True),
        ("writing_styles", sa.String(length=255), True),
        ("portfolio_file", sa.String(length=255), True),
        ("accept_terms", sa.Boolean(), False),
    ]
    for name, typ, nullable in add_ops:
        if name in cols:
            continue
        kwargs = {"nullable": nullable}
        if name == "accept_terms":
            kwargs["server_default"] = sa.false()
        op.add_column("application", sa.Column(name, typ, **kwargs))


def downgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    if "application" not in inspector.get_table_names():
        return
    cols = {c["name"] for c in inspector.get_columns("application")}
    drop_names = ["accept_terms", "portfolio_file", "writing_styles", "years_experience", "education_level"]
    with op.batch_alter_table("application") as batch_op:
        for name in drop_names:
            if name in cols:
                batch_op.drop_column(name)
