"""add sample metadata fields and file reference

Revision ID: 20260218_sample_metadata_fields
Revises: 20260218_user_settings_expansion
Create Date: 2026-02-18 02:10:00
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = "20260218_sample_metadata_fields"
down_revision = "20260218_user_settings_expansion"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    if "sample" not in inspector.get_table_names():
        return
    cols = {c["name"] for c in inspector.get_columns("sample")}
    add_ops = [
        ("style", sa.String(length=50), True),
        ("level", sa.String(length=50), True),
        ("subject", sa.String(length=100), True),
        ("grade", sa.String(length=50), True),
        ("published_at", sa.DateTime(), True),
        ("source_url", sa.String(length=255), True),
        ("file_type", sa.String(length=20), True),
        ("file_name", sa.String(length=255), True),
    ]
    for name, typ, nullable in add_ops:
        if name in cols:
            continue
        op.add_column("sample", sa.Column(name, typ, nullable=nullable))


def downgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    if "sample" not in inspector.get_table_names():
        return
    cols = {c["name"] for c in inspector.get_columns("sample")}
    drop_names = [
        "file_name",
        "file_type",
        "source_url",
        "published_at",
        "grade",
        "subject",
        "level",
        "style",
    ]
    with op.batch_alter_table("sample") as batch_op:
        for name in drop_names:
            if name in cols:
                batch_op.drop_column(name)
