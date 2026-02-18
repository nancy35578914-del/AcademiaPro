"""add is_read to message

Revision ID: 20260217_message_is_read
Revises: 20260217_job_applications
Create Date: 2026-02-17 20:05:00
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = '20260217_message_is_read'
down_revision = '20260217_job_applications'
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    if 'message' in inspector.get_table_names():
        cols = {c['name'] for c in inspector.get_columns('message')}
        if 'is_read' not in cols:
            op.add_column('message', sa.Column('is_read', sa.Boolean(), nullable=False, server_default=sa.false()))


def downgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    if 'message' in inspector.get_table_names():
        cols = {c['name'] for c in inspector.get_columns('message')}
        if 'is_read' in cols:
            with op.batch_alter_table('message') as batch_op:
                batch_op.drop_column('is_read')
