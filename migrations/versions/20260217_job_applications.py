"""add job applications and assigned_at

Revision ID: 20260217_job_applications
Revises: 85d3a56153be
Create Date: 2026-02-17 18:40:00
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


# revision identifiers, used by Alembic.
revision = '20260217_job_applications'
down_revision = '85d3a56153be'
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = inspect(bind)

    if 'job_application' not in inspector.get_table_names():
        op.create_table(
            'job_application',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('order_id', sa.Integer(), nullable=False),
            sa.Column('writer_user_id', sa.Integer(), nullable=False),
            sa.Column('cover_note', sa.Text(), nullable=True),
            sa.Column('status', sa.String(length=20), nullable=False, server_default='pending'),
            sa.Column('created_at', sa.DateTime(), nullable=True),
            sa.Column('reviewed_at', sa.DateTime(), nullable=True),
            sa.ForeignKeyConstraint(['order_id'], ['order.id']),
            sa.ForeignKeyConstraint(['writer_user_id'], ['user.id']),
            sa.PrimaryKeyConstraint('id'),
            sa.UniqueConstraint('order_id', 'writer_user_id', name='uq_job_application_order_writer')
        )

    order_columns = {col['name'] for col in inspector.get_columns('order')} if 'order' in inspector.get_table_names() else set()
    if 'assigned_at' not in order_columns:
        op.add_column('order', sa.Column('assigned_at', sa.DateTime(), nullable=True))


def downgrade():
    bind = op.get_bind()
    inspector = inspect(bind)

    if 'order' in inspector.get_table_names():
        order_columns = {col['name'] for col in inspector.get_columns('order')}
        if 'assigned_at' in order_columns:
            with op.batch_alter_table('order') as batch_op:
                batch_op.drop_column('assigned_at')

    if 'job_application' in inspector.get_table_names():
        op.drop_table('job_application')
