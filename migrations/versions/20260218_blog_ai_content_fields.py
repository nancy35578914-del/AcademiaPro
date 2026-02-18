"""add blog metadata fields and ai conversation table

Revision ID: 20260218_blog_ai_content_fields
Revises: 20260218_writer_files_and_reviews
Create Date: 2026-02-18 18:10:00
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = "20260218_blog_ai_content_fields"
down_revision = "20260218_writer_files_and_reviews"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = inspect(bind)

    if "blog_post" in inspector.get_table_names():
        cols = {c["name"] for c in inspector.get_columns("blog_post")}
        if "excerpt" not in cols:
            op.add_column("blog_post", sa.Column("excerpt", sa.Text(), nullable=True))
        if "category" not in cols:
            op.add_column("blog_post", sa.Column("category", sa.String(length=80), nullable=False, server_default="Academic Skills"))
        if "pillar" not in cols:
            op.add_column("blog_post", sa.Column("pillar", sa.String(length=120), nullable=True))
        if "cluster_topic" not in cols:
            op.add_column("blog_post", sa.Column("cluster_topic", sa.String(length=120), nullable=True))
        if "author_id" not in cols:
            op.add_column("blog_post", sa.Column("author_id", sa.Integer(), nullable=True))
        if "author_name" not in cols:
            op.add_column("blog_post", sa.Column("author_name", sa.String(length=120), nullable=True))
        if "is_published" not in cols:
            op.add_column("blog_post", sa.Column("is_published", sa.Boolean(), nullable=False, server_default=sa.text("1")))
        if "updated_at" not in cols:
            op.add_column("blog_post", sa.Column("updated_at", sa.DateTime(), nullable=True))

    if "ai_conversation_message" not in inspector.get_table_names():
        op.create_table(
            "ai_conversation_message",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("user_id", sa.Integer(), nullable=True),
            sa.Column("guest_thread_id", sa.String(length=64), nullable=True),
            sa.Column("role", sa.String(length=20), nullable=False),
            sa.Column("content", sa.Text(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=True),
            sa.ForeignKeyConstraint(["user_id"], ["user.id"]),
        )
        op.create_index("ix_ai_conversation_message_guest_thread_id", "ai_conversation_message", ["guest_thread_id"], unique=False)
        op.create_index("ix_ai_conversation_message_created_at", "ai_conversation_message", ["created_at"], unique=False)


def downgrade():
    bind = op.get_bind()
    inspector = inspect(bind)

    if "ai_conversation_message" in inspector.get_table_names():
        idx = {i["name"] for i in inspector.get_indexes("ai_conversation_message")}
        if "ix_ai_conversation_message_guest_thread_id" in idx:
            op.drop_index("ix_ai_conversation_message_guest_thread_id", table_name="ai_conversation_message")
        if "ix_ai_conversation_message_created_at" in idx:
            op.drop_index("ix_ai_conversation_message_created_at", table_name="ai_conversation_message")
        op.drop_table("ai_conversation_message")

    if "blog_post" in inspector.get_table_names():
        cols = {c["name"] for c in inspector.get_columns("blog_post")}
        for col in ["updated_at", "is_published", "author_name", "author_id", "cluster_topic", "pillar", "category", "excerpt"]:
            if col in cols:
                op.drop_column("blog_post", col)
