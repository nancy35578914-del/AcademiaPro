"""seed admin credentials and role

Revision ID: 20260217_admin_credentials_seed
Revises: 20260217_user_role
Create Date: 2026-02-17 23:35:00
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect, text
from werkzeug.security import generate_password_hash
from datetime import datetime


revision = "20260217_admin_credentials_seed"
down_revision = "20260217_user_role"
branch_labels = None
depends_on = None


ADMIN_EMAIL = "bwamistevenez001@gmail.com"
ADMIN_NAME = "Admin"
ADMIN_PASSWORD = "bwami.007j"


def upgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    if "user" not in inspector.get_table_names():
        return

    cols = {c["name"] for c in inspector.get_columns("user")}
    if not {"email", "name", "password_hash", "role"}.issubset(cols):
        return

    admin_exists = bind.execute(
        text("SELECT id FROM user WHERE lower(email)=:email"),
        {"email": ADMIN_EMAIL},
    ).fetchone()

    hashed = generate_password_hash(ADMIN_PASSWORD)
    if admin_exists:
        bind.execute(
            text(
                "UPDATE user SET role='admin', password_hash=:password_hash "
                "WHERE lower(email)=:email"
            ),
            {"password_hash": hashed, "email": ADMIN_EMAIL},
        )
    else:
        bind.execute(
            text(
                "INSERT INTO user (email, name, password_hash, role, created_at) "
                "VALUES (:email, :name, :password_hash, 'admin', :created_at)"
            ),
            {
                "email": ADMIN_EMAIL,
                "name": ADMIN_NAME,
                "password_hash": hashed,
                "created_at": datetime.utcnow(),
            },
        )


def downgrade():
    # Keep account data intact on downgrade.
    pass
