"""expand user settings/preferences fields

Revision ID: 20260218_user_settings_expansion
Revises: 20260218_writer_profile_fields
Create Date: 2026-02-18 01:20:00
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = "20260218_user_settings_expansion"
down_revision = "20260218_writer_profile_fields"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    if "user" not in inspector.get_table_names():
        return
    cols = {c["name"] for c in inspector.get_columns("user")}
    add_ops = [
        ("phone", sa.String(length=30), True, None),
        ("academic_level", sa.String(length=50), True, None),
        ("expertise_tags", sa.String(length=255), True, None),
        ("two_factor_enabled", sa.Boolean(), False, sa.false()),
        ("profile_public", sa.Boolean(), False, sa.true()),
        ("notify_email", sa.Boolean(), False, sa.true()),
        ("notify_sms", sa.Boolean(), False, sa.false()),
        ("notify_in_app", sa.Boolean(), False, sa.true()),
        ("alert_order_updates", sa.Boolean(), False, sa.true()),
        ("alert_payment_confirmations", sa.Boolean(), False, sa.true()),
        ("alert_revision_requests", sa.Boolean(), False, sa.true()),
        ("alert_admin_announcements", sa.Boolean(), False, sa.true()),
        ("billing_method", sa.String(length=50), True, None),
        ("payout_method", sa.String(length=50), True, None),
        ("auto_deposit_notifications", sa.Boolean(), False, sa.false()),
        ("preferred_language", sa.String(length=50), True, "English"),
        ("timezone", sa.String(length=50), True, "UTC"),
        ("preferred_channel", sa.String(length=30), True, "chat"),
        ("layout_mode", sa.String(length=20), True, "detailed"),
        ("citation_style", sa.String(length=30), True, "APA"),
        ("favorite_writers", sa.String(length=255), True, None),
        ("marketing_opt_in", sa.Boolean(), False, sa.false()),
    ]
    for name, typ, nullable, default in add_ops:
        if name in cols:
            continue
        kwargs = {"nullable": nullable}
        if default is not None:
            kwargs["server_default"] = default if not isinstance(default, str) else sa.text(f"'{default}'")
        op.add_column("user", sa.Column(name, typ, **kwargs))


def downgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    if "user" not in inspector.get_table_names():
        return
    cols = {c["name"] for c in inspector.get_columns("user")}
    drop_names = [
        "marketing_opt_in",
        "favorite_writers",
        "citation_style",
        "layout_mode",
        "preferred_channel",
        "timezone",
        "preferred_language",
        "auto_deposit_notifications",
        "payout_method",
        "billing_method",
        "alert_admin_announcements",
        "alert_revision_requests",
        "alert_payment_confirmations",
        "alert_order_updates",
        "notify_in_app",
        "notify_sms",
        "notify_email",
        "profile_public",
        "two_factor_enabled",
        "expertise_tags",
        "academic_level",
        "phone",
    ]
    with op.batch_alter_table("user") as batch_op:
        for name in drop_names:
            if name in cols:
                batch_op.drop_column(name)
