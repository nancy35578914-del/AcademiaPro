import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev_secret_key")
    SQLALCHEMY_DATABASE_URI = os.environ.get("SQLALCHEMY_DATABASE_URI", "sqlite:///your.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    ADMIN_EMAILS = [
        e.strip().lower()
        for e in os.environ.get(
            "ADMIN_EMAILS",
            "bwamistevenez001@gmail.com,bwamistevenez@gmail.com",
        ).split(",")
        if e.strip()
    ]
    ADMIN_BOOTSTRAP_EMAIL = os.environ.get("ADMIN_BOOTSTRAP_EMAIL", "").strip().lower()
    ADMIN_BOOTSTRAP_PASSWORD = os.environ.get("ADMIN_BOOTSTRAP_PASSWORD", "")
    RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "").strip()
    RESEND_FROM_EMAIL = os.environ.get("RESEND_FROM_EMAIL", "").strip()
    EMAIL_OTP_ENABLED = os.environ.get("EMAIL_OTP_ENABLED", "false").strip().lower() in ("1", "true", "yes", "on")
    AUTO_ASSIGN_ADMIN_EMAILS = os.environ.get("AUTO_ASSIGN_ADMIN_EMAILS", "false").strip().lower() in ("1", "true", "yes", "on")

LOGIN_MESSAGE = "You must log in to access this page."
LOGIN_MESSAGE_CATEGORY = "warning"
