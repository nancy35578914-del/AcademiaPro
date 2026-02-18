from flask import Flask
from flask_mail import Mail
from app.extensions import db, login_manager, migrate
from app.models import User, Message, Application, Writer
from flask_login import current_user
from sqlalchemy import inspect, text
from werkzeug.security import generate_password_hash

mail = Mail()

def create_app():
    app = Flask(__name__)
    app.config.from_object("config.Config")
    login_manager.init_app(app)

    # Email configuration
    app.config.setdefault('MAIL_SERVER', 'smtp.gmail.com')
    app.config.setdefault('MAIL_PORT', 587)
    app.config.setdefault('MAIL_USE_TLS', True)
    app.config.setdefault('MAIL_USERNAME', '')
    app.config.setdefault('MAIL_PASSWORD', '')
    app.config.setdefault('MAIL_DEFAULT_SENDER', app.config.get('MAIL_USERNAME') or 'noreply@academicpro.local')

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    migrate.init_app(app, db)
    mail.init_app(app)

    with app.app_context():
        # Best-effort compatibility for existing SQLite deployments where
        # model fields/tables were added without a matching migration chain.
        db.create_all()
        inspector = inspect(db.engine)
        if "order" in inspector.get_table_names():
            order_columns = {col["name"] for col in inspector.get_columns("order")}
            if "assigned_at" not in order_columns:
                db.session.execute(text("ALTER TABLE \"order\" ADD COLUMN assigned_at DATETIME"))
                db.session.commit()
            if "task_type" not in order_columns:
                db.session.execute(text("ALTER TABLE \"order\" ADD COLUMN task_type VARCHAR(60)"))
                db.session.commit()
            if "price" not in order_columns:
                db.session.execute(text("ALTER TABLE \"order\" ADD COLUMN price FLOAT"))
                db.session.commit()
            if "job_posted" not in order_columns:
                db.session.execute(text("ALTER TABLE \"order\" ADD COLUMN job_posted BOOLEAN DEFAULT 0 NOT NULL"))
                db.session.commit()
            order_additions = [
                ("citation_style", "ALTER TABLE \"order\" ADD COLUMN citation_style VARCHAR(30)"),
                ("sources_count", "ALTER TABLE \"order\" ADD COLUMN sources_count INTEGER"),
                ("currency", "ALTER TABLE \"order\" ADD COLUMN currency VARCHAR(10)"),
                ("timezone", "ALTER TABLE \"order\" ADD COLUMN timezone VARCHAR(50)"),
            ]
            for col_name, sql in order_additions:
                if col_name not in order_columns:
                    try:
                        db.session.execute(text(sql))
                        db.session.commit()
                    except Exception:
                        db.session.rollback()
        if "message" in inspector.get_table_names():
            message_columns = {col["name"] for col in inspector.get_columns("message")}
            if "is_read" not in message_columns:
                db.session.execute(text("ALTER TABLE message ADD COLUMN is_read BOOLEAN DEFAULT 0 NOT NULL"))
                db.session.commit()
        if "user" in inspector.get_table_names():
            user_columns = {col["name"] for col in inspector.get_columns("user")}
            if "role" not in user_columns:
                db.session.execute(text("ALTER TABLE user ADD COLUMN role VARCHAR(20) DEFAULT 'client' NOT NULL"))
                db.session.commit()
            user_additions = [
                ("phone", "ALTER TABLE user ADD COLUMN phone VARCHAR(30)"),
                ("academic_level", "ALTER TABLE user ADD COLUMN academic_level VARCHAR(50)"),
                ("expertise_tags", "ALTER TABLE user ADD COLUMN expertise_tags VARCHAR(255)"),
                ("two_factor_enabled", "ALTER TABLE user ADD COLUMN two_factor_enabled BOOLEAN DEFAULT 0 NOT NULL"),
                ("profile_public", "ALTER TABLE user ADD COLUMN profile_public BOOLEAN DEFAULT 1 NOT NULL"),
                ("notify_email", "ALTER TABLE user ADD COLUMN notify_email BOOLEAN DEFAULT 1 NOT NULL"),
                ("notify_sms", "ALTER TABLE user ADD COLUMN notify_sms BOOLEAN DEFAULT 0 NOT NULL"),
                ("notify_in_app", "ALTER TABLE user ADD COLUMN notify_in_app BOOLEAN DEFAULT 1 NOT NULL"),
                ("alert_order_updates", "ALTER TABLE user ADD COLUMN alert_order_updates BOOLEAN DEFAULT 1 NOT NULL"),
                ("alert_payment_confirmations", "ALTER TABLE user ADD COLUMN alert_payment_confirmations BOOLEAN DEFAULT 1 NOT NULL"),
                ("alert_revision_requests", "ALTER TABLE user ADD COLUMN alert_revision_requests BOOLEAN DEFAULT 1 NOT NULL"),
                ("alert_admin_announcements", "ALTER TABLE user ADD COLUMN alert_admin_announcements BOOLEAN DEFAULT 1 NOT NULL"),
                ("billing_method", "ALTER TABLE user ADD COLUMN billing_method VARCHAR(50)"),
                ("payout_method", "ALTER TABLE user ADD COLUMN payout_method VARCHAR(50)"),
                ("auto_deposit_notifications", "ALTER TABLE user ADD COLUMN auto_deposit_notifications BOOLEAN DEFAULT 0 NOT NULL"),
                ("preferred_language", "ALTER TABLE user ADD COLUMN preferred_language VARCHAR(50)"),
                ("timezone", "ALTER TABLE user ADD COLUMN timezone VARCHAR(50)"),
                ("preferred_channel", "ALTER TABLE user ADD COLUMN preferred_channel VARCHAR(30)"),
                ("layout_mode", "ALTER TABLE user ADD COLUMN layout_mode VARCHAR(20)"),
                ("citation_style", "ALTER TABLE user ADD COLUMN citation_style VARCHAR(30)"),
                ("favorite_writers", "ALTER TABLE user ADD COLUMN favorite_writers VARCHAR(255)"),
                ("marketing_opt_in", "ALTER TABLE user ADD COLUMN marketing_opt_in BOOLEAN DEFAULT 0 NOT NULL"),
            ]
            for col_name, sql in user_additions:
                if col_name not in user_columns:
                    try:
                        db.session.execute(text(sql))
                        db.session.commit()
                    except Exception:
                        db.session.rollback()
        if "writer" in inspector.get_table_names():
            writer_columns = {col["name"] for col in inspector.get_columns("writer")}
            if "degree" not in writer_columns:
                db.session.execute(text("ALTER TABLE writer ADD COLUMN degree VARCHAR(120)"))
                db.session.commit()
            if "years_experience" not in writer_columns:
                db.session.execute(text("ALTER TABLE writer ADD COLUMN years_experience INTEGER"))
                db.session.commit()
            if "portfolio_url" not in writer_columns:
                db.session.execute(text("ALTER TABLE writer ADD COLUMN portfolio_url VARCHAR(255)"))
                db.session.commit()
            if "rating" not in writer_columns:
                db.session.execute(text("ALTER TABLE writer ADD COLUMN rating FLOAT"))
                db.session.commit()
            if "portfolio_file" not in writer_columns:
                db.session.execute(text("ALTER TABLE writer ADD COLUMN portfolio_file VARCHAR(255)"))
                db.session.commit()
            if "resume_file" not in writer_columns:
                db.session.execute(text("ALTER TABLE writer ADD COLUMN resume_file VARCHAR(255)"))
                db.session.commit()
        if "application" in inspector.get_table_names():
            app_columns = {col["name"] for col in inspector.get_columns("application")}
            app_additions = [
                ("education_level", "ALTER TABLE application ADD COLUMN education_level VARCHAR(50)"),
                ("years_experience", "ALTER TABLE application ADD COLUMN years_experience INTEGER"),
                ("writing_styles", "ALTER TABLE application ADD COLUMN writing_styles VARCHAR(255)"),
                ("portfolio_file", "ALTER TABLE application ADD COLUMN portfolio_file VARCHAR(255)"),
                ("accept_terms", "ALTER TABLE application ADD COLUMN accept_terms BOOLEAN DEFAULT 0 NOT NULL"),
            ]
            for col_name, sql in app_additions:
                if col_name not in app_columns:
                    try:
                        db.session.execute(text(sql))
                        db.session.commit()
                    except Exception:
                        db.session.rollback()
        if "order_review" not in inspector.get_table_names():
            try:
                db.session.execute(text(
                    "CREATE TABLE order_review ("
                    "id INTEGER PRIMARY KEY, "
                    "order_id INTEGER NOT NULL, "
                    "writer_id INTEGER NOT NULL, "
                    "user_id INTEGER NOT NULL, "
                    "rating INTEGER NOT NULL, "
                    "comment TEXT, "
                    "created_at DATETIME, "
                    "FOREIGN KEY(order_id) REFERENCES \"order\"(id), "
                    "FOREIGN KEY(writer_id) REFERENCES writer(id), "
                    "FOREIGN KEY(user_id) REFERENCES user(id))"
                ))
                db.session.commit()
            except Exception:
                db.session.rollback()
        if "sample" in inspector.get_table_names():
            sample_columns = {col["name"] for col in inspector.get_columns("sample")}
            sample_additions = [
                ("style", "ALTER TABLE sample ADD COLUMN style VARCHAR(50)"),
                ("level", "ALTER TABLE sample ADD COLUMN level VARCHAR(50)"),
                ("subject", "ALTER TABLE sample ADD COLUMN subject VARCHAR(100)"),
                ("grade", "ALTER TABLE sample ADD COLUMN grade VARCHAR(50)"),
                ("published_at", "ALTER TABLE sample ADD COLUMN published_at DATETIME"),
                ("source_url", "ALTER TABLE sample ADD COLUMN source_url VARCHAR(255)"),
                ("file_type", "ALTER TABLE sample ADD COLUMN file_type VARCHAR(20)"),
                ("file_name", "ALTER TABLE sample ADD COLUMN file_name VARCHAR(255)"),
            ]
            for col_name, sql in sample_additions:
                if col_name not in sample_columns:
                    try:
                        db.session.execute(text(sql))
                        db.session.commit()
                    except Exception:
                        db.session.rollback()
        admin_emails = {e.strip().lower() for e in app.config.get("ADMIN_EMAILS", []) if e.strip()}
        if admin_emails:
            users = User.query.filter(User.email.in_(list(admin_emails))).all()
            for user in users:
                user.role = "admin"
            if users:
                db.session.commit()
        bootstrap_email = app.config.get("ADMIN_BOOTSTRAP_EMAIL", "")
        bootstrap_password = app.config.get("ADMIN_BOOTSTRAP_PASSWORD", "")
        if bootstrap_email and bootstrap_password:
            admin = User.query.filter_by(email=bootstrap_email).first()
            if not admin:
                admin = User(email=bootstrap_email, name="Admin", password_hash=generate_password_hash(bootstrap_password), role="admin")
                db.session.add(admin)
            else:
                admin.password_hash = generate_password_hash(bootstrap_password)
                admin.role = "admin"
            db.session.commit()

    @app.context_processor
    def inject_user():
        unread_count = 0
        writer_enabled = False
        if getattr(current_user, "is_authenticated", False):
            try:
                unread_count = Message.query.filter_by(receiver_id=current_user.id, is_read=False).count()
                writer_enabled = bool(
                    Application.query.filter_by(email=current_user.email, approved=True).first()
                    or Writer.query.filter_by(name=current_user.name, approved=True).first()
                )
            except Exception:
                unread_count = 0
                writer_enabled = False
        return dict(current_user=current_user, unread_count=unread_count, writer_enabled=writer_enabled)

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    # Register Blueprints
    from app.routes import main
    app.register_blueprint(main)

    return app  # ✅ this must be inside the create_app() function
