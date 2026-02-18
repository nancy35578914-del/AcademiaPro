from flask import Flask
from flask_mail import Mail
from app.extensions import db, login_manager, migrate
from app.models import User, Message, Application, Writer, BlogPost, AIConversationMessage, OTPCode
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
            if "email_verified" not in user_columns:
                try:
                    db.session.execute(text("ALTER TABLE user ADD COLUMN email_verified BOOLEAN DEFAULT 0 NOT NULL"))
                    db.session.commit()
                except Exception:
                    db.session.rollback()
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
        if "blog_post" in inspector.get_table_names():
            blog_columns = {col["name"] for col in inspector.get_columns("blog_post")}
            blog_additions = [
                ("excerpt", "ALTER TABLE blog_post ADD COLUMN excerpt TEXT"),
                ("category", "ALTER TABLE blog_post ADD COLUMN category VARCHAR(80) DEFAULT 'Academic Skills' NOT NULL"),
                ("pillar", "ALTER TABLE blog_post ADD COLUMN pillar VARCHAR(120)"),
                ("cluster_topic", "ALTER TABLE blog_post ADD COLUMN cluster_topic VARCHAR(120)"),
                ("author_id", "ALTER TABLE blog_post ADD COLUMN author_id INTEGER"),
                ("author_name", "ALTER TABLE blog_post ADD COLUMN author_name VARCHAR(120)"),
                ("is_published", "ALTER TABLE blog_post ADD COLUMN is_published BOOLEAN DEFAULT 1 NOT NULL"),
                ("updated_at", "ALTER TABLE blog_post ADD COLUMN updated_at DATETIME"),
            ]
            for col_name, sql in blog_additions:
                if col_name not in blog_columns:
                    try:
                        db.session.execute(text(sql))
                        db.session.commit()
                    except Exception:
                        db.session.rollback()
        if "ai_conversation_message" not in inspector.get_table_names():
            try:
                db.session.execute(text(
                    "CREATE TABLE ai_conversation_message ("
                    "id INTEGER PRIMARY KEY, "
                    "user_id INTEGER, "
                    "guest_thread_id VARCHAR(64), "
                    "role VARCHAR(20) NOT NULL, "
                    "content TEXT NOT NULL, "
                    "created_at DATETIME, "
                    "FOREIGN KEY(user_id) REFERENCES user(id))"
                ))
                db.session.commit()
            except Exception:
                db.session.rollback()
        if "otp_code" not in inspector.get_table_names():
            try:
                db.session.execute(text(
                    "CREATE TABLE otp_code ("
                    "id INTEGER PRIMARY KEY, "
                    "user_id INTEGER, "
                    "email VARCHAR(120) NOT NULL, "
                    "purpose VARCHAR(40) NOT NULL, "
                    "code VARCHAR(8) NOT NULL, "
                    "is_used BOOLEAN DEFAULT 0 NOT NULL, "
                    "expires_at DATETIME NOT NULL, "
                    "created_at DATETIME NOT NULL, "
                    "FOREIGN KEY(user_id) REFERENCES user(id))"
                ))
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

        if BlogPost.query.count() == 0:
            seed_posts = [
                BlogPost(
                    title="The Ultimate Guide to Mastering Grade 12 Exams",
                    excerpt="A practical framework for revision planning, mock strategy, and exam-day execution.",
                    category="Exam Strategy",
                    pillar="Grade 12 Mastery",
                    cluster_topic="Foundation",
                    author_name="AcademicPro Editorial Team",
                    is_published=True,
                    content=(
                        "Grade 12 exam success is rarely about studying longer. It is about studying with structure.\n\n"
                        "Start by building a subject map: list each subject, the weight of every unit, and your current confidence level. "
                        "Rank topics into three groups: strong, moderate, and weak. Your weekly plan should spend most time on weak areas while still revising strong ones to keep recall sharp.\n\n"
                        "Use a 3-cycle revision model.\n"
                        "Cycle 1: Concept review. Summarize each topic into one-page notes with definitions, formulas, and common traps.\n"
                        "Cycle 2: Active recall. Close notes and answer questions from memory, then check errors.\n"
                        "Cycle 3: Timed papers. Simulate exam conditions to train speed, calmness, and accuracy.\n\n"
                        "For each mock, run a post-mock audit. Record every error under one of these labels: knowledge gap, misread question, time pressure, or careless slip. "
                        "Fixing the error type is more effective than just redoing questions randomly.\n\n"
                        "In the final week, reduce new content. Focus on high-yield summaries, formula sheets, and repeated weak-question types. "
                        "Sleep consistency and short review blocks will help retention better than all-night sessions.\n\n"
                        "Exam day checklist: arrive early, read instructions once fully, allocate time per section before writing, and leave final minutes for targeted checking. "
                        "Discipline in execution often decides the final grade."
                    ),
                ),
                BlogPost(
                    title="8 Common Calculus Mistakes and How to Avoid Them",
                    excerpt="A mistake-by-mistake breakdown to improve marks quickly in derivatives, integrals, and limits.",
                    category="STEM Skills",
                    pillar="Grade 12 Mastery",
                    cluster_topic="Calculus",
                    author_name="AcademicPro Editorial Team",
                    is_published=True,
                    content=(
                        "Most calculus losses come from repeated patterns, not hard theory.\n\n"
                        "1) Sign errors during expansion. Slow down when distributing negatives and use one line per transformation.\n"
                        "2) Misusing chain rule. If a function is nested, include inner derivative every time.\n"
                        "3) Product/quotient confusion. Memorize form and keep numerator in brackets before simplifying.\n"
                        "4) Ignoring domain restrictions. Check values that make denominators zero or roots invalid.\n"
                        "5) Skipping constant of integration. Always add +C for indefinite integrals.\n"
                        "6) Poor limit notation. Show substitution and algebraic steps clearly to avoid logic gaps.\n"
                        "7) Unit blindness in applications. State units in rates, areas, and optimization outputs.\n"
                        "8) No verification pass. Re-differentiate antiderivatives and test critical points.\n\n"
                        "Build a personal error ledger. After each set, log mistake type, why it happened, and correction rule. "
                        "In 2-3 weeks, this approach can reduce avoidable losses dramatically."
                    ),
                ),
                BlogPost(
                    title="How to Write a Thesis Without Burnout",
                    excerpt="Use milestone planning, realistic writing targets, and feedback loops to finish strong.",
                    category="Research Writing",
                    pillar="Thesis Writing",
                    cluster_topic="Workflow",
                    author_name="AcademicPro Editorial Team",
                    is_published=True,
                    content=(
                        "Thesis burnout usually starts when planning is vague. Convert your thesis into concrete milestones: proposal, literature review, methods, results, discussion, final edits.\n\n"
                        "Set weekly deliverables with measurable outputs, such as words drafted, sources annotated, or figures finalized. "
                        "Avoid goals like 'work on chapter 2' and use 'complete section 2.1 with three cited sources'.\n\n"
                        "Use deep-work blocks of 60-90 minutes with short breaks. Protect two high-focus blocks each day for writing and one low-focus block for formatting, references, or admin tasks.\n\n"
                        "Build a supervisor feedback loop every 1-2 weeks. Smaller review cycles prevent major rewrites at the end.\n\n"
                        "When stuck, switch task type instead of forcing output. Move from drafting to outlining, or from analysis to source organization. "
                        "Momentum matters more than perfect flow.\n\n"
                        "Your final month should prioritize argument clarity, coherence between chapters, citation consistency, and formatting compliance. "
                        "A finished good draft is stronger than an unfinished perfect chapter."
                    ),
                ),
                BlogPost(
                    title="APA vs MLA vs Chicago: Practical Comparison for Students",
                    excerpt="Quick rules and examples to choose the right style and avoid formatting penalties.",
                    category="Citation & Integrity",
                    pillar="Citation Mastery",
                    cluster_topic="Style Comparison",
                    author_name="AcademicPro Editorial Team",
                    is_published=True,
                    content=(
                        "Choosing the right citation style depends on discipline and institutional guidelines.\n\n"
                        "APA is common in social sciences. It uses author-date citations and emphasizes publication year relevance.\n"
                        "MLA is frequent in humanities. It uses author-page citations and focuses on textual analysis.\n"
                        "Chicago appears in history and business contexts, often with notes-bibliography format.\n\n"
                        "Common penalties come from inconsistent in-text format, missing bibliography details, and incorrect capitalization rules.\n\n"
                        "Before writing, set your style once and keep a template for title page, headings, and references. "
                        "Use citation tools carefully and always validate output manually. Automated tools help speed, but human review ensures correctness.\n\n"
                        "Final check before submission: every in-text citation must match one reference entry, and every reference entry must be cited in text."
                    ),
                ),
                BlogPost(
                    title="Avoiding Plagiarism: A Student Guide to Safe Academic Writing",
                    excerpt="A practical method to paraphrase correctly, cite confidently, and protect originality.",
                    category="Citation & Integrity",
                    pillar="Citation Mastery",
                    cluster_topic="Plagiarism Prevention",
                    author_name="AcademicPro Editorial Team",
                    is_published=True,
                    content=(
                        "Plagiarism is often accidental when students copy structure or phrasing too closely.\n\n"
                        "Safe workflow:\n"
                        "1) Read source and close it.\n"
                        "2) Write idea in your own words from memory.\n"
                        "3) Reopen source to verify accuracy.\n"
                        "4) Add citation immediately.\n\n"
                        "Use direct quotes only for precise wording that must be preserved. Most academic writing should be paraphrased with attribution.\n\n"
                        "Track sources while drafting. Leaving citation to the end increases risk of lost references and weak attribution.\n\n"
                        "Before submission, run an originality check and inspect flagged sections manually. "
                        "Similarity is not automatically plagiarism; context matters, but uncited overlaps are always risky."
                    ),
                ),
                BlogPost(
                    title="Time Management for Exam Season: A 4-Week Plan",
                    excerpt="A realistic schedule framework to balance classes, revision, and recovery during peak pressure.",
                    category="Exam Strategy",
                    pillar="Grade 12 Mastery",
                    cluster_topic="Time Management",
                    author_name="AcademicPro Editorial Team",
                    is_published=True,
                    content=(
                        "Week 4: Build your plan. List all exams, topics, and current readiness. Assign daily blocks by priority.\n"
                        "Week 3: Start timed practice for high-weight subjects. Keep error logs after each session.\n"
                        "Week 2: Increase mixed-topic drills and memory recall sessions. Tighten weak topics.\n"
                        "Week 1: Reduce cognitive overload. Review summaries, formulas, and frequent error patterns.\n\n"
                        "Daily structure example:\n"
                        "Morning: high-focus study block.\n"
                        "Afternoon: practice questions and marking.\n"
                        "Evening: low-intensity recap and planning for next day.\n\n"
                        "Use a simple rule: do the most important difficult task first each day. "
                        "Consistency beats intensity, especially under exam pressure."
                    ),
                ),
            ]
            db.session.add_all(seed_posts)
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
