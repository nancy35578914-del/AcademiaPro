from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from flask import current_app
from app.extensions import db

class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    sender = db.Column(db.String(20), nullable=False, default="user")  # 'user' or 'admin'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            "id": self.id,
            "content": self.content,
            "sender": self.sender,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S") if self.timestamp else None
        }

class Testimonial(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    content = db.Column(db.Text)
    rating = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Lead(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    topic = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Writer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    subject = db.Column(db.String(100))
    degree = db.Column(db.String(120), nullable=True)
    years_experience = db.Column(db.Integer, nullable=True)
    portfolio_url = db.Column(db.String(255), nullable=True)
    portfolio_file = db.Column(db.String(255), nullable=True)
    resume_file = db.Column(db.String(255), nullable=True)
    rating = db.Column(db.Float, nullable=True)
    image_url = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    approved = db.Column(db.Boolean, default=False)

class Settings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    image_url = db.Column(db.String(255))

class SiteReview(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reviewer = db.Column(db.String(100), nullable=False)
    comment = db.Column(db.Text, nullable=False)
    stars = db.Column(db.Integer, nullable=False)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(50), nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="client")
    email_verified = db.Column(db.Boolean, default=False, nullable=False)
    phone = db.Column(db.String(30), nullable=True)
    academic_level = db.Column(db.String(50), nullable=True)
    expertise_tags = db.Column(db.String(255), nullable=True)
    two_factor_enabled = db.Column(db.Boolean, default=False, nullable=False)
    profile_public = db.Column(db.Boolean, default=True, nullable=False)
    notify_email = db.Column(db.Boolean, default=True, nullable=False)
    notify_sms = db.Column(db.Boolean, default=False, nullable=False)
    notify_in_app = db.Column(db.Boolean, default=True, nullable=False)
    alert_order_updates = db.Column(db.Boolean, default=True, nullable=False)
    alert_payment_confirmations = db.Column(db.Boolean, default=True, nullable=False)
    alert_revision_requests = db.Column(db.Boolean, default=True, nullable=False)
    alert_admin_announcements = db.Column(db.Boolean, default=True, nullable=False)
    billing_method = db.Column(db.String(50), nullable=True)
    payout_method = db.Column(db.String(50), nullable=True)
    auto_deposit_notifications = db.Column(db.Boolean, default=False, nullable=False)
    preferred_language = db.Column(db.String(50), nullable=True, default="English")
    timezone = db.Column(db.String(50), nullable=True, default="UTC")
    preferred_channel = db.Column(db.String(30), nullable=True, default="chat")
    layout_mode = db.Column(db.String(20), nullable=True, default="detailed")
    citation_style = db.Column(db.String(30), nullable=True, default="APA")
    favorite_writers = db.Column(db.String(255), nullable=True)
    marketing_opt_in = db.Column(db.Boolean, default=False, nullable=False)
    photo = db.Column(db.String(120), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    orders = db.relationship('Order', backref='user', lazy=True)

    @property
    def is_admin(self):
        role = (getattr(self, "role", "") or "").strip().lower()
        if role == "admin":
            return True
        email = (self.email or "").strip().lower()
        default_admins = {"bwamistevenez001@gmail.com", "bwamistevenez@gmail.com"}
        try:
            configured = set(current_app.config.get("ADMIN_EMAILS", []))
        except Exception:
            configured = set()
        return email in (configured or default_admins)

    @property
    def is_writer(self):
        role = (getattr(self, "role", "") or "").strip().lower()
        return role == "writer"

    def set_password(self, password):
        from werkzeug.security import generate_password_hash
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        from werkzeug.security import check_password_hash
        return check_password_hash(self.password_hash, password)
     
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, nullable=False)
    receiver_id = db.Column(db.Integer, nullable=False)
    content = db.Column(db.Text, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(100))
    amount = db.Column(db.Float)
    method = db.Column(db.String(50))
    status = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class SiteSetting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=False)

class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    body = db.Column(db.Text, nullable=False)
    audience = db.Column(db.String(20), nullable=False)
    category = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class PublicPage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(50), unique=True, nullable=False)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    topic = db.Column(db.String(255), nullable=False)
    task_type = db.Column(db.String(60), nullable=True)
    description = db.Column(db.Text, nullable=False)
    citation_style = db.Column(db.String(30), nullable=True)
    sources_count = db.Column(db.Integer, nullable=True)
    currency = db.Column(db.String(10), nullable=True, default="USD")
    timezone = db.Column(db.String(50), nullable=True, default="UTC")
    deadline = db.Column(db.DateTime, nullable=False)
    word_count = db.Column(db.Integer, nullable=False)
    level = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=True)
    job_posted = db.Column(db.Boolean, default=False, nullable=False)
    status = db.Column(db.String(50), default="Pending")
    writer_id = db.Column(db.Integer, db.ForeignKey("writer.id"))
    assigned_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


class JobApplication(db.Model):
    __table_args__ = (
        db.UniqueConstraint("order_id", "writer_user_id", name="uq_job_application_order_writer"),
    )
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey("order.id"), nullable=False)
    writer_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    cover_note = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), default="pending", nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    reviewed_at = db.Column(db.DateTime, nullable=True)

def calculate_price(word_count, level, deadline):
    base_rate = 0.05
    urgency_multiplier = 2.0 if (deadline - datetime.utcnow()).days <= 1 else 1.0
    level_multiplier = {"Undergrad": 1.0, "Masters": 1.5, "PhD": 2.0}.get(level, 1.0)
    return word_count * base_rate * urgency_multiplier * level_multiplier

class OrderFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    uploader = db.Column(db.String(50))
    order_id = db.Column(db.Integer, nullable=True)

class BlogPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    excerpt = db.Column(db.Text, nullable=True)
    category = db.Column(db.String(80), nullable=False, default="Academic Skills")
    pillar = db.Column(db.String(120), nullable=True)
    cluster_topic = db.Column(db.String(120), nullable=True)
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    author_name = db.Column(db.String(120), nullable=True)
    is_published = db.Column(db.Boolean, default=True, nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
class Sample(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    style = db.Column(db.String(50), nullable=True)
    level = db.Column(db.String(50), nullable=True)
    subject = db.Column(db.String(100), nullable=True)
    grade = db.Column(db.String(50), nullable=True)
    published_at = db.Column(db.DateTime, nullable=True)
    source_url = db.Column(db.String(255), nullable=True)
    file_type = db.Column(db.String(20), nullable=True)
    file_name = db.Column(db.String(255), nullable=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Application(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    bio = db.Column(db.Text, nullable=False)
    education_level = db.Column(db.String(50), nullable=True)
    years_experience = db.Column(db.Integer, nullable=True)
    writing_styles = db.Column(db.String(255), nullable=True)
    portfolio_file = db.Column(db.String(255), nullable=True)
    accept_terms = db.Column(db.Boolean, default=False, nullable=False)
    approved = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class SupportTicket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    order_id = db.Column(db.Integer, db.ForeignKey("order.id"), nullable=True)
    subject = db.Column(db.String(150), nullable=False)
    message = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(30), nullable=False, default="open")
    priority = db.Column(db.String(20), nullable=False, default="normal")
    admin_note = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class OrderReview(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey("order.id"), nullable=False)
    writer_id = db.Column(db.Integer, db.ForeignKey("writer.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class AIConversationMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    guest_thread_id = db.Column(db.String(64), nullable=True, index=True)
    role = db.Column(db.String(20), nullable=False)  # user | assistant
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class OTPCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    email = db.Column(db.String(120), nullable=False, index=True)
    purpose = db.Column(db.String(40), nullable=False, index=True)
    code = db.Column(db.String(8), nullable=False)
    is_used = db.Column(db.Boolean, default=False, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
