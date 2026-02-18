from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, current_app, abort, send_from_directory, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from functools import wraps
import os
import re
import uuid
import random
import json
import urllib.request
import urllib.error

from app.extensions import db, login_manager
from app.forms import OrderForm, RegistrationForm, LoginForm, ProfileForm, SettingForm, ApplicationForm
from app.models import (
    BlogPost, Sample, User, Testimonial, Lead, Writer, SiteReview, ChatMessage, Message,
    Announcement, Order, OrderFile, Application, JobApplication, Payment, SiteSetting, SupportTicket, OrderReview,
    AIConversationMessage, OTPCode, calculate_price
)
from flask_mail import Message as MailMessage
from app import mail
from sqlalchemy.exc import IntegrityError

main = Blueprint("main", __name__)
JOB_TAKEN_ANNOUNCEMENT_TTL_HOURS = 12
GUEST_THREAD_TAG = "[GUEST_THREAD:"
SUPPORT_CHAT_TAG = "[Support]"
AI_THREAD_TAG = "ai_guest_thread_id"


def _otp_enabled():
    return bool(current_app.config.get("EMAIL_OTP_ENABLED", False))


def _get_guest_thread_id():
    thread_id = session.get("guest_thread_id")
    if not thread_id:
        thread_id = uuid.uuid4().hex[:16]
        session["guest_thread_id"] = thread_id
    return thread_id


def _get_ai_guest_thread_id():
    thread_id = session.get(AI_THREAD_TAG)
    if not thread_id:
        thread_id = uuid.uuid4().hex[:20]
        session[AI_THREAD_TAG] = thread_id
    return thread_id


def _guest_thread_prefix(thread_id):
    return f"{GUEST_THREAD_TAG}{thread_id}]"


def _extract_guest_thread_id(content):
    match = re.search(r"\[GUEST_THREAD:([a-f0-9]{8,32})\]", content or "", re.IGNORECASE)
    if match:
        return match.group(1).lower()
    return None


def _strip_tag(content, tag_pattern):
    return re.sub(tag_pattern, "", content or "").strip()


def _order_access_context(order):
    approved_app = JobApplication.query.filter_by(order_id=order.id, status="approved").first()
    allowed_ids = {order.user_id}
    if approved_app:
        allowed_ids.add(approved_app.writer_user_id)
    if current_user.is_admin:
        allowed_ids.add(current_user.id)
    return approved_app, allowed_ids


def _cleanup_taken_job_announcements():
    cutoff = datetime.utcnow() - timedelta(hours=JOB_TAKEN_ANNOUNCEMENT_TTL_HOURS)
    stale = Announcement.query.filter(
        Announcement.category == "jobs_taken",
        Announcement.created_at < cutoff
    ).all()
    if stale:
        for row in stale:
            db.session.delete(row)
        db.session.commit()


def _job_id_from_announcement_title(title):
    match = re.match(r"^JOB#(\d+)\b", title or "")
    return int(match.group(1)) if match else None


def _is_approved_writer(user):
    if not user or not user.is_authenticated:
        return False
    if getattr(user, "is_writer", False):
        return True
    approved_application = Application.query.filter_by(email=user.email, approved=True).first()
    approved_writer = Writer.query.filter_by(name=user.name, approved=True).first()
    return bool(approved_application or approved_writer)


def _get_primary_admin():
    admin_emails = [e for e in current_app.config.get("ADMIN_EMAILS", []) if e]
    for email in admin_emails:
        admin = User.query.filter_by(email=email).first()
        if admin:
            return admin
    return User.query.filter_by(role="admin").order_by(User.id.asc()).first()


def _send_mail_safely(message):
    resend_api_key = (current_app.config.get("RESEND_API_KEY") or "").strip()
    resend_from = (current_app.config.get("RESEND_FROM_EMAIL") or current_app.config.get("MAIL_DEFAULT_SENDER") or "").strip()
    recipients = getattr(message, "recipients", None) or []
    to_email = recipients[0] if recipients else None
    if resend_api_key and resend_from and to_email:
        payload = {
            "from": resend_from,
            "to": [to_email],
            "subject": message.subject,
            "text": message.body or "",
        }
        req = urllib.request.Request(
            "https://api.resend.com/emails",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {resend_api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                raw = resp.read().decode("utf-8") if resp else "{}"
                data = json.loads(raw or "{}")
                message_id = data.get("id")
                current_app.logger.info("Resend email delivered", extra={"resend_message_id": message_id, "to": to_email})
                return True
        except urllib.error.HTTPError as err:
            error_body = err.read().decode("utf-8", errors="ignore") if err else ""
            current_app.logger.error("Resend API HTTP error: %s %s", getattr(err, "code", "unknown"), error_body)
            return False
        except Exception:
            current_app.logger.exception("Resend API send failed.")
            return False

    # SMTP fallback only when Resend is not configured.
    try:
        mail.send(message)
        current_app.logger.info("SMTP email delivered", extra={"to": to_email})
        return True
    except Exception:
        current_app.logger.exception("SMTP mail send failed.")
        return False


def _generate_otp_code():
    return f"{random.randint(0, 999999):06d}"


def _issue_otp(email, purpose, user_id=None, minutes=10):
    code = _generate_otp_code()
    expires_at = datetime.utcnow() + timedelta(minutes=minutes)
    otp = OTPCode(
        user_id=user_id,
        email=(email or "").strip().lower(),
        purpose=purpose,
        code=code,
        expires_at=expires_at,
        is_used=False,
    )
    try:
        db.session.add(otp)
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.exception("OTP persistence failed.")
        return None

    msg = MailMessage(
        subject=f"AcademicPro Security Code ({purpose.replace('_', ' ').title()})",
        recipients=[email],
        body=(
            f"Your AcademicPro verification code is: {code}\n\n"
            f"This code expires in {minutes} minutes.\n"
            "If you did not request this, ignore this email."
        ),
    )
    sent = _send_mail_safely(msg)
    if not sent:
        try:
            db.session.delete(otp)
            db.session.commit()
        except Exception:
            db.session.rollback()
        return None
    return otp


def _verify_otp(email, purpose, code):
    row = OTPCode.query.filter_by(
        email=(email or "").strip().lower(),
        purpose=purpose,
        code=(code or "").strip(),
        is_used=False,
    ).order_by(OTPCode.created_at.desc()).first()
    if not row:
        return False
    if row.expires_at < datetime.utcnow():
        return False
    row.is_used = True
    db.session.commit()
    return True


def _guest_ai_reply(question):
    q = (question or "").strip().lower()
    if not q:
        return "Share your question and I will guide you on orders, writers, pricing, or deadlines."
    if any(k in q for k in ["price", "cost", "how much", "budget"]):
        return "Pricing depends on deadline, level, and word count. Use Place Order and submit details for an exact quote."
    if any(k in q for k in ["deadline", "urgent", "time", "delivery"]):
        return "Urgent orders are supported. Include your exact deadline in the order form so admin can prioritize assignment."
    if any(k in q for k in ["writer", "expert", "subject", "nursing", "programming", "law"]):
        return "You can review writer profiles on the Writers page. Admin assigns by expertise, ratings, and availability."
    if any(k in q for k in ["revision", "change", "edit"]):
        return "Revisions are handled through the order communication thread after draft submission."
    if any(k in q for k in ["payment", "paypal", "card", "refund"]):
        return "Client payments are verified by admin and tracked in your dashboard. Refunds are handled via support tickets."
    if any(k in q for k in ["chat", "message", "support", "admin"]):
        return "Use the message icon to contact admin directly. Sign in to unlock full order chat with writers."
    return "Thanks. For account-specific help, send a message via the message icon or sign in to continue."


def _ai_generate_reply(question, history, user):
    q = (question or "").strip()
    ql = q.lower()
    name = (user.name.split()[0] if user and user.is_authenticated and user.name else "there")

    if not q:
        return "I am ready. Tell me your topic, deadline, level, and word count, and I will guide the next step."

    if any(k in ql for k in ["price", "cost", "quote", "budget"]):
        return (
            "Pricing is calculated from task type, level, word count, and deadline urgency. "
            "Open Place Order and fill all fields for a live estimate. "
            "If you share your details here, I can help you estimate before checkout."
        )
    if any(k in ql for k in ["deadline", "urgent", "hours", "days", "time"]):
        return (
            "For urgent work, submit exact date and time with timezone in Place Order. "
            "After a writer is assigned, live client-writer chat opens for quick clarifications and draft updates."
        )
    if any(k in ql for k in ["writer", "expert", "niche", "subject"]):
        return (
            "You can filter writers by subject and ratings, then admin matches based on availability and expertise. "
            "Share your subject now and I will suggest what profile to choose."
        )
    if any(k in ql for k in ["revision", "revise", "changes"]):
        return (
            "Revisions are managed inside the order workspace. "
            "Use clear bullet points for change requests so the writer can close them fast."
        )
    if any(k in ql for k in ["plagiarism", "turnitin", "originality"]):
        return (
            "Each order follows originality checks before final delivery. "
            "You can request citation style, source count, and final similarity-report guidance in instructions."
        )
    if any(k in ql for k in ["hello", "hi", "hey"]):
        return f"Hi {name}. I can help with orders, pricing, deadlines, writers, and revisions. What do you need first?"

    if len(history) >= 2:
        return (
            "I understand. Based on our chat, next best step is: "
            "1) confirm your exact requirements, 2) submit the order form, 3) keep updates in live order chat once assigned."
        )
    return (
        "I can help with this. Share these details and I will give a precise plan: "
        "task type, academic level, word count, deadline, and citation style."
    )


def _cleanup_temporary_ai_history():
    cutoff = datetime.utcnow() - timedelta(days=2)
    old_rows = AIConversationMessage.query.filter(
        AIConversationMessage.user_id.is_(None),
        AIConversationMessage.created_at < cutoff
    ).all()
    if not old_rows:
        return
    for row in old_rows:
        db.session.delete(row)
    db.session.commit()


def _task_multiplier(task_type):
    mapping = {
        "Essay": 1.0,
        "Research Paper": 1.2,
        "Dissertation": 1.8,
        "Assignment": 0.9,
        "Case Study": 1.15,
        "Admission Essay": 1.1,
    }
    return mapping.get(task_type or "Essay", 1.0)


def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for("main.admin_login", next=request.url))
        if not current_user.is_admin:
            abort(403)
        return func(*args, **kwargs)
    return wrapper


@main.before_request
def protect_admin_routes():
    # Centralized guard for all admin prefixed routes.
    if request.path.startswith("/admin"):
        if request.endpoint == "main.admin_login":
            return
        if not current_user.is_authenticated:
            return redirect(url_for("main.admin_login", next=request.url))
        if not current_user.is_admin:
            abort(403)

@main.route("/")
def index():
    _cleanup_taken_job_announcements()
    page = request.args.get("page", 1, type=int)
    category = request.args.get("category", "public")
    announcements = Announcement.query.filter(
        (Announcement.audience == category) |
        (Announcement.category == "jobs") |
        (Announcement.category == "jobs_taken")
    ).order_by(Announcement.created_at.desc()).paginate(page=page, per_page=5)

    job_order_ids = [
        jid for jid in (_job_id_from_announcement_title(a.title) for a in announcements.items)
        if jid is not None
    ]
    open_jobs = {
        o.id for o in Order.query.filter(Order.id.in_(job_order_ids), Order.writer_id.is_(None)).all()
    }
    job_apply_map = {}
    for a in announcements.items:
        jid = _job_id_from_announcement_title(a.title)
        if jid and jid in open_jobs:
            job_apply_map[a.id] = jid

    top_writer_ids = (
        db.session.query(OrderReview.writer_id)
        .group_by(OrderReview.writer_id)
        .order_by(db.func.avg(OrderReview.rating).desc())
        .limit(4)
        .all()
    )
    top_ids = [wid for (wid,) in top_writer_ids]
    writers = Writer.query.filter(Writer.id.in_(top_ids)).all() if top_ids else Writer.query.order_by(Writer.created_at.desc()).limit(4).all()
    review_counts = dict(
        db.session.query(OrderReview.writer_id, db.func.count(OrderReview.id)).group_by(OrderReview.writer_id).all()
    )
    posts = BlogPost.query.order_by(BlogPost.created_at.desc()).limit(3).all()
    fast_facts = {
        "students_supported": max(1200, User.query.count() * 45),
        "writers": Writer.query.filter_by(approved=True).count(),
        "papers_delivered": max(3500, Order.query.count() * 7),
        "success_rate": 96,
    }
 
    return render_template(
        "index.html",
        announcements=announcements,
        selected_category=category,
        writers=writers,
        posts=posts,
        testimonials=Testimonial.query.order_by(Testimonial.created_at.desc()).limit(6).all(),
        reviews=SiteReview.query.order_by(SiteReview.id.desc()).limit(6).all(),
        review_counts=review_counts,
        files=[],
        writer_can_apply_jobs=_is_approved_writer(current_user),
        job_apply_map=job_apply_map,
        fast_facts=fast_facts
    )

@main.route('/lead', methods=['POST'])
def lead():
    topic = request.form.get('topic')
    new_lead = Lead(topic=topic)
    db.session.add(new_lead)
    db.session.commit()
    return redirect(url_for('main.index'))

UPLOAD_FOLDER = os.path.join(os.getcwd(), 'app', 'static', 'uploads')
SAMPLE_UPLOAD_FOLDER = os.path.join(UPLOAD_FOLDER, "samples")
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'txt', 'png', 'jpg'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_grouped_chats(admin_id=None):
    chats = Message.query.order_by(Message.timestamp.asc()).all()
    grouped = {}
    for msg in chats:
        if msg.sender_id == 0 or msg.receiver_id == 0:
            thread_id = _extract_guest_thread_id(msg.content) or "legacy"
            partner_id = f"guest:{thread_id}"
        elif admin_id:
            partner_id = msg.receiver_id if msg.sender_id == admin_id else msg.sender_id
        else:
            partner_id = msg.sender_id
        grouped.setdefault(partner_id, []).append(msg)
    return grouped

@main.route('/Register now', methods=['GET', 'POST'])
@main.route('/signup', methods=['GET', 'POST'])
@main.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        existing = User.query.filter_by(email=email).first()
        if existing:
            flash("An account with that email already exists. Please log in.", "warning")
            return redirect(url_for("main.login"))
        hashed_pw = generate_password_hash(form.password.data)
        user = User(
            email=email,
            name=form.name.data.strip(),
            password_hash=hashed_pw,
            role="client",
            email_verified=not _otp_enabled(),
        )
        db.session.add(user)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash("An account with that email already exists. Please log in.", "warning")
            return redirect(url_for("main.login"))
        if _otp_enabled():
            otp = _issue_otp(email=user.email, purpose="signup", user_id=user.id, minutes=15)
            session["pending_signup_user_id"] = user.id
            if otp:
                flash("Account created. Enter the OTP sent to your email to verify your account.", "info")
            else:
                flash("Account created, but OTP delivery failed. Click Resend OTP after checking email settings.", "warning")
            return redirect(url_for('main.verify_email'))
        flash("Account created successfully. You can now sign in.", "success")
        return redirect(url_for("main.login"))
    return render_template('register.html', form=form)


@main.route("/verify-email", methods=["GET", "POST"])
def verify_email():
    if not _otp_enabled():
        flash("Email verification is temporarily disabled for testing.", "info")
        return redirect(url_for("main.login"))
    pending_user_id = session.get("pending_signup_user_id")
    if not pending_user_id:
        flash("No pending email verification request found.", "warning")
        return redirect(url_for("main.login"))
    user = User.query.get(pending_user_id)
    if not user:
        session.pop("pending_signup_user_id", None)
        flash("Verification request is invalid. Please register again.", "warning")
        return redirect(url_for("main.register"))

    if request.method == "POST":
        action = (request.form.get("action") or "verify").strip()
        if action == "resend":
            otp = _issue_otp(email=user.email, purpose="signup", user_id=user.id, minutes=15)
            if otp:
                flash("A new OTP has been sent to your email.", "info")
            else:
                flash("Unable to send OTP right now. Please try again later.", "warning")
            return redirect(url_for("main.verify_email"))
        code = (request.form.get("code") or "").strip()
        if not code:
            flash("Enter the OTP code.", "warning")
            return render_template("verify_email.html", email=user.email)
        if _verify_otp(user.email, "signup", code):
            user.email_verified = True
            db.session.commit()
            session.pop("pending_signup_user_id", None)
            flash("Email verified. You can now sign in.", "success")
            return redirect(url_for("main.login"))
        flash("Invalid or expired OTP.", "danger")
    return render_template("verify_email.html", email=user.email)

@main.route('/send_message', methods=['POST'])
@login_required
def send_message():
    data = request.get_json()
    content = data.get('message')
    if not content:
        return jsonify({'error': 'Empty message'}), 400

    admin = _get_primary_admin()
    receiver_id = admin.id if admin else 1
    msg = Message(sender_id=current_user.id, receiver_id=receiver_id, content=content, is_read=False)
    db.session.add(msg)
    db.session.commit()
    return jsonify({'status': 'Message sent'})

@main.route('/get_messages', methods=['GET'])
@login_required
def get_messages():
    messages = Message.query.filter(
        (Message.sender_id == current_user.id) | 
        (Message.receiver_id == current_user.id)
    ).order_by(Message.timestamp).all()
    return jsonify([
        {
            'content': m.content,
            'is_admin': m.is_admin,
            'timestamp': m.timestamp.strftime("%Y-%m-%d %H:%M") if m.timestamp else None
        } for m in messages
    ])


@main.route("/support/chat/send", methods=["POST"])
@login_required
def support_chat_send():
    if current_user.is_admin:
        return jsonify({"ok": False, "error": "Use admin inbox for replies."}), 403
    payload = request.get_json(silent=True) or {}
    text = (payload.get("message") or "").strip()
    if not text:
        return jsonify({"ok": False, "error": "Message is required."}), 400
    admin = _get_primary_admin()
    if not admin:
        return jsonify({"ok": False, "error": "Admin is unavailable right now."}), 503
    db.session.add(Message(
        sender_id=current_user.id,
        receiver_id=admin.id,
        content=f"{SUPPORT_CHAT_TAG} {text}",
        is_admin=False,
        is_read=False,
    ))
    db.session.commit()
    return jsonify({"ok": True})


@main.route("/support/chat/messages", methods=["GET"])
@login_required
def support_chat_messages():
    if current_user.is_admin:
        return jsonify({"ok": False, "error": "Use admin inbox."}), 403
    admin = _get_primary_admin()
    if not admin:
        return jsonify({"ok": True, "messages": []})
    thread = Message.query.filter(
        (
            ((Message.sender_id == current_user.id) & (Message.receiver_id == admin.id))
            | ((Message.sender_id == admin.id) & (Message.receiver_id == current_user.id))
        )
        & Message.content.like(f"{SUPPORT_CHAT_TAG}%")
    ).order_by(Message.timestamp.asc()).all()
    unread = [m for m in thread if m.receiver_id == current_user.id and not m.is_read]
    for item in unread:
        item.is_read = True
    if unread:
        db.session.commit()

    payload = [{
        "id": m.id,
        "from_admin": m.sender_id == admin.id,
        "content": _strip_tag(m.content, r"^\[Support\]\s*"),
        "timestamp": m.timestamp.strftime("%Y-%m-%d %H:%M") if m.timestamp else ""
    } for m in thread]
    return jsonify({"ok": True, "messages": payload})

@main.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated and not current_user.is_admin:
        return redirect(url_for("main.index"))
    if current_user.is_authenticated and current_user.is_admin:
        return redirect(url_for("main.admin_dashboard"))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.strip().lower()).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            verification_rollout_date = datetime(2026, 2, 18)
            requires_verification = (user.created_at or datetime.utcnow()) >= verification_rollout_date
            if _otp_enabled() and requires_verification and not user.email_verified and not user.is_admin:
                session["pending_signup_user_id"] = user.id
                flash("Please verify your email before signing in.", "warning")
                return redirect(url_for("main.verify_email"))
            if user.is_admin:
                flash("Admin account detected. Please use the Admin Login page.", "info")
                return redirect(url_for("main.admin_login"))
            login_user(user)
            next_page = request.args.get("next")
            return redirect(next_page) if next_page else redirect(url_for("main.index"))
        else:
            flash("Invalid email or password", "danger")
    return render_template("login.html", form=form)


@main.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if current_user.is_authenticated and current_user.is_admin:
        return redirect(url_for("main.admin_dashboard"))
    if current_user.is_authenticated and not current_user.is_admin:
        logout_user()
        flash("Use the user login page for non-admin accounts.", "warning")
        return redirect(url_for("main.login"))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.strip().lower()).first()
        if user and user.is_admin and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            next_page = request.args.get("next")
            if next_page and next_page.startswith("/"):
                return redirect(next_page)
            return redirect(url_for("main.admin_dashboard"))
        flash("Invalid admin credentials", "danger")
    return render_template("admin_login.html", form=form)

@main.route("/protected")
@login_required
def protected():
    return "You must be logged in to view this page."

@main.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully", "info")
    return redirect(url_for("main.login"))


@main.route("/admin/logout")
@login_required
def admin_logout():
    if not current_user.is_admin:
        abort(403)
    logout_user()
    flash("Admin logged out successfully", "info")
    return redirect(url_for("main.admin_login"))

login_manager.login_view = 'main.login'
@login_manager.unauthorized_handler
def unauthorized_callback():
    flash("You must log in or sign up to access this page.", "warning")
    return redirect(url_for('main.login'))


@main.route("/dashboard")
@login_required
def dashboard():
    writer_enabled = _is_approved_writer(current_user)
    unread_count = Message.query.filter_by(receiver_id=current_user.id, is_read=False).count()
    my_orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.created_at.desc()).limit(8).all()
    writer_apps = JobApplication.query.filter_by(writer_user_id=current_user.id).order_by(JobApplication.created_at.desc()).limit(5).all() if writer_enabled else []
    writer_application = Application.query.filter_by(email=current_user.email).order_by(Application.created_at.desc()).first()

    writer_profile = Writer.query.filter_by(name=current_user.name, approved=True).first()
    if writer_application and writer_application.approved:
        subject = writer_application.subject
        bio = writer_application.bio
    else:
        subject = writer_profile.subject if writer_profile else "Not set"
        bio = "Writer profile active."

    approved_app_rows = JobApplication.query.filter_by(writer_user_id=current_user.id, status="approved").all()
    approved_order_ids = [a.order_id for a in approved_app_rows]
    assigned_orders = Order.query.filter(Order.id.in_(approved_order_ids)).order_by(Order.created_at.desc()).all() if approved_order_ids else []
    active_writer_orders = [o for o in assigned_orders if o.status in ("Open", "In Progress")]
    completed_writer_orders = [o for o in assigned_orders if o.status == "Completed"]
    revision_writer_orders = [o for o in assigned_orders if "revision" in (o.status or "").lower()]
    writer_next_order = None
    if active_writer_orders:
        writer_next_order = min(
            active_writer_orders,
            key=lambda o: o.deadline or datetime.utcnow()
        )
    total_writer_orders = len(active_writer_orders) + len(completed_writer_orders) + len(revision_writer_orders)
    writer_workload_percent = int((len(completed_writer_orders) / total_writer_orders) * 100) if total_writer_orders else 0

    available_orders = (
        Order.query.filter_by(status="Open", job_posted=True)
        .filter(Order.writer_id.is_(None))
        .order_by(Order.created_at.desc())
        .limit(8)
        .all()
    )
    writer_announcements = (
        Announcement.query.filter(
            (Announcement.audience == "writers")
            | (Announcement.category == "jobs")
            | (Announcement.category == "jobs_taken")
        )
        .order_by(Announcement.created_at.desc())
        .limit(8)
        .all()
    )
    recent_notifications = Message.query.filter_by(receiver_id=current_user.id).order_by(Message.timestamp.desc()).limit(6).all()

    completed_payments = Payment.query.filter_by(user_name=current_user.name, status="completed").all()
    pending_payments = Payment.query.filter_by(user_name=current_user.name, status="pending").all()
    payment_history = Payment.query.filter_by(user_name=current_user.name).order_by(Payment.created_at.desc()).limit(8).all()
    total_earnings = round(sum((p.amount or 0) for p in completed_payments), 2)
    pending_payout = round(sum((p.amount or 0) for p in pending_payments), 2)
    on_time_bonus = round(total_earnings * 0.03, 2) if len(completed_writer_orders) >= 5 else 0.0
    high_rating_bonus = round(total_earnings * 0.02, 2) if len(completed_writer_orders) >= 10 else 0.0

    client_orders_all = Order.query.filter_by(user_id=current_user.id).order_by(Order.created_at.desc()).all()
    client_active_orders = [o for o in client_orders_all if (o.status or "") in ("Open", "In Progress")]
    client_completed_orders = [o for o in client_orders_all if (o.status or "") == "Completed"]
    client_revision_orders = [o for o in client_orders_all if "revision" in (o.status or "").lower()]
    client_primary_order = client_active_orders[0] if client_active_orders else (client_orders_all[0] if client_orders_all else None)
    client_primary_progress = 0
    if client_primary_order:
        status_lower = (client_primary_order.status or "").lower()
        progress_map = {
            "pending": 10,
            "pending review": 10,
            "open": 25,
            "in progress": 55,
            "revision": 70,
            "completed": 100,
        }
        client_primary_progress = progress_map.get(status_lower, 35)
    client_order_updates = (
        Message.query.filter_by(receiver_id=current_user.id)
        .filter(Message.content.like("[Order #%"))
        .order_by(Message.timestamp.desc())
        .limit(6)
        .all()
    )
    client_direct_messages = Message.query.filter_by(receiver_id=current_user.id).filter(~Message.content.like("[Order #%")).order_by(Message.timestamp.desc()).limit(6).all()

    client_payments = Payment.query.filter_by(user_name=current_user.name).order_by(Payment.created_at.desc()).all()
    client_pending_payments = [p for p in client_payments if (p.status or "").lower() in ("pending", "processing")]
    client_refunds = [p for p in client_payments if "refund" in (p.status or "").lower()]
    open_tickets = SupportTicket.query.filter_by(user_id=current_user.id, status="open").count()

    assigned_writer_map = {}
    if client_orders_all:
        order_ids = [o.id for o in client_orders_all]
        approved_apps = JobApplication.query.filter(
            JobApplication.order_id.in_(order_ids),
            JobApplication.status == "approved",
        ).all()
        writer_users = {
            u.id: u for u in User.query.filter(User.id.in_([a.writer_user_id for a in approved_apps])).all()
        } if approved_apps else {}
        for app_item in approved_apps:
            assigned_writer_map[app_item.order_id] = writer_users.get(app_item.writer_user_id)
    support_chat_enabled = _get_primary_admin() is not None

    return render_template(
        "dashboard.html",
        writer_enabled=writer_enabled,
        unread_count=unread_count,
        my_orders=my_orders,
        writer_apps=writer_apps,
        writer_application=writer_application,
        writer_subject=subject,
        writer_bio=bio,
        active_writer_orders=active_writer_orders,
        completed_writer_orders=completed_writer_orders,
        revision_writer_orders=revision_writer_orders,
        writer_next_order=writer_next_order,
        writer_workload_percent=writer_workload_percent,
        available_orders=available_orders,
        recent_notifications=recent_notifications,
        total_earnings=total_earnings,
        pending_payout=pending_payout,
        payment_history=payment_history,
        on_time_bonus=on_time_bonus,
        high_rating_bonus=high_rating_bonus,
        writer_announcements=writer_announcements,
        client_active_orders=client_active_orders,
        client_completed_orders=client_completed_orders,
        client_revision_orders=client_revision_orders,
        client_order_updates=client_order_updates,
        client_direct_messages=client_direct_messages,
        client_primary_order=client_primary_order,
        client_primary_progress=client_primary_progress,
        client_payments=client_payments,
        client_pending_payments=client_pending_payments,
        client_refunds=client_refunds,
        open_tickets=open_tickets,
        assigned_writer_map=assigned_writer_map,
        support_chat_enabled=support_chat_enabled,
    )


@main.route("/my-orders")
@login_required
def my_orders():
    orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.created_at.desc()).all()
    return render_template("my_orders.html", orders=orders)


@main.route("/notifications")
@login_required
def notifications():
    notices = Message.query.filter_by(receiver_id=current_user.id).order_by(Message.timestamp.desc()).all()
    unread = [m for m in notices if not m.is_read]
    for item in unread:
        item.is_read = True
    if unread:
        db.session.commit()
    return render_template("notifications.html", notices=notices)


@main.route("/support-tickets", methods=["GET", "POST"])
@login_required
def support_tickets():
    if request.method == "POST":
        subject = (request.form.get("subject") or "").strip()
        message = (request.form.get("message") or "").strip()
        order_id = request.form.get("order_id", type=int)
        priority = (request.form.get("priority") or "normal").strip().lower()
        if not subject or not message:
            flash("Subject and message are required.", "danger")
            return redirect(url_for("main.support_tickets"))
        if priority not in {"low", "normal", "high"}:
            priority = "normal"
        if order_id:
            owned = Order.query.filter_by(id=order_id, user_id=current_user.id).first()
            if not owned:
                flash("Invalid order selected for ticket.", "danger")
                return redirect(url_for("main.support_tickets"))
        ticket = SupportTicket(
            user_id=current_user.id,
            order_id=order_id,
            subject=subject,
            message=message,
            priority=priority,
            status="open",
        )
        db.session.add(ticket)
        db.session.commit()
        flash("Support ticket submitted. Admin will review it.", "success")
        return redirect(url_for("main.support_tickets"))

    tickets = SupportTicket.query.filter_by(user_id=current_user.id).order_by(SupportTicket.created_at.desc()).all()
    my_order_choices = Order.query.filter_by(user_id=current_user.id).order_by(Order.created_at.desc()).limit(20).all()
    return render_template("support_tickets.html", tickets=tickets, my_order_choices=my_order_choices)


@main.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    form = ProfileForm(obj=current_user)
    if form.validate_on_submit():
        existing = User.query.filter(User.email == form.email.data.strip().lower(), User.id != current_user.id).first()
        if existing:
            flash("That email is already used by another account.", "danger")
            return render_template("profile.html", form=form)
        current_user.name = form.name.data or current_user.name
        current_user.email = (form.email.data or current_user.email).strip().lower()
        pending_password_hash = None
        if form.password.data:
            pending_password_hash = generate_password_hash(form.password.data)
        if form.photo.data:
            filename = secure_filename(form.photo.data.filename)
            photo_name = f"user_{current_user.id}_{int(datetime.utcnow().timestamp())}_{filename}"
            os.makedirs(UPLOAD_FOLDER, exist_ok=True)
            form.photo.data.save(os.path.join(UPLOAD_FOLDER, photo_name))
            current_user.photo = photo_name
        writer_profile = Writer.query.filter_by(name=current_user.name, approved=True).first()
        if writer_profile and form.writer_portfolio.data:
            filename = secure_filename(form.writer_portfolio.data.filename)
            file_name = f"writer_portfolio_{writer_profile.id}_{int(datetime.utcnow().timestamp())}_{filename}"
            os.makedirs(UPLOAD_FOLDER, exist_ok=True)
            form.writer_portfolio.data.save(os.path.join(UPLOAD_FOLDER, file_name))
            writer_profile.portfolio_file = file_name
        if writer_profile and form.writer_resume.data:
            filename = secure_filename(form.writer_resume.data.filename)
            file_name = f"writer_resume_{writer_profile.id}_{int(datetime.utcnow().timestamp())}_{filename}"
            os.makedirs(UPLOAD_FOLDER, exist_ok=True)
            form.writer_resume.data.save(os.path.join(UPLOAD_FOLDER, file_name))
            writer_profile.resume_file = file_name
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash("That email is already used by another account.", "danger")
            return render_template("profile.html", form=form)
        if pending_password_hash and not _otp_enabled():
            current_user.password_hash = pending_password_hash
            db.session.commit()
            flash("Profile updated and password changed.", "success")
            return redirect(url_for("main.profile"))
        if pending_password_hash:
            session["pending_password_hash"] = pending_password_hash
            otp = _issue_otp(email=current_user.email, purpose="password_change", user_id=current_user.id, minutes=10)
            if otp:
                flash("Profile updated. Verify OTP sent to your email to complete password change.", "info")
            else:
                session.pop("pending_password_hash", None)
                flash("Profile updated, but OTP delivery failed. Password was not changed.", "warning")
                return redirect(url_for("main.profile"))
            return redirect(url_for("main.verify_password_change"))
        flash("Profile updated.", "success")
        return redirect(url_for("main.profile"))
    return render_template("profile.html", form=form)


@main.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    form = SettingForm(obj=current_user)
    if form.validate_on_submit():
        existing = User.query.filter(User.email == form.email.data.strip().lower(), User.id != current_user.id).first()
        if existing:
            flash("That email is already used by another account.", "danger")
            return render_template("settings.html", form=form)
        current_user.name = form.name.data or current_user.name
        current_user.email = (form.email.data or current_user.email).strip().lower()
        current_user.phone = (form.phone.data or "").strip() or None
        current_user.academic_level = form.academic_level.data or None
        current_user.expertise_tags = (form.expertise_tags.data or "").strip() or None
        current_user.two_factor_enabled = bool(form.two_factor_enabled.data)
        current_user.profile_public = bool(form.profile_public.data)
        current_user.notify_email = bool(form.notify_email.data)
        current_user.notify_sms = bool(form.notify_sms.data)
        current_user.notify_in_app = bool(form.notify_in_app.data)
        current_user.alert_order_updates = bool(form.alert_order_updates.data)
        current_user.alert_payment_confirmations = bool(form.alert_payment_confirmations.data)
        current_user.alert_revision_requests = bool(form.alert_revision_requests.data)
        current_user.alert_admin_announcements = bool(form.alert_admin_announcements.data)
        current_user.billing_method = form.billing_method.data or None
        current_user.payout_method = form.payout_method.data or None
        current_user.auto_deposit_notifications = bool(form.auto_deposit_notifications.data)
        current_user.preferred_language = form.preferred_language.data or "English"
        current_user.timezone = form.timezone.data or "UTC"
        current_user.preferred_channel = form.preferred_channel.data or "chat"
        current_user.layout_mode = form.layout_mode.data or "detailed"
        current_user.citation_style = form.citation_style.data or "APA"
        current_user.favorite_writers = (form.favorite_writers.data or "").strip() or None
        current_user.marketing_opt_in = bool(form.marketing_opt_in.data)
        pending_password_hash = None
        if form.password.data:
            pending_password_hash = generate_password_hash(form.password.data)
        if form.photo.data:
            filename = secure_filename(form.photo.data.filename)
            photo_name = f"user_{current_user.id}_{int(datetime.utcnow().timestamp())}_{filename}"
            os.makedirs(UPLOAD_FOLDER, exist_ok=True)
            form.photo.data.save(os.path.join(UPLOAD_FOLDER, photo_name))
            current_user.photo = photo_name
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash("That email is already used by another account.", "danger")
            return render_template("settings.html", form=form)
        if pending_password_hash and not _otp_enabled():
            current_user.password_hash = pending_password_hash
            db.session.commit()
            flash("Settings saved and password changed.", "success")
            return redirect(url_for("main.settings"))
        if pending_password_hash:
            session["pending_password_hash"] = pending_password_hash
            otp = _issue_otp(email=current_user.email, purpose="password_change", user_id=current_user.id, minutes=10)
            if otp:
                flash("Settings saved. Verify OTP sent to your email to complete password change.", "info")
            else:
                session.pop("pending_password_hash", None)
                flash("Settings saved, but OTP delivery failed. Password was not changed.", "warning")
                return redirect(url_for("main.settings"))
            return redirect(url_for("main.verify_password_change"))
        flash("Settings saved.", "success")
        return redirect(url_for("main.settings"))
    return render_template("settings.html", form=form)


@main.route("/settings/export-data")
@login_required
def export_user_data():
    payload = {
        "id": current_user.id,
        "name": current_user.name,
        "email": current_user.email,
        "phone": current_user.phone,
        "academic_level": current_user.academic_level,
        "expertise_tags": current_user.expertise_tags,
        "preferences": {
            "language": current_user.preferred_language,
            "timezone": current_user.timezone,
            "channel": current_user.preferred_channel,
            "layout": current_user.layout_mode,
            "citation_style": current_user.citation_style,
            "notify_email": current_user.notify_email,
            "notify_sms": current_user.notify_sms,
            "notify_in_app": current_user.notify_in_app,
            "marketing_opt_in": current_user.marketing_opt_in,
        },
    }
    return jsonify(payload)


@main.route("/settings/request-delete", methods=["POST"])
@login_required
def request_delete_account():
    if not _otp_enabled():
        db.session.add(
            SupportTicket(
                user_id=current_user.id,
                subject="Account Deletion Request",
                message="User requested account deletion while OTP verification is disabled.",
                priority="high",
                status="open",
            )
        )
        db.session.commit()
        flash("Deletion request sent to admin for processing.", "info")
        return redirect(url_for("main.settings"))
    otp = _issue_otp(email=current_user.email, purpose="delete_account", user_id=current_user.id, minutes=10)
    if not otp:
        flash("Unable to issue deletion OTP now. Please try again later.", "warning")
        return redirect(url_for("main.settings"))
    session["pending_delete_user_id"] = current_user.id
    flash("OTP sent. Enter code to confirm account deletion request.", "warning")
    return redirect(url_for("main.verify_delete_account"))


@main.route("/settings/verify-password-change", methods=["GET", "POST"])
@login_required
def verify_password_change():
    if not _otp_enabled():
        flash("Password OTP verification is temporarily disabled.", "info")
        return redirect(url_for("main.settings"))
    pending_hash = session.get("pending_password_hash")
    if not pending_hash:
        flash("No pending password change request found.", "warning")
        return redirect(url_for("main.settings"))
    if request.method == "POST":
        action = (request.form.get("action") or "verify").strip()
        if action == "resend":
            otp = _issue_otp(email=current_user.email, purpose="password_change", user_id=current_user.id, minutes=10)
            if otp:
                flash("A new OTP has been sent.", "info")
            else:
                flash("Unable to send OTP right now.", "warning")
            return redirect(url_for("main.verify_password_change"))
        code = (request.form.get("code") or "").strip()
        if _verify_otp(current_user.email, "password_change", code):
            current_user.password_hash = pending_hash
            db.session.commit()
            session.pop("pending_password_hash", None)
            flash("Password changed successfully.", "success")
            return redirect(url_for("main.settings"))
        flash("Invalid or expired OTP.", "danger")
    return render_template("verify_action.html", title="Verify Password Change", email=current_user.email, action_route=url_for("main.verify_password_change"))


@main.route("/settings/verify-delete-account", methods=["GET", "POST"])
@login_required
def verify_delete_account():
    if not _otp_enabled():
        flash("Account deletion OTP verification is temporarily disabled.", "info")
        return redirect(url_for("main.settings"))
    pending_uid = session.get("pending_delete_user_id")
    if pending_uid != current_user.id:
        flash("No pending account deletion request found.", "warning")
        return redirect(url_for("main.settings"))
    if request.method == "POST":
        action = (request.form.get("action") or "verify").strip()
        if action == "resend":
            otp = _issue_otp(email=current_user.email, purpose="delete_account", user_id=current_user.id, minutes=10)
            if otp:
                flash("A new OTP has been sent.", "info")
            else:
                flash("Unable to send OTP right now.", "warning")
            return redirect(url_for("main.verify_delete_account"))
        code = (request.form.get("code") or "").strip()
        if _verify_otp(current_user.email, "delete_account", code):
            db.session.add(
                SupportTicket(
                    user_id=current_user.id,
                    subject="Confirmed Account Deletion Request",
                    message="User completed OTP verification for account deletion.",
                    priority="high",
                    status="open",
                )
            )
            db.session.commit()
            session.pop("pending_delete_user_id", None)
            flash("Deletion request confirmed and sent to admin.", "info")
            return redirect(url_for("main.settings"))
        flash("Invalid or expired OTP.", "danger")
    return render_template("verify_action.html", title="Confirm Account Deletion", email=current_user.email, action_route=url_for("main.verify_delete_account"))


@main.route("/writer/apply", methods=["GET", "POST"])
@login_required
def writer_apply():
    form = ApplicationForm()
    existing = Application.query.filter_by(email=current_user.email).first()
    if form.validate_on_submit():
        if existing:
            flash("You already submitted a writer application. Please wait for review.", "info")
            return redirect(url_for("main.writer_apply"))
        portfolio_name = None
        if form.portfolio.data:
            filename = secure_filename(form.portfolio.data.filename)
            portfolio_name = f"writer_app_{current_user.id}_{int(datetime.utcnow().timestamp())}_{filename}"
            os.makedirs(UPLOAD_FOLDER, exist_ok=True)
            form.portfolio.data.save(os.path.join(UPLOAD_FOLDER, portfolio_name))
        application = Application(
            name=form.name.data.strip(),
            email=current_user.email,
            subject=form.subject.data.strip(),
            bio=form.bio.data.strip(),
            education_level=form.education_level.data,
            years_experience=form.years_experience.data,
            writing_styles=",".join(form.writing_styles.data) if form.writing_styles.data else None,
            portfolio_file=portfolio_name,
            accept_terms=form.accept_terms.data,
            approved=False
        )
        db.session.add(application)
        db.session.commit()
        flash("Application received. We'll review it in 3-5 business days.", "success")
        return redirect(url_for("main.writer_apply"))
    if request.method == "GET":
        form.name.data = current_user.name
        form.email.data = current_user.email
    return render_template("writer_apply.html", form=form, existing=existing)

@main.route('/admin/messages')
def admin_messages():
    if not current_user.is_admin:
        abort(403)
    return render_template('admin_messages.html')


@main.route("/admin/support-tickets", methods=["GET", "POST"])
@login_required
def admin_support_tickets():
    if not current_user.is_admin:
        abort(403)
    if request.method == "POST":
        ticket_id = request.form.get("ticket_id", type=int)
        status = (request.form.get("status") or "").strip().lower()
        admin_note = (request.form.get("admin_note") or "").strip()
        ticket = SupportTicket.query.get_or_404(ticket_id)
        if status in {"open", "in_progress", "resolved", "closed"}:
            ticket.status = status
        ticket.admin_note = admin_note
        ticket.updated_at = datetime.utcnow()
        db.session.commit()
        flash("Support ticket updated.", "success")
        return redirect(url_for("main.admin_support_tickets"))
    tickets = SupportTicket.query.order_by(SupportTicket.created_at.desc()).all()
    ticket_users = {
        u.id: u for u in User.query.filter(User.id.in_([t.user_id for t in tickets])).all()
    } if tickets else {}
    return render_template("admin_support_tickets.html", tickets=tickets, ticket_users=ticket_users)

@main.route('/writers')
def public_writers():
    writers = Writer.query.filter_by(approved=True).order_by(Writer.id.desc()).all()
    return render_template('public_writers.html', writers=writers)


def _can_manage_blog(user):
    return bool(user and user.is_authenticated and (user.is_admin or _is_approved_writer(user)))


def _apply_blog_filters(base_query):
    q = (request.args.get("q") or "").strip()
    category = (request.args.get("category") or "").strip()
    pillar = (request.args.get("pillar") or "").strip()
    cluster = (request.args.get("cluster") or "").strip()

    query = base_query.filter(BlogPost.is_published.is_(True))
    if q:
        query = query.filter(
            BlogPost.title.ilike(f"%{q}%")
            | BlogPost.content.ilike(f"%{q}%")
            | BlogPost.excerpt.ilike(f"%{q}%")
            | BlogPost.pillar.ilike(f"%{q}%")
            | BlogPost.cluster_topic.ilike(f"%{q}%")
        )
    if category:
        query = query.filter(BlogPost.category == category)
    if pillar:
        query = query.filter(BlogPost.pillar == pillar)
    if cluster:
        query = query.filter(BlogPost.cluster_topic == cluster)
    return query, q, category, pillar, cluster


@main.route("/Blog")
def blog_list():
    page = request.args.get("page", 1, type=int)
    query, q, category, pillar, cluster = _apply_blog_filters(BlogPost.query)
    blogs = query.order_by(BlogPost.created_at.desc()).paginate(page=page, per_page=6)
    pillars = [row[0] for row in db.session.query(BlogPost.pillar).filter(BlogPost.pillar.isnot(None)).distinct().all() if row[0]]
    clusters = [row[0] for row in db.session.query(BlogPost.cluster_topic).filter(BlogPost.cluster_topic.isnot(None)).distinct().all() if row[0]]
    categories = [row[0] for row in db.session.query(BlogPost.category).filter(BlogPost.category.isnot(None)).distinct().all() if row[0]]
    return render_template(
        "blog.html",
        blogs=blogs,
        query=q,
        selected_category=category,
        selected_pillar=pillar,
        selected_cluster=cluster,
        pillars=sorted(pillars),
        clusters=sorted(clusters),
        categories=sorted(categories),
    )

@main.route('/admin')
def admin_dashboard():
    now = datetime.utcnow()
    seven_days_ago = now - timedelta(days=6)
    dates = [(seven_days_ago + timedelta(days=i)).date() for i in range(7)]
    date_labels = [d.strftime("%b %d") for d in dates]

    orders_7d = []
    leads_7d = []
    payments_7d = []
    for d in dates:
        d_start = datetime.combine(d, datetime.min.time())
        d_end = d_start + timedelta(days=1)
        orders_7d.append(Order.query.filter(Order.created_at >= d_start, Order.created_at < d_end).count())
        leads_7d.append(Lead.query.filter(Lead.created_at >= d_start, Lead.created_at < d_end).count())
        payments_7d.append(Payment.query.filter(Payment.created_at >= d_start, Payment.created_at < d_end).count())
    prev_dates = [(seven_days_ago - timedelta(days=7)) + timedelta(days=i) for i in range(7)]
    orders_prev_7d = []
    leads_prev_7d = []
    payments_prev_7d = []
    for d in prev_dates:
        d_start = datetime.combine(d.date(), datetime.min.time())
        d_end = d_start + timedelta(days=1)
        orders_prev_7d.append(Order.query.filter(Order.created_at >= d_start, Order.created_at < d_end).count())
        leads_prev_7d.append(Lead.query.filter(Lead.created_at >= d_start, Lead.created_at < d_end).count())
        payments_prev_7d.append(Payment.query.filter(Payment.created_at >= d_start, Payment.created_at < d_end).count())
    orders_velocity = round(((sum(orders_7d) - sum(orders_prev_7d)) / max(sum(orders_prev_7d), 1)) * 100, 1)
    leads_velocity = round(((sum(leads_7d) - sum(leads_prev_7d)) / max(sum(leads_prev_7d), 1)) * 100, 1)
    payments_velocity = round(((sum(payments_7d) - sum(payments_prev_7d)) / max(sum(payments_prev_7d), 1)) * 100, 1)

    pending_applications = Application.query.filter_by(approved=False).count()
    overdue_orders = Order.query.filter(Order.deadline < now, Order.status.in_(["Open", "In Progress"])).count()
    pending_withdrawals = Payment.query.filter_by(status="pending").count()
    unread_admin_msgs = Message.query.filter_by(receiver_id=current_user.id, is_read=False).count()
    new_users_24h = User.query.filter(User.created_at >= (now - timedelta(hours=24))).count()
    incoming_guest_msgs = Message.query.filter_by(receiver_id=current_user.id, is_read=False).filter(Message.sender_id == 0).count()
    open_support_tickets = SupportTicket.query.filter(SupportTicket.status.in_(["open", "in_progress"])).count()
    pending_orders = Order.query.filter_by(status="Pending").count()

    alerts = []
    if pending_applications:
        alerts.append({
            "level": "warning",
            "title": f"{pending_applications} writer applications pending",
            "action": url_for("main.admin_writers"),
            "action_label": "Review applications"
        })
    if overdue_orders:
        alerts.append({
            "level": "danger",
            "title": f"{overdue_orders} orders are overdue",
            "action": url_for("main.admin_orders", status="In Progress"),
            "action_label": "Open orders queue"
        })
    if pending_withdrawals:
        alerts.append({
            "level": "info",
            "title": f"{pending_withdrawals} payout settlements pending",
            "action": url_for("main.admin_settlements"),
            "action_label": "Reconcile payouts"
        })
    if unread_admin_msgs:
        alerts.append({
            "level": "primary",
            "title": f"{unread_admin_msgs} unread admin messages",
            "action": url_for("main.admin_chat_grouped"),
            "action_label": "Open inbox"
        })
    if new_users_24h:
        alerts.append({
            "level": "success",
            "title": f"{new_users_24h} new users registered in last 24h",
            "action": url_for("main.admin_dashboard"),
            "action_label": "View recent users"
        })
    if incoming_guest_msgs:
        alerts.append({
            "level": "warning",
            "title": f"{incoming_guest_msgs} unread guest messages",
            "action": url_for("main.admin_chat_grouped"),
            "action_label": "Reply to guests"
        })
    if open_support_tickets:
        alerts.append({
            "level": "danger" if open_support_tickets > 10 else "warning",
            "title": f"{open_support_tickets} support tickets need attention",
            "action": url_for("main.admin_support_tickets"),
            "action_label": "Open support queue"
        })
    if pending_orders:
        alerts.append({
            "level": "info",
            "title": f"{pending_orders} orders awaiting assignment",
            "action": url_for("main.admin_orders", status="Pending"),
            "action_label": "Assign orders"
        })

    recent_users = User.query.order_by(User.created_at.desc()).limit(6).all()
    recent_applications = Application.query.order_by(Application.created_at.desc()).limit(6).all()
    recent_orders = Order.query.order_by(Order.created_at.desc()).limit(6).all()
    settlement_snapshot = {
        "pending_count": Payment.query.filter_by(status="pending").count(),
        "completed_count": Payment.query.filter_by(status="completed").count(),
        "failed_count": Payment.query.filter_by(status="failed").count(),
        "pending_amount": round(sum(p.amount or 0 for p in Payment.query.filter_by(status="pending").all()), 2),
    }
    projected_payouts = round(settlement_snapshot["pending_amount"] * 1.15, 2)

    total_users = User.query.count()
    active_orders = Order.query.filter(Order.status.in_(["Open", "In Progress"])).count()
    completed_orders = Order.query.filter_by(status="Completed").count()
    total_leads = Lead.query.count()
    payment_attempts = Payment.query.count()
    payment_success = Payment.query.filter_by(status="completed").count()
    payment_success_rate = round((payment_success / payment_attempts) * 100, 1) if payment_attempts else 0.0
    lead_to_order = round((Order.query.count() / total_leads) * 100, 1) if total_leads else 0.0
    stats = {
        "messages": Message.query.count(),
        "testimonials": Testimonial.query.count(),
        "writers": Writer.query.count(),
        "leads": Lead.query.count(),
        "orders": Order.query.count(),
        "payments": Payment.query.count(),
        "pending_writer_apps": pending_applications,
        "users": total_users,
        "active_orders": active_orders,
        "completed_orders": completed_orders,
        "payment_success_rate": payment_success_rate,
        "lead_to_order_rate": lead_to_order,
    }
    grouped_chats = get_grouped_chats()
    announcements = Announcement.query.order_by(Announcement.created_at.desc()).limit(8).all()
    attention_users = User.query.order_by(User.created_at.desc()).limit(6).all()
    pending_apps = Application.query.filter_by(approved=False).order_by(Application.created_at.desc()).limit(6).all()

    return render_template(
        "admin_dashboard.html",
        stats=stats,
        grouped_chats=grouped_chats,
        announcements=announcements,
        alerts=alerts,
        chart_labels=date_labels,
        chart_orders=orders_7d,
        chart_leads=leads_7d,
        chart_payments=payments_7d,
        chart_targets=[max(2, int(sum(orders_7d) / max(len(orders_7d), 1))) for _ in dates],
        chart_annotations=[
            {"label": "Campaign", "index": 4} if len(dates) > 4 else None
        ],
        velocities={
            "orders": orders_velocity,
            "leads": leads_velocity,
            "payments": payments_velocity,
        },
        recent_users=recent_users,
        recent_applications=recent_applications,
        recent_orders=recent_orders,
        attention_users=attention_users,
        pending_apps=pending_apps,
        settlement_snapshot=settlement_snapshot,
        projected_payouts=projected_payouts
    )
    
@main.route('/admin/leads')
def admin_leads():
    leads = Lead.query.order_by(Lead.created_at.desc()).all()
    return render_template("admin_leads.html", leads=leads)

@main.route('/admin/testimonials', methods=['GET', 'POST'])
def admin_testimonials():
    if request.method == 'POST':
        name = request.form['name']
        content = request.form['content']
        rating = int(request.form['rating'])
        testimonial = Testimonial(name=name, content=content, rating=rating)
        db.session.add(testimonial)
        db.session.commit()
        return redirect(url_for('main.admin_testimonials'))

    testimonials = Testimonial.query.order_by(Testimonial.created_at.desc()).all()
    return render_template('admin_testimonials.html', testimonials=testimonials)

@main.route('/admin/testimonial/<int:id>/edit', methods=['GET', 'POST'])
def edit_testimonial(id):
    testimonial = Testimonial.query.get_or_404(id)
    if request.method == 'POST':
        testimonial.name = request.form['name']
        testimonial.content = request.form['content']
        testimonial.rating = int(request.form['rating'])
        db.session.commit()
        return redirect(url_for('main.admin_testimonials'))
    return render_template('edit_testimonial.html', testimonial=testimonial)

@main.route('/admin/testimonial/<int:id>/delete')
def delete_testimonial(id):
    testimonial = Testimonial.query.get_or_404(id)
    db.session.delete(testimonial)
    db.session.commit()
    return redirect(url_for('main.admin_testimonials'))

@main.route("/admin/samples", methods=["GET", "POST"])
def admin_samples():
    if request.method == "POST":
        title = (request.form.get("title") or "").strip()
        category = (request.form.get("category") or "").strip()
        style = (request.form.get("style") or "").strip() or None
        level = (request.form.get("level") or "").strip() or None
        subject = (request.form.get("subject") or "").strip() or None
        grade = (request.form.get("grade") or "").strip() or None
        published_at_raw = (request.form.get("published_at") or "").strip()
        source_url = (request.form.get("source_url") or "").strip() or None
        content = (request.form.get("content") or "").strip()
        published_at = None
        if published_at_raw:
            try:
                published_at = datetime.strptime(published_at_raw, "%Y-%m-%d")
            except ValueError:
                published_at = None

        file_name = None
        file_type = None
        uploaded = request.files.get("file")
        if uploaded and uploaded.filename:
            if not allowed_file(uploaded.filename):
                flash("Unsupported file type.", "danger")
                return redirect(url_for("main.admin_samples"))
            os.makedirs(SAMPLE_UPLOAD_FOLDER, exist_ok=True)
            safe_name = secure_filename(uploaded.filename)
            stored = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{safe_name}"
            uploaded.save(os.path.join(SAMPLE_UPLOAD_FOLDER, stored))
            file_name = stored
            file_type = stored.rsplit(".", 1)[-1].lower()

        if not title or not category or not content:
            flash("Title, category, and summary are required.", "danger")
            return redirect(url_for("main.admin_samples"))

        new_sample = Sample(
            title=title,
            category=category,
            style=style,
            level=level,
            subject=subject,
            grade=grade,
            published_at=published_at,
            source_url=source_url,
            file_type=file_type,
            file_name=file_name,
            content=content,
        )
        db.session.add(new_sample)
        db.session.commit()
        return redirect(url_for("main.admin_samples"))

    samples = Sample.query.order_by(Sample.created_at.desc()).all()
    return render_template("admin_samples.html", samples=samples)


@main.route("/writer/samples", methods=["GET", "POST"])
@login_required
def writer_samples():
    if not _is_approved_writer(current_user):
        abort(403)
    if request.method == "POST":
        title = (request.form.get("title") or "").strip()
        category = (request.form.get("category") or "").strip()
        style = (request.form.get("style") or "").strip() or None
        level = (request.form.get("level") or "").strip() or None
        subject = (request.form.get("subject") or "").strip() or None
        grade = (request.form.get("grade") or "").strip() or None
        published_at_raw = (request.form.get("published_at") or "").strip()
        source_url = (request.form.get("source_url") or "").strip() or None
        content = (request.form.get("content") or "").strip()
        published_at = None
        if published_at_raw:
            try:
                published_at = datetime.strptime(published_at_raw, "%Y-%m-%d")
            except ValueError:
                published_at = None

        file_name = None
        file_type = None
        uploaded = request.files.get("file")
        if uploaded and uploaded.filename:
            if not allowed_file(uploaded.filename):
                flash("Unsupported file type.", "danger")
                return redirect(url_for("main.writer_samples"))
            os.makedirs(SAMPLE_UPLOAD_FOLDER, exist_ok=True)
            safe_name = secure_filename(uploaded.filename)
            stored = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{safe_name}"
            uploaded.save(os.path.join(SAMPLE_UPLOAD_FOLDER, stored))
            file_name = stored
            file_type = stored.rsplit(".", 1)[-1].lower()

        if not title or not category or not content:
            flash("Title, category, and summary are required.", "danger")
            return redirect(url_for("main.writer_samples"))

        new_sample = Sample(
            title=title,
            category=category,
            style=style,
            level=level,
            subject=subject,
            grade=grade,
            published_at=published_at,
            source_url=source_url,
            file_type=file_type,
            file_name=file_name,
            content=content,
        )
        db.session.add(new_sample)
        db.session.commit()
        flash("Sample uploaded.", "success")
        return redirect(url_for("main.writer_samples"))

    samples = Sample.query.order_by(Sample.created_at.desc()).all()
    return render_template("writer_samples.html", samples=samples)

@main.route('/admin/samples/<int:id>/delete')
def delete_samples(id):
    post = Sample.query.get_or_404(id)
    db.session.delete(post)
    db.session.commit()
    flash('Sample post deleted.', 'info')
    return redirect(url_for('main.admin_samples'))

@main.route('/admin/reviews', methods=['GET', 'POST'])
def admin_reviews():
    if request.method == 'POST':
        reviewer = request.form['reviewer']
        comment = request.form['comment']
        stars = int(request.form['stars'])

        new_review = SiteReview(reviewer=reviewer, comment=comment, stars=stars)
        db.session.add(new_review)
        db.session.commit()
        return redirect(url_for('main.admin_reviews'))

    reviews = SiteReview.query.order_by(SiteReview.created_at.desc()).all()
    return render_template("admin_reviews.html", reviews=reviews)

@main.route('/admin/reviews/<int:id>/delete')
def delete_review(id):
    review = SiteReview.query.get_or_404(id)
    db.session.delete(review)
    db.session.commit()
    return redirect(url_for('main.admin_reviews'))

@main.route('/admin/writers')
def admin_writers():
    q = (request.args.get("q") or "").strip()
    status = (request.args.get("status") or "").strip().lower()

    writers_query = Writer.query
    applications_query = Application.query

    if q:
        like_q = f"%{q}%"
        writers_query = writers_query.filter(
            Writer.name.ilike(like_q) | Writer.subject.ilike(like_q)
        )
        applications_query = applications_query.filter(
            Application.name.ilike(like_q) |
            Application.email.ilike(like_q) |
            Application.subject.ilike(like_q)
        )

    if status in {"approved", "pending"}:
        approved_flag = status == "approved"
        writers_query = writers_query.filter(Writer.approved == approved_flag)
        applications_query = applications_query.filter(Application.approved == approved_flag)

    writers = writers_query.order_by(Writer.created_at.desc()).all()
    applications = applications_query.order_by(Application.created_at.desc()).all()
    return render_template('admin_writers.html', writers=writers, applications=applications, q=q, status=status)


@main.route('/admin/application/<int:id>/approve')
@login_required
def approve_application(id):
    if not current_user.is_admin:
        abort(403)
    app_item = Application.query.get_or_404(id)
    app_item.approved = True
    user = User.query.filter_by(email=app_item.email).first()
    if user:
        user.role = "writer"
    existing_writer = Writer.query.filter_by(name=app_item.name, approved=True).first()
    if not existing_writer:
        db.session.add(Writer(name=app_item.name, subject=app_item.subject, approved=True))
    db.session.commit()
    flash('Writer application approved.', 'success')
    return redirect(url_for('main.admin_writers'))


@main.route('/admin/application/<int:id>/reject')
@login_required
def reject_application(id):
    if not current_user.is_admin:
        abort(403)
    app_item = Application.query.get_or_404(id)
    app_item.approved = False
    db.session.commit()
    flash('Writer application marked as not approved.', 'info')
    return redirect(url_for('main.admin_writers'))

@main.route('/admin/writer/<int:id>/approve')
def approve_writer(id):
    writer = Writer.query.get_or_404(id)
    writer.approved = True
    db.session.commit()
    flash('Writer approved!', 'success')
    return redirect(url_for('main.admin_writers'))

@main.route('/admin/writer/<int:id>/delete')
def delete_writer(id):
    writer = Writer.query.get_or_404(id)
    db.session.delete(writer)
    db.session.commit()
    flash('Writer deleted.', 'info')
    return redirect(url_for('main.admin_writers'))

@main.route('/writer/thanks')
def writer_thank_you():
    return render_template('writer_thank_you.html')

@main.route('/admin/writer/add', methods=['GET', 'POST'])
@login_required
def add_writer():
    if request.method == 'POST':
        name = request.form['name']
        subject = request.form['subject']
        image_url = request.form.get('image_url')
        approved = True  # Admin-added writers are auto-approved
        new_writer = Writer(name=name, subject=subject, image_url=image_url, approved=approved)
        db.session.add(new_writer)
        db.session.commit()
        flash("Writer added successfully.", "success")
        return redirect(url_for('main.admin_writers'))
    return render_template('admin_writer_add.html')

@main.route("/order", methods=["GET", "POST"])
@login_required
def order():
    form = OrderForm()
    if request.method == "GET":
        form.name.data = current_user.name
        form.email.data = current_user.email
    if form.validate_on_submit():
        task_type = (form.task_type.data or "Essay").strip()
        submitted_wc = form.word_count.data if form.word_count.data else 0
        word_count = submitted_wc if submitted_wc and submitted_wc > 0 else 1000
        level = (form.level.data or "Undergrad").strip()
        deadline_dt = datetime.combine(form.deadline.data, datetime.min.time())
        base_price = calculate_price(word_count, level, deadline_dt)
        final_price = round(base_price * _task_multiplier(task_type), 2)
        order = Order(
            topic=form.subject.data.strip(),
            task_type=task_type,
            description=form.details.data.strip(),
            citation_style=form.citation_style.data or "APA",
            sources_count=form.sources_count.data or 0,
            currency=form.currency.data or "USD",
            timezone=form.timezone.data or "UTC",
            deadline=deadline_dt,
            word_count=word_count,
            level=level,
            price=final_price,
            status="Pending Review",
            job_posted=False,
            user_id=current_user.id
        )
        db.session.add(order)
        db.session.commit()
        if form.attachments.data:
            uploaded = form.attachments.data
            if uploaded and uploaded.filename and allowed_file(uploaded.filename):
                filename = secure_filename(uploaded.filename)
                stored = f"order_{order.id}_{int(datetime.utcnow().timestamp())}_{filename}"
                os.makedirs(UPLOAD_FOLDER, exist_ok=True)
                uploaded.save(os.path.join(UPLOAD_FOLDER, stored))
                db.session.add(OrderFile(
                    filename=stored,
                    uploader=current_user.name,
                    order_id=order.id
                ))
                db.session.commit()
        admin = _get_primary_admin()
        if admin:
            db.session.add(
                Message(
                    sender_id=current_user.id,
                    receiver_id=admin.id,
                    content=f"[New Order #{order.id}] {order.topic} | {task_type} | {word_count} words | ${final_price} | Style: {order.citation_style} | Sources: {order.sources_count}",
                    is_admin=False,
                    is_read=False,
                )
            )
            db.session.commit()

        msg = MailMessage(
            subject="We Received Your Order",
            recipients=[current_user.email],
            body=f"""
Hi {current_user.name},

Thanks for your order!

Subject: {form.subject.data}
Deadline: {form.deadline.data.strftime('%Y-%m-%d')}
Details: {form.details.data}

We'll get back to you shortly.

Regards,
Your Website Team
""",
        )
        _send_mail_safely(msg)

        flash(f"Order submitted for admin review. Estimated price: ${final_price}.", "success")
        return redirect(url_for("main.order_confirmation"))

    return render_template("order.html", form=form)

@main.route("/order/confirmation")
def order_confirmation():
    return render_template("order_confirmation.html")

@main.route("/admin/orders")
def admin_orders():
    q = (request.args.get("q") or "").strip()
    status = (request.args.get("status") or "").strip()
    date_from = (request.args.get("date_from") or "").strip()
    date_to = (request.args.get("date_to") or "").strip()

    query = Order.query
    if q:
        query = query.filter(
            (Order.topic.ilike(f"%{q}%")) |
            (Order.description.ilike(f"%{q}%")) |
            (User.name.ilike(f"%{q}%"))
        ).join(User, Order.user_id == User.id)
    if status:
        query = query.filter(Order.status == status)
    if date_from:
        try:
            df = datetime.strptime(date_from, "%Y-%m-%d")
            query = query.filter(Order.created_at >= df)
        except ValueError:
            pass
    if date_to:
        try:
            dt = datetime.strptime(date_to, "%Y-%m-%d") + timedelta(days=1)
            query = query.filter(Order.created_at < dt)
        except ValueError:
            pass

    orders = query.order_by(Order.created_at.desc()).all()

    applications = JobApplication.query.order_by(JobApplication.created_at.desc()).all()
    applications_by_order = {}
    for app_item in applications:
        applications_by_order.setdefault(app_item.order_id, []).append(app_item)
    writer_users = {
        u.id: u for u in User.query.filter(User.id.in_([a.writer_user_id for a in applications])).all()
    } if applications else {}

    return render_template(
        "admin_orders.html",
        orders=orders,
        writers=Writer.query.filter_by(approved=True).order_by(Writer.created_at.desc()).all(),
        applications_by_order=applications_by_order,
        writer_users=writer_users,
        q=q,
        status=status,
        date_from=date_from,
        date_to=date_to
    )

@main.route('/admin/order/<int:id>/update', methods=['GET', 'POST'])
def update_order(id):
    order = Order.query.get_or_404(id)
    if request.method == 'POST':
        order.status = request.form['status']
        writer_id = request.form.get('writer_id', type=int)
        if writer_id:
            order.writer_id = writer_id
            order.assigned_at = datetime.utcnow()
        db.session.commit()
        return redirect(url_for('main.admin_orders'))
    return render_template('admin_orders.html', order=order)


@main.route("/admin/order/<int:id>/publish-job", methods=["POST"])
@login_required
def publish_order_job(id):
    if not current_user.is_admin:
        abort(403)
    order = Order.query.get_or_404(id)
    if order.job_posted:
        flash("Job is already published to writers.", "info")
        return redirect(url_for("main.admin_orders"))
    order.status = "Open"
    order.job_posted = True
    db.session.add(
        Announcement(
            title=f"JOB#{order.id} | {order.topic}",
            body=(
                f"New task published. Type: {order.task_type or 'Essay'}, "
                f"Words: {order.word_count}, Budget: ${order.price or 0}, "
                f"Deadline: {order.deadline.strftime('%Y-%m-%d') if order.deadline else 'N/A'}."
            ),
            audience="writers",
            category="jobs",
        )
    )
    db.session.commit()
    flash("Task published to all writers announcements.", "success")
    return redirect(url_for("main.admin_orders"))


@main.route("/jobs")
@login_required
def jobs():
    if not _is_approved_writer(current_user):
        flash("Only approved writers can view and apply for jobs.", "warning")
        return redirect(url_for("main.writer_apply"))
    open_orders = (
        Order.query.filter_by(status="Open", job_posted=True)
        .filter(Order.writer_id.is_(None))
        .order_by(Order.created_at.desc())
        .all()
    )
    my_apps = JobApplication.query.filter_by(writer_user_id=current_user.id).all()
    applied_order_ids = {a.order_id for a in my_apps}
    assigned_order_ids = [a.order_id for a in my_apps if a.status == "approved"]
    assigned_orders = Order.query.filter(Order.id.in_(assigned_order_ids)).order_by(Order.created_at.desc()).all() if assigned_order_ids else []
    return render_template(
        "jobs_board.html",
        open_orders=open_orders,
        applied_order_ids=applied_order_ids,
        assigned_orders=assigned_orders
    )


@main.route("/jobs/<int:order_id>/apply", methods=["POST"])
@login_required
def apply_job(order_id):
    if not _is_approved_writer(current_user):
        flash("Only approved writers can apply for jobs.", "danger")
        return redirect(url_for("main.writer_apply"))

    order = Order.query.get_or_404(order_id)
    if order.writer_id:
        flash("This job is no longer available.", "warning")
        return redirect(url_for("main.jobs"))

    existing = JobApplication.query.filter_by(order_id=order.id, writer_user_id=current_user.id).first()
    if existing:
        flash("You already applied for this job.", "info")
        return redirect(url_for("main.jobs"))

    pitch = (request.form.get("cover_note") or "").strip()
    db.session.add(JobApplication(order_id=order.id, writer_user_id=current_user.id, cover_note=pitch))
    db.session.commit()
    flash("Application sent. Admin will review it.", "success")
    return redirect(url_for("main.jobs"))


@main.route("/admin/job-applications/<int:application_id>/approve", methods=["POST"])
@login_required
def approve_job_application(application_id):
    if not current_user.is_admin:
        abort(403)

    app_item = JobApplication.query.get_or_404(application_id)
    order = Order.query.get_or_404(app_item.order_id)
    writer_user = User.query.get_or_404(app_item.writer_user_id)
    if order.writer_id:
        flash("This job has already been assigned.", "warning")
        return redirect(url_for("main.admin_orders"))

    app_item.status = "approved"
    app_item.reviewed_at = datetime.utcnow()

    # Mark all other applications as rejected.
    others = JobApplication.query.filter(
        JobApplication.order_id == order.id,
        JobApplication.id != app_item.id,
        JobApplication.status == "pending"
    ).all()
    for other in others:
        other.status = "rejected"
        other.reviewed_at = datetime.utcnow()

    linked_writer = Writer.query.filter_by(name=writer_user.name, approved=True).first()
    if linked_writer:
        order.writer_id = linked_writer.id
    order.status = "In Progress"
    order.assigned_at = datetime.utcnow()

    # Replace open job announcement with a taken-status announcement.
    job_announce = Announcement.query.filter(
        Announcement.category == "jobs",
        Announcement.title.like(f"JOB#{order.id} |%")
    ).first()
    if job_announce:
        db.session.delete(job_announce)
    db.session.add(Announcement(
        title=f"JOB TAKEN #{order.id}",
        body=f"Writer {writer_user.name} was approved for this job.",
        audience="public",
        category="jobs_taken"
    ))

    admin_sender = current_user.id
    db.session.add(Message(
        sender_id=admin_sender,
        receiver_id=order.user_id,
        content=f"[Order #{order.id}] Writer {writer_user.name} has taken your job. Open order chat to communicate.",
        is_admin=True
    ))
    db.session.add(Message(
        sender_id=admin_sender,
        receiver_id=app_item.writer_user_id,
        content=f"[Order #{order.id}] Your application was approved. Open order chat to communicate with the client.",
        is_admin=True
    ))
    db.session.commit()

    client_user = User.query.get(order.user_id)
    if client_user:
        tracking_url = url_for("main.dashboard", _external=True)
        order_chat_url = url_for("main.order_chat", order_id=order.id, _external=True)
        email_body = (
            f"Hello {client_user.name},\n\n"
            f"Your order #{order.id} has been assigned to writer {writer_user.name}.\n"
            f"You can now track progress and chat directly with your writer.\n\n"
            f"Track order: {tracking_url}\n"
            f"Open order chat: {order_chat_url}\n\n"
            "Thank you for choosing AcademicPro."
        )
        msg = MailMessage(
            subject=f"Order #{order.id} assigned - writer {writer_user.name}",
            recipients=[client_user.email],
            body=email_body,
        )
        _send_mail_safely(msg)

    flash("Writer approved and client notified.", "success")
    return redirect(url_for("main.admin_orders"))


@main.route("/orders/<int:order_id>/chat", methods=["GET", "POST"])
@login_required
def order_chat(order_id):
    order = Order.query.get_or_404(order_id)
    approved_app, allowed_ids = _order_access_context(order)
    if current_user.id not in allowed_ids and not current_user.is_admin:
        abort(403)

    status_lower = (order.status or "").lower()
    chat_active = status_lower in ("open", "in progress", "revision") and approved_app is not None
    if request.method == "POST":
        if not chat_active:
            flash("Order chat is inactive. You can only contact admin for closed orders.", "warning")
            return redirect(url_for("main.order_chat", order_id=order.id))
        raw = (request.form.get("message") or "").strip()
        uploaded = request.files.get("file")
        prohibited = {"insult", "idiot", "stupid", "moron", "dumb", "trash", "hate"}
        lowered = raw.lower()
        if raw and any(bad in lowered for bad in prohibited):
            admin = _get_primary_admin()
            if admin:
                db.session.add(Message(
                    sender_id=current_user.id,
                    receiver_id=admin.id,
                    content=f"[Moderation] Prohibited language attempt in Order #{order.id} by {current_user.email}.",
                    is_admin=False,
                    is_read=False
                ))
                db.session.commit()
            flash("Please keep communication respectful. Insulting language is not allowed.", "danger")
            return redirect(url_for("main.order_chat", order_id=order.id))
        if raw:
            if current_user.id == order.user_id and approved_app:
                receiver_id = approved_app.writer_user_id
            elif approved_app and current_user.id == approved_app.writer_user_id:
                receiver_id = order.user_id
            else:
                receiver_id = order.user_id
            db.session.add(Message(
                sender_id=current_user.id,
                receiver_id=receiver_id,
                content=f"[Order #{order.id}] {raw}",
                is_admin=current_user.is_admin,
                is_read=False
            ))
        if uploaded and uploaded.filename:
            if not allowed_file(uploaded.filename):
                flash("Unsupported file type.", "danger")
                return redirect(url_for("main.order_chat", order_id=order.id))
            filename = secure_filename(uploaded.filename)
            stored = f"order_{order.id}_{int(datetime.utcnow().timestamp())}_{filename}"
            os.makedirs(UPLOAD_FOLDER, exist_ok=True)
            uploaded.save(os.path.join(UPLOAD_FOLDER, stored))
            db.session.add(OrderFile(
                filename=stored,
                uploader=current_user.name,
                order_id=order.id
            ))
        db.session.commit()
        if raw or (uploaded and uploaded.filename):
            flash("Update sent.", "success")
        return redirect(url_for("main.order_chat", order_id=order.id))

    messages = Message.query.filter(
        Message.content.like(f"[Order #{order.id}]%")
    ).order_by(Message.timestamp.asc()).all()
    for msg in messages:
        if msg.receiver_id == current_user.id and not msg.is_read:
            msg.is_read = True
    db.session.commit()
    order_files = OrderFile.query.filter_by(order_id=order.id).order_by(OrderFile.uploaded_at.desc()).all()
    writer_user = User.query.get(approved_app.writer_user_id) if approved_app else None
    writer_profile = Writer.query.filter_by(name=writer_user.name, approved=True).first() if writer_user else None
    existing_review = None
    if writer_profile and current_user.id == order.user_id and (order.status or "").lower() == "completed":
        existing_review = OrderReview.query.filter_by(order_id=order.id, user_id=current_user.id).first()
    milestones = [
        {"label": "Writer Assigned", "done": bool(approved_app)},
        {"label": "Outline Approved", "done": "outline" in status_lower or "in progress" in status_lower or "completed" in status_lower},
        {"label": "Research Phase", "done": "research" in status_lower or "in progress" in status_lower or "completed" in status_lower},
        {"label": "Draft Submitted", "done": "draft" in status_lower or "revision" in status_lower or "completed" in status_lower},
        {"label": "Plagiarism Check", "done": "plagiarism" in status_lower or "completed" in status_lower},
        {"label": "Revision", "done": "revision" in status_lower},
        {"label": "Completed", "done": "completed" in status_lower},
    ]
    done_count = sum(1 for m in milestones if m["done"])
    progress_percent = int((done_count / len(milestones)) * 100) if milestones else 0

    file_groups = {"Reference Materials": [], "Drafts": [], "Final Deliverables": [], "Other Files": []}
    for f in order_files:
        name_lower = (f.filename or "").lower()
        version = None
        for tag in ("v1", "v2", "v3", "v4", "v5"):
            if tag in name_lower:
                version = tag.upper()
                break
        category = "Other Files"
        if "final" in name_lower:
            category = "Final Deliverables"
        elif "draft" in name_lower:
            category = "Drafts"
        elif writer_user and f.uploader == writer_user.name:
            category = "Drafts"
        elif f.uploader == order.user.name:
            category = "Reference Materials"
        file_groups[category].append({"file": f, "version": version})
    file_group_list = [(k, v) for k, v in file_groups.items() if v]

    admin = _get_primary_admin()
    admin_messages = []
    if admin:
        admin_messages = Message.query.filter(
            (
                ((Message.sender_id == current_user.id) & (Message.receiver_id == admin.id))
                | ((Message.sender_id == admin.id) & (Message.receiver_id == current_user.id))
            )
            & Message.content.like(f"[Admin Chat #{order.id}]%")
        ).order_by(Message.timestamp.asc()).all()

    return render_template(
        "order_chat.html",
        order=order,
        messages=messages,
        approved_app=approved_app,
        order_files=order_files,
        writer_user=writer_user,
        writer_profile=writer_profile,
        milestones=milestones,
        progress_percent=progress_percent,
        file_groups=file_group_list,
        chat_active=chat_active,
        chat_status=status_lower,
        admin_messages=admin_messages,
        existing_review=existing_review,
    )


@main.route("/orders/<int:order_id>/chat/messages", methods=["GET"])
@login_required
def order_chat_messages(order_id):
    order = Order.query.get_or_404(order_id)
    approved_app, allowed_ids = _order_access_context(order)
    if current_user.id not in allowed_ids and not current_user.is_admin:
        abort(403)

    status_lower = (order.status or "").lower()
    chat_active = status_lower in ("open", "in progress", "revision") and approved_app is not None
    thread = Message.query.filter(
        Message.content.like(f"[Order #{order.id}]%")
    ).order_by(Message.timestamp.asc()).all()

    unread = [m for m in thread if m.receiver_id == current_user.id and not m.is_read]
    for item in unread:
        item.is_read = True
    if unread:
        db.session.commit()

    payload = [{
        "id": m.id,
        "mine": m.sender_id == current_user.id,
        "content": _strip_tag(m.content, rf"^\[Order #{order.id}\]\s*"),
        "timestamp": m.timestamp.strftime("%Y-%m-%d %H:%M") if m.timestamp else ""
    } for m in thread]
    return jsonify({"ok": True, "chat_active": chat_active, "messages": payload})


@main.route("/orders/<int:order_id>/admin/messages", methods=["GET"])
@login_required
def order_admin_messages(order_id):
    order = Order.query.get_or_404(order_id)
    approved_app, allowed_ids = _order_access_context(order)
    if current_user.id not in allowed_ids and not current_user.is_admin:
        abort(403)
    admin = _get_primary_admin()
    if not admin:
        return jsonify({"ok": True, "messages": []})

    thread = Message.query.filter(
        (
            ((Message.sender_id == current_user.id) & (Message.receiver_id == admin.id))
            | ((Message.sender_id == admin.id) & (Message.receiver_id == current_user.id))
        )
        & Message.content.like(f"[Admin Chat #{order.id}]%")
    ).order_by(Message.timestamp.asc()).all()

    unread = [m for m in thread if m.receiver_id == current_user.id and not m.is_read]
    for item in unread:
        item.is_read = True
    if unread:
        db.session.commit()

    payload = [{
        "id": m.id,
        "mine": m.sender_id == current_user.id,
        "content": _strip_tag(m.content, rf"^\[Admin Chat #{order.id}\]\s*"),
        "timestamp": m.timestamp.strftime("%Y-%m-%d %H:%M") if m.timestamp else ""
    } for m in thread]
    return jsonify({"ok": True, "messages": payload})


@main.route("/orders/<int:order_id>/review", methods=["POST"])
@login_required
def submit_order_review(order_id):
    order = Order.query.get_or_404(order_id)
    if current_user.id != order.user_id:
        abort(403)
    if (order.status or "").lower() != "completed":
        flash("Reviews can only be submitted after completion.", "warning")
        return redirect(url_for("main.order_chat", order_id=order.id))
    approved_app = JobApplication.query.filter_by(order_id=order.id, status="approved").first()
    if not approved_app:
        flash("Writer not found for this order.", "danger")
        return redirect(url_for("main.order_chat", order_id=order.id))
    writer_user = User.query.get(approved_app.writer_user_id)
    writer_profile = Writer.query.filter_by(name=writer_user.name, approved=True).first() if writer_user else None
    if not writer_profile:
        flash("Writer profile is unavailable.", "danger")
        return redirect(url_for("main.order_chat", order_id=order.id))

    rating = request.form.get("rating", type=int)
    comment = (request.form.get("comment") or "").strip()
    if not rating or rating < 1 or rating > 5:
        flash("Rating must be between 1 and 5.", "danger")
        return redirect(url_for("main.order_chat", order_id=order.id))

    existing = OrderReview.query.filter_by(order_id=order.id, user_id=current_user.id).first()
    if existing:
        flash("You already reviewed this order.", "info")
        return redirect(url_for("main.order_chat", order_id=order.id))

    db.session.add(OrderReview(
        order_id=order.id,
        writer_id=writer_profile.id,
        user_id=current_user.id,
        rating=rating,
        comment=comment
    ))
    db.session.commit()

    ratings = OrderReview.query.filter_by(writer_id=writer_profile.id).all()
    if ratings:
        writer_profile.rating = round(sum(r.rating for r in ratings) / len(ratings), 2)
        db.session.commit()

    flash("Thank you for your feedback.", "success")
    return redirect(url_for("main.order_chat", order_id=order.id))


@main.route("/orders/<int:order_id>/admin-message", methods=["POST"])
@login_required
def order_admin_message(order_id):
    order = Order.query.get_or_404(order_id)
    if current_user.id != order.user_id and not current_user.is_admin:
        approved_app = JobApplication.query.filter_by(order_id=order.id, status="approved").first()
        if not approved_app or approved_app.writer_user_id != current_user.id:
            abort(403)
    text = (request.form.get("admin_message") or "").strip()
    if not text:
        flash("Message cannot be empty.", "danger")
        return redirect(url_for("main.order_chat", order_id=order.id))
    admin = _get_primary_admin()
    if not admin:
        flash("Admin is unavailable right now.", "warning")
        return redirect(url_for("main.order_chat", order_id=order.id))
    db.session.add(Message(
        sender_id=current_user.id,
        receiver_id=admin.id,
        content=f"[Admin Chat #{order.id}] {text}",
        is_admin=False,
        is_read=False
    ))
    db.session.commit()
    flash("Admin message sent.", "success")
    return redirect(url_for("main.order_chat", order_id=order.id))


@main.route("/orders/files/<path:filename>")
@login_required
def download_order_file(filename):
    file_item = OrderFile.query.filter_by(filename=filename).first_or_404()
    order = Order.query.get_or_404(file_item.order_id)
    approved_app = JobApplication.query.filter_by(order_id=order.id, status="approved").first()
    allowed_ids = {order.user_id}
    if approved_app:
        allowed_ids.add(approved_app.writer_user_id)
    if current_user.is_admin:
        allowed_ids.add(current_user.id)
    if current_user.id not in allowed_ids:
        abort(403)
    return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)

@main.route("/admin/order/delete/<int:id>")
def delete_order(id):
    order = Order.query.get_or_404(id)
    db.session.delete(order)
    db.session.commit()
    flash("Order deleted successfully.", "info")
    return redirect(url_for("main.admin_orders"))

@main.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == "GET":
        return redirect(url_for("main.index"))
    message = request.form.get('message')
    # Choose how to associate sender/receiver. Here, sender_id=0 (guest), receiver_id=1 (admin)
    admin = _get_primary_admin()
    receiver_id = admin.id if admin else 1
    new_msg = Message(
        sender_id=current_user.id if current_user.is_authenticated else 0,
        receiver_id=receiver_id,
        content=message,
        is_admin=False,
        is_read=False
    )
    db.session.add(new_msg)
    db.session.commit()
    return redirect(url_for('main.index', success=True))


@main.route("/guest/chat/send", methods=["POST"])
def guest_chat_send():
    payload = request.get_json(silent=True) or {}
    email = (payload.get("email") or "").strip().lower()
    text = (payload.get("message") or "").strip()
    if not text:
        return jsonify({"ok": False, "error": "Message is required."}), 400
    admin = _get_primary_admin()
    receiver_id = admin.id if admin else 1
    thread_id = _get_guest_thread_id()
    prefix = _guest_thread_prefix(thread_id)
    if email:
        content = f"{prefix} [Guest:{email}] {text}"
    else:
        content = f"{prefix} [Guest] {text}"
    db.session.add(
        Message(
            sender_id=0,
            receiver_id=receiver_id,
            content=content,
            is_admin=False,
            is_read=False,
        )
    )
    db.session.commit()
    return jsonify({"ok": True, "message": "Message sent. Admin can reply here live."})


@main.route("/guest/chat/messages", methods=["GET"])
def guest_chat_messages():
    thread_id = _get_guest_thread_id()
    prefix = _guest_thread_prefix(thread_id)
    like_pattern = f"%{prefix}%"
    messages = Message.query.filter(
        ((Message.sender_id == 0) | (Message.receiver_id == 0)) &
        (Message.content.like(like_pattern))
    ).order_by(Message.timestamp.asc()).all()

    unread_admin = [m for m in messages if m.sender_id != 0 and not m.is_read]
    for row in unread_admin:
        row.is_read = True
    if unread_admin:
        db.session.commit()

    payload = [{
        "id": m.id,
        "from_admin": m.sender_id != 0,
        "content": re.sub(r"^\[GUEST_THREAD:[^\]]+\]\s*", "", m.content or "").strip(),
        "timestamp": m.timestamp.strftime("%Y-%m-%d %H:%M") if m.timestamp else None
    } for m in messages]
    return jsonify({"ok": True, "messages": payload})


@main.route("/guest/ai/ask", methods=["POST"])
def guest_ai_ask():
    payload = request.get_json(silent=True) or {}
    question = (payload.get("question") or "").strip()
    return jsonify({"ok": True, "answer": _guest_ai_reply(question)})


@main.route("/ai/chat/history", methods=["GET"])
def ai_chat_history():
    _cleanup_temporary_ai_history()
    if current_user.is_authenticated:
        rows = AIConversationMessage.query.filter_by(user_id=current_user.id).order_by(AIConversationMessage.created_at.asc()).all()
    else:
        thread_id = _get_ai_guest_thread_id()
        rows = AIConversationMessage.query.filter_by(user_id=None, guest_thread_id=thread_id).order_by(AIConversationMessage.created_at.asc()).all()
    payload = [{
        "id": r.id,
        "role": r.role,
        "content": r.content,
        "timestamp": r.created_at.strftime("%Y-%m-%d %H:%M") if r.created_at else ""
    } for r in rows]
    return jsonify({"ok": True, "messages": payload})


@main.route("/ai/chat/send", methods=["POST"])
def ai_chat_send():
    _cleanup_temporary_ai_history()
    payload = request.get_json(silent=True) or {}
    question = (payload.get("message") or "").strip()
    if not question:
        return jsonify({"ok": False, "error": "Message is required."}), 400

    if current_user.is_authenticated:
        user_id = current_user.id
        guest_thread_id = None
        history_rows = AIConversationMessage.query.filter_by(user_id=user_id).order_by(AIConversationMessage.created_at.asc()).all()
    else:
        user_id = None
        guest_thread_id = _get_ai_guest_thread_id()
        history_rows = AIConversationMessage.query.filter_by(user_id=None, guest_thread_id=guest_thread_id).order_by(AIConversationMessage.created_at.asc()).all()

    history = [{"role": h.role, "content": h.content} for h in history_rows[-12:]]
    answer = _ai_generate_reply(question, history, current_user if current_user.is_authenticated else None)

    db.session.add(AIConversationMessage(
        user_id=user_id,
        guest_thread_id=guest_thread_id,
        role="user",
        content=question
    ))
    db.session.add(AIConversationMessage(
        user_id=user_id,
        guest_thread_id=guest_thread_id,
        role="assistant",
        content=answer
    ))
    db.session.commit()
    return jsonify({"ok": True, "answer": answer})


@main.route("/pricing/estimate", methods=["POST"])
def pricing_estimate():
    payload = request.get_json(silent=True) or {}
    task_type = (payload.get("task_type") or "Essay").strip()
    level = (payload.get("level") or "Undergrad").strip()
    word_count = payload.get("word_count", 1000)
    deadline_str = (payload.get("deadline") or "").strip()

    try:
        word_count = int(word_count)
    except (TypeError, ValueError):
        word_count = 1000
    if word_count <= 0:
        word_count = 1000

    try:
        deadline_dt = datetime.strptime(deadline_str, "%Y-%m-%d") if deadline_str else (datetime.utcnow() + timedelta(days=7))
    except ValueError:
        deadline_dt = datetime.utcnow() + timedelta(days=7)

    base = calculate_price(word_count, level, deadline_dt)
    estimate = round(base * _task_multiplier(task_type), 2)
    return jsonify({"ok": True, "estimate": estimate})

@main.route('/admin/chat/grouped')
def admin_chat_grouped():
    grouped_chats = get_grouped_chats(current_user.id)
    partner_ids = [pid for pid in grouped_chats.keys() if isinstance(pid, int) and pid > 0]
    users = {u.id: u for u in User.query.filter(User.id.in_(partner_ids)).all()} if partner_ids else {}
    return render_template('admin_chat_grouped.html', grouped_chats=grouped_chats, chat_users=users)

@main.route('/admin/chat/reply', methods=['POST'])
def reply_to_user():
    user_id = request.form.get('user_id')
    guest_thread_id = (request.form.get("guest_thread_id") or "").strip().lower()
    message = (request.form.get('message') or "").strip()
    if not message:
        flash("Message cannot be empty.", "warning")
        return redirect(url_for('main.admin_chat_grouped'))

    if guest_thread_id:
        msg = Message(
            sender_id=current_user.id,
            receiver_id=0,
            content=f"{_guest_thread_prefix(guest_thread_id)} {message}",
            is_admin=True,
            is_read=False
        )
    else:
        msg = Message(
            sender_id=current_user.id,
            receiver_id=int(user_id),
            content=message,
            is_admin=True,
            is_read=False
        )
    db.session.add(msg)
    db.session.commit()
    return redirect(url_for('main.admin_chat_grouped'))

@main.route('/chat/messages')
@login_required
def get_messages_json():
    if current_user.is_admin:
        partner_id = request.args.get("partner_id", type=int)
        if partner_id:
            messages = Message.query.filter(
                ((Message.sender_id == current_user.id) & (Message.receiver_id == partner_id)) |
                ((Message.sender_id == partner_id) & (Message.receiver_id == current_user.id))
            ).order_by(Message.timestamp.asc()).all()
        else:
            messages = Message.query.order_by(Message.timestamp.asc()).all()
    else:
        messages = Message.query.filter(
            (Message.sender_id == current_user.id) |
            (Message.receiver_id == current_user.id)
        ).order_by(Message.timestamp.asc()).all()

    result = [{
        "sender_id": msg.sender_id,
        "receiver_id": msg.receiver_id,
        "content": msg.content,
        "timestamp": msg.timestamp.strftime("%Y-%m-%d %H:%M") if msg.timestamp else None
    } for msg in messages]
    return jsonify(result)

@main.route('/admin_chat')
def admin_chat():
    if not current_user.is_admin:
        return redirect(url_for('main.index'))
    return render_template("admin_chat.html")

@main.route('/admin/uploads', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        uploaded = request.files['file']
        if uploaded and allowed_file(uploaded.filename):
            filename = secure_filename(uploaded.filename)
            uploaded.save(os.path.join(UPLOAD_FOLDER, filename))

            file_entry = OrderFile(filename=filename, uploader='admin')
            db.session.add(file_entry)
            db.session.commit()
            return redirect(url_for('main.upload_file'))

    files = OrderFile.query.order_by(OrderFile.uploaded_at.desc()).all()
    return render_template('admin_uploads.html', files=files)

@main.route('/admin/payments')
def admin_payments():
    if not current_user.is_admin:
        abort(403)
    return render_template('admin_payments.html')

@main.route("/Samples")
def Samples():
    style = (request.args.get("style") or "").strip()
    level = (request.args.get("level") or "").strip()
    subject = (request.args.get("subject") or "").strip()
    category = (request.args.get("category") or "").strip()
    q = (request.args.get("q") or "").strip()
    query = Sample.query
    if style:
        query = query.filter(Sample.style.ilike(f"%{style}%"))
    if level:
        query = query.filter(Sample.level.ilike(f"%{level}%"))
    if subject:
        query = query.filter(Sample.subject.ilike(f"%{subject}%"))
    if category:
        query = query.filter(Sample.category.ilike(f"%{category}%"))
    if q:
        query = query.filter(
            (Sample.title.ilike(f"%{q}%"))
            | (Sample.content.ilike(f"%{q}%"))
            | (Sample.subject.ilike(f"%{q}%"))
            | (Sample.category.ilike(f"%{q}%"))
        )
    samples = query.order_by(Sample.category.asc(), Sample.title.asc()).all()
    styles = sorted({row[0] for row in db.session.query(Sample.style).distinct().all() if row[0]})
    levels = sorted({row[0] for row in db.session.query(Sample.level).distinct().all() if row[0]})
    subjects = sorted({row[0] for row in db.session.query(Sample.subject).distinct().all() if row[0]})
    categories = sorted({row[0] for row in db.session.query(Sample.category).distinct().all() if row[0]})
    grouped_samples = []
    current_category = None
    bucket = []
    for sample in samples:
        if sample.category != current_category:
            if bucket:
                grouped_samples.append((current_category, bucket))
            current_category = sample.category
            bucket = []
        bucket.append(sample)
    if bucket:
        grouped_samples.append((current_category, bucket))
    return render_template(
        "Samples.html",
        samples=samples,
        grouped_samples=grouped_samples,
        selected_style=style,
        selected_level=level,
        selected_subject=subject,
        selected_category=category,
        query=q,
        styles=styles,
        levels=levels,
        subjects=subjects,
        categories=categories,
    )


@main.route("/samples/<int:sample_id>")
def sample_detail(sample_id):
    sample = Sample.query.get_or_404(sample_id)
    return render_template("sample_detail.html", sample=sample)

@main.route('/admin/announcements', methods=['GET', 'POST'])
def admin_announcements():
    if request.method == 'POST':
        title = request.form['title']
        body = request.form['body']
        audience = request.form.get('audience', 'public')
        category = request.form.get('category', 'general')
        new_announcement = Announcement(title=title, body=body, audience=audience, category=category)
        db.session.add(new_announcement)
        db.session.commit()
        flash("Announcement posted!", "success")
        return redirect(url_for('main.admin_announcements'))

    page = request.args.get('page', 1, type=int)
    category = request.args.get('category')

    query = Announcement.query.order_by(Announcement.created_at.desc())
    if category:
        query = query.filter_by(category=category)

    pagination = query.paginate(page=page, per_page=5)
    announcements = pagination.items

    return render_template("admin_announcements.html",
                           announcements=announcements,
                           pagination=pagination,
                           selected_category=category)


@main.route('/admin/settlements')
def admin_settlements():
    payments = Payment.query.order_by(Payment.created_at.desc()).all()
    summary = {
        "pending_amount": round(sum((p.amount or 0) for p in payments if p.status == "pending"), 2),
        "completed_amount": round(sum((p.amount or 0) for p in payments if p.status == "completed"), 2),
        "failed_amount": round(sum((p.amount or 0) for p in payments if p.status == "failed"), 2),
        "count": len(payments),
    }
    return render_template("admin_settlements.html", payments=payments, summary=summary)


@main.route('/admin/disputes')
def admin_disputes():
    # Dispute center MVP: highlights overdue/in-progress items as candidates.
    now = datetime.utcnow()
    queue = Order.query.filter(
        Order.status.in_(["Open", "In Progress"]),
        Order.deadline < now
    ).order_by(Order.deadline.asc()).all()
    return render_template("admin_disputes.html", disputes=queue)


@main.route('/admin/activity-logs')
def admin_activity_logs():
    recent_messages = Message.query.order_by(Message.timestamp.desc()).limit(50).all()
    recent_orders = Order.query.order_by(Order.created_at.desc()).limit(25).all()
    recent_announcements = Announcement.query.order_by(Announcement.created_at.desc()).limit(25).all()
    return render_template(
        "admin_activity_logs.html",
        recent_messages=recent_messages,
        recent_orders=recent_orders,
        recent_announcements=recent_announcements
    )


@main.route('/admin/marketing')
def admin_marketing():
    blog_count = BlogPost.query.count()
    sample_count = Sample.query.count()
    lead_count = Lead.query.count()
    order_count = Order.query.count()
    conversion = round((order_count / lead_count) * 100, 2) if lead_count else 0.0
    return render_template(
        "admin_marketing.html",
        blog_count=blog_count,
        sample_count=sample_count,
        lead_count=lead_count,
        order_count=order_count,
        conversion=conversion
    )


@main.route('/admin/roles')
def admin_roles():
    # RBAC scaffold view for future sub-admin expansion.
    roles = [
        {"name": "Super Admin", "scope": "Full access", "users": 1},
        {"name": "Support", "scope": "Messages, Orders, Disputes", "users": 0},
        {"name": "Editor", "scope": "Blog, Samples, Marketing", "users": 0},
    ]
    return render_template("admin_roles.html", roles=roles)

@main.route('/admin/settings', methods=['GET', 'POST'])
def admin_settings():
    if not current_user.is_admin:
        abort(403)

    def get_setting(key, default=""):
        row = SiteSetting.query.filter_by(key=key).first()
        return row.value if row and row.value is not None else default

    def upsert_setting(key, value):
        row = SiteSetting.query.filter_by(key=key).first()
        if not row:
            row = SiteSetting(key=key, value=value)
            db.session.add(row)
        else:
            row.value = value

    if request.method == "POST":
        form_type = request.form.get("form_type", "").strip()

        if form_type == "platform":
            commission_raw = (request.form.get("commission_rate") or "").strip()
            refund_policy = (request.form.get("refund_policy") or "").strip()
            try:
                commission = float(commission_raw)
            except ValueError:
                flash("Commission rate must be a valid number.", "danger")
                return redirect(url_for("main.admin_settings"))
            if commission < 0 or commission > 100:
                flash("Commission rate must be between 0 and 100.", "danger")
                return redirect(url_for("main.admin_settings"))
            upsert_setting("commission_rate", str(commission))
            upsert_setting("refund_policy", refund_policy)
            db.session.commit()
            flash("Platform settings updated.", "success")
            return redirect(url_for("main.admin_settings"))

        if form_type == "password":
            current_password = request.form.get("current_password") or ""
            new_password = request.form.get("new_password") or ""
            confirm_password = request.form.get("confirm_password") or ""

            if not current_password or not new_password or not confirm_password:
                flash("All password fields are required.", "danger")
                return redirect(url_for("main.admin_settings"))
            if not check_password_hash(current_user.password_hash, current_password):
                flash("Current password is incorrect.", "danger")
                return redirect(url_for("main.admin_settings"))
            if len(new_password) < 8:
                flash("New password must be at least 8 characters.", "danger")
                return redirect(url_for("main.admin_settings"))
            if new_password != confirm_password:
                flash("New password and confirmation do not match.", "danger")
                return redirect(url_for("main.admin_settings"))
            current_user.password_hash = generate_password_hash(new_password)
            db.session.commit()
            flash("Admin password updated successfully.", "success")
            return redirect(url_for("main.admin_settings"))

        flash("Invalid settings request.", "warning")
        return redirect(url_for("main.admin_settings"))

    settings = {
        "commission_rate": get_setting("commission_rate", "20"),
        "refund_policy": get_setting(
            "refund_policy",
            "Refund requests are reviewed by admin based on work status and evidence.",
        ),
    }
    return render_template('admin_settings.html', settings=settings)

@main.route('/blogs')
@main.route('/blog')
def public_blogs():
    return redirect(url_for("main.blog_list", **request.args))

@main.route("/Blog/<int:id>")
def blog_detail(id):
    blog = BlogPost.query.get_or_404(id)
    return render_template("blog_detail.html", blog=blog)

@main.route('/blog/manage', methods=['GET', 'POST'])
@login_required
def blog_manage():
    if not _can_manage_blog(current_user):
        abort(403)
    if request.method == 'POST':
        title = (request.form.get('title') or "").strip()
        excerpt = (request.form.get('excerpt') or "").strip() or None
        category = (request.form.get('category') or "Academic Skills").strip()
        pillar = (request.form.get('pillar') or "").strip() or None
        cluster_topic = (request.form.get('cluster_topic') or "").strip() or None
        is_published = bool(request.form.get("is_published"))
        content = (request.form.get('content') or "").strip()

        if not title or not content:
            flash("Title and content are required.", "warning")
            return redirect(url_for('main.blog_manage'))

        new_post = BlogPost(
            title=title,
            excerpt=excerpt,
            category=category,
            pillar=pillar,
            cluster_topic=cluster_topic,
            content=content,
            author_id=current_user.id,
            author_name=current_user.name,
            is_published=is_published
        )
        db.session.add(new_post)
        db.session.commit()
        flash("Blog post published.", "success")
        return redirect(url_for('main.blog_manage'))

    posts = BlogPost.query.order_by(BlogPost.created_at.desc()).all()
    return render_template('blog_manage.html', posts=posts)


@main.route('/admin/Blog', methods=['GET', 'POST'])
@login_required
def admin_Blog():
    if not current_user.is_admin:
        abort(403)
    return redirect(url_for("main.blog_manage"))

@main.route('/admin/blog/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_blog(id):
    if not _can_manage_blog(current_user):
        abort(403)
    post = BlogPost.query.get_or_404(id)
    if not current_user.is_admin and post.author_id != current_user.id:
        abort(403)
    if request.method == 'POST':
        post.title = (request.form.get('title') or "").strip()
        post.excerpt = (request.form.get('excerpt') or "").strip() or None
        post.category = (request.form.get('category') or "Academic Skills").strip()
        post.pillar = (request.form.get('pillar') or "").strip() or None
        post.cluster_topic = (request.form.get('cluster_topic') or "").strip() or None
        post.content = (request.form.get('content') or "").strip()
        post.is_published = bool(request.form.get("is_published"))
        post.author_name = post.author_name or current_user.name
        if not post.title or not post.content:
            flash("Title and content are required.", "warning")
            return redirect(url_for('main.edit_blog', id=post.id))
        db.session.commit()
        flash('Blog post updated!', 'success')
        return redirect(url_for('main.blog_manage'))
    return render_template('edit_blog.html', post=post)

@main.route('/admin/blog/<int:id>/delete')
@login_required
def delete_blog(id):
    if not _can_manage_blog(current_user):
        abort(403)
    post = BlogPost.query.get_or_404(id)
    if not current_user.is_admin and post.author_id != current_user.id:
        abort(403)
    db.session.delete(post)
    db.session.commit()
    flash('Blog post deleted.', 'info')
    return redirect(url_for('main.blog_manage'))

@main.route('/admin/messages/json', methods=['GET'])
@login_required
def admin_view_all():
    if not current_user.is_admin:
        return "Forbidden", 403
    all_msgs = Message.query.order_by(Message.timestamp).all()
    return jsonify([
        {
            'from': m.sender_id,
            'to': m.receiver_id,
            'content': m.content,
            'is_admin': m.is_admin,
            'timestamp': m.timestamp.strftime("%Y-%m-%d %H:%M") if m.timestamp else None
        } for m in all_msgs
    ])

# ------------------------
# 🏢 Company Section Routes
# ------------------------
@main.route('/about')
def about():
    return render_template('about.html')


@main.route('/services')
def services_page():
    return render_template('services.html')

@main.route('/testimonials')
def testimonials():
    return render_template('testimonials.html')

@main.route('/privacy-policy')
def privacy_policy():
    return render_template('privacy_policy.html')

@main.route('/faq')
def faq():
    return render_template('faq.html')

@main.route('/how-it-works')
def how_it_works():
    return render_template('how_it_works.html')

@main.route('/hiring')
def hiring():
    return render_template('hiring.html')

@main.route('/terms')
def terms():
    return render_template('terms.html')

@main.route('/fair-use')
def fair_use():
    return render_template('fair_use.html')

@main.route('/payment-policy')
def payment_policy():
    return render_template('payment_policy.html')

@main.route('/dont_buy_accounts')
def dont_buy_accounts():
    return render_template('dont_buy_accounts.html')

# ------------------------
# 🧾 Services Section Routes
# ------------------------

@main.route('/services/essay-writing')
def essay_writing():
    return render_template('services/essay_writing.html')

@main.route('/services/research-papers')
def research_papers():
    return render_template('services/research_papers.html')

@main.route('/services/case-studies')
def case_studies():
    return render_template('services/case_studies.html')

@main.route('/services/dissertations')
def dissertations():
    return render_template('services/dissertations.html')

@main.route('/services/theses')
def theses():
    return render_template('services/theses.html')

@main.route('/services/speeches')
def speeches():
    return render_template('services/speeches.html')

@main.route('/services/assignments')
def assignments():
    return render_template('services/assignments.html')

@main.route('/services/narrative-essays')
def narrative_essays():
    return render_template('services/narrative_essays.html')

@main.route('/services/analytical-essays')
def analytical_essays():
    return render_template('services/analytical_essays.html')

@main.route('/services/persuasive-essays')
def persuasive_essays():
    return render_template('services/persuasive_essays.html')

@main.route('/services/admission-help')
def admission_help():
    return render_template('services/admission_help.html')

@main.route('/services/literature-reviews')
def literature_reviews():
    return render_template('services/literature_reviews.html')

@main.route('/services/book-reports')
def book_reports():
    return render_template('services/book_reports.html')

@main.context_processor
def inject_now():
    from datetime import datetime
    return {'current_year': datetime.now().year}



