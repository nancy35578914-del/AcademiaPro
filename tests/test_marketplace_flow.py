from datetime import datetime, timedelta
import os
import tempfile

import pytest
from werkzeug.security import generate_password_hash

from app import create_app
from app import mail
from app.extensions import db
from app.models import Announcement, Application, JobApplication, Message, Order, User


@pytest.fixture()
def app(monkeypatch):
    fd, test_db_path = tempfile.mkstemp(prefix="academicpro_test_", suffix=".db")
    os.close(fd)
    monkeypatch.setenv("SQLALCHEMY_DATABASE_URI", f"sqlite:///{test_db_path}")
    app = create_app()
    app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
        MAIL_SUPPRESS_SEND=True,
    )
    monkeypatch.setattr(mail, "send", lambda _msg: None)
    with app.app_context():
        db.drop_all()
        db.create_all()
    yield app
    with app.app_context():
        db.session.remove()
        db.drop_all()
        db.engine.dispose()
    if os.path.exists(test_db_path):
        try:
            os.remove(test_db_path)
        except PermissionError:
            pass


@pytest.fixture()
def client(app):
    return app.test_client()


def _create_user(email, name, password):
    user = User(
        email=email,
        name=name,
        password_hash=generate_password_hash(password),
    )
    db.session.add(user)
    db.session.commit()
    return user


def _login(client, email, password):
    return client.post(
        "/login",
        data={"email": email, "password": password},
        follow_redirects=True,
    )


def _admin_login(client, email, password):
    return client.post(
        "/admin/login",
        data={"email": email, "password": password},
        follow_redirects=True,
    )


def _logout(client):
    return client.get("/logout", follow_redirects=True)


def test_client_post_writer_apply_admin_approve_flow(app, client):
    with app.app_context():
        client_user = _create_user("client@example.com", "Client User", "pass12345")
        writer_user = _create_user("writer@example.com", "Writer User", "pass12345")
        admin_user = _create_user("bwamistevenez001@gmail.com", "Admin User", "pass12345")
        db.session.add(
            Application(
                name=writer_user.name,
                email=writer_user.email,
                subject="Nursing",
                bio="Experienced academic writer.",
                approved=True,
            )
        )
        db.session.commit()
        client_id = client_user.id
        writer_id = writer_user.id
        admin_id = admin_user.id

    _login(client, "client@example.com", "pass12345")
    deadline = (datetime.utcnow() + timedelta(days=2)).strftime("%Y-%m-%d")
    client.post(
        "/order",
        data={
            "name": "Client User",
            "email": "client@example.com",
            "subject": "History Essay",
            "details": "Need a 1500-word essay.",
            "deadline": deadline,
        },
        follow_redirects=True,
    )
    _logout(client)

    with app.app_context():
        order = Order.query.filter_by(user_id=client_id).first()
        assert order is not None
        assert order.status == "Pending Review"
        assert order.job_posted is False
        order_id = order.id

    _admin_login(client, "bwamistevenez001@gmail.com", "pass12345")
    client.post(f"/admin/order/{order_id}/publish-job", follow_redirects=True)
    _logout(client)

    with app.app_context():
        order = Order.query.get(order_id)
        assert order.status == "Open"
        assert order.job_posted is True
        jobs_announcement = Announcement.query.filter(
            Announcement.category == "jobs",
            Announcement.title.like(f"JOB#{order.id} |%"),
        ).first()
        assert jobs_announcement is not None

    _login(client, "writer@example.com", "pass12345")
    client.post(
        f"/jobs/{order_id}/apply",
        data={"cover_note": "I can complete this quickly."},
        follow_redirects=True,
    )
    _logout(client)

    with app.app_context():
        job_app = JobApplication.query.filter_by(order_id=order_id, writer_user_id=writer_id).first()
        assert job_app is not None
        assert job_app.status == "pending"
        application_id = job_app.id

    _admin_login(client, "bwamistevenez001@gmail.com", "pass12345")
    client.post(f"/admin/job-applications/{application_id}/approve", follow_redirects=True)
    _logout(client)

    with app.app_context():
        updated_order = Order.query.get(order_id)
        assert updated_order.status == "In Progress"
        assert updated_order.assigned_at is not None

        open_announcement = Announcement.query.filter(
            Announcement.category == "jobs",
            Announcement.title.like(f"JOB#{order_id} |%"),
        ).first()
        assert open_announcement is None

        taken_announcement = Announcement.query.filter(
            Announcement.category == "jobs_taken",
            Announcement.title == f"JOB TAKEN #{order_id}",
        ).first()
        assert taken_announcement is not None

        client_notice = Message.query.filter_by(
            receiver_id=client_id,
            sender_id=admin_id,
            is_admin=True,
        ).filter(Message.content.like(f"[Order #{order_id}]%")).first()
        assert client_notice is not None

        writer_notice = Message.query.filter_by(
            receiver_id=writer_id,
            sender_id=admin_id,
            is_admin=True,
        ).filter(Message.content.like(f"[Order #{order_id}]%")).first()
        assert writer_notice is not None


def test_order_chat_access_control_and_messaging(app, client):
    with app.app_context():
        client_user = _create_user("client2@example.com", "Client Two", "pass12345")
        writer_user = _create_user("writer2@example.com", "Writer Two", "pass12345")
        outsider_user = _create_user("outsider@example.com", "Outsider", "pass12345")

        order = Order(
            topic="Business Case Study",
            description="Write a case analysis.",
            deadline=datetime.utcnow() + timedelta(days=3),
            word_count=1200,
            level="Undergrad",
            status="In Progress",
            user_id=client_user.id,
            assigned_at=datetime.utcnow(),
        )
        db.session.add(order)
        db.session.commit()

        db.session.add(
            JobApplication(
                order_id=order.id,
                writer_user_id=writer_user.id,
                status="approved",
                reviewed_at=datetime.utcnow(),
            )
        )
        db.session.commit()
        order_id = order.id
        outsider_email = outsider_user.email

    _login(client, outsider_email, "pass12345")
    outsider_resp = client.get(f"/orders/{order_id}/chat")
    _logout(client)
    assert outsider_resp.status_code == 403

    _login(client, "client2@example.com", "pass12345")
    client_get = client.get(f"/orders/{order_id}/chat")
    assert client_get.status_code == 200
    client.post(
        f"/orders/{order_id}/chat",
        data={"message": "Hello writer, please follow APA."},
        follow_redirects=True,
    )
    _logout(client)

    _login(client, "writer2@example.com", "pass12345")
    writer_get = client.get(f"/orders/{order_id}/chat")
    _logout(client)
    assert writer_get.status_code == 200

    with app.app_context():
        sent = Message.query.filter(
            Message.content.like(f"[Order #{order_id}]%"),
            Message.sender_id != 0,
        ).all()
        assert len(sent) >= 1
