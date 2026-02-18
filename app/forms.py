from wtforms.validators import DataRequired, Email, Length, EqualTo, Optional, InputRequired
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, DateField, PasswordField, SubmitField, IntegerField, SelectField, BooleanField, SelectMultipleField
from wtforms.validators import DataRequired, Email, EqualTo, Length
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Optional
from flask_wtf.file import FileField, FileAllowed

class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    name = StringField('Name', validators=[DataRequired(), Length(min=2, max=50)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    accept_terms = BooleanField('I agree to the Terms', validators=[InputRequired()])
    accept_privacy = BooleanField('I agree to the Privacy Policy', validators=[InputRequired()])
    submit = SubmitField('Register')

from wtforms.validators import ValidationError
from app.models import User

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class OrderForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    subject = StringField('Subject', validators=[DataRequired()])
    task_type = SelectField(
        "Task Type",
        choices=[
            ("Essay", "Essay"),
            ("Research Paper", "Research Paper"),
            ("Dissertation", "Dissertation"),
            ("Assignment", "Assignment"),
            ("Case Study", "Case Study"),
            ("Admission Essay", "Admission Essay"),
        ],
        validators=[Optional()],
    )
    word_count = IntegerField("Word Count", validators=[Optional()])
    level = SelectField(
        "Academic Level",
        choices=[("Undergrad", "Undergrad"), ("Masters", "Masters"), ("PhD", "PhD")],
        validators=[Optional()],
    )
    citation_style = SelectField(
        "Referencing Style",
        choices=[("APA", "APA"), ("MLA", "MLA"), ("Chicago", "Chicago"), ("Harvard", "Harvard")],
        validators=[Optional()],
    )
    sources_count = IntegerField("Minimum Sources", validators=[Optional()])
    currency = SelectField(
        "Currency",
        choices=[("USD", "USD"), ("GBP", "GBP"), ("EUR", "EUR")],
        validators=[Optional()],
    )
    timezone = SelectField(
        "Deadline Timezone",
        choices=[("UTC", "UTC"), ("America/New_York", "GMT-5 (New York)"), ("Europe/London", "GMT+0 (London)"), ("Africa/Nairobi", "GMT+3 (Nairobi)")],
        validators=[Optional()],
    )
    attachments = FileField("Upload Files", validators=[FileAllowed(['pdf', 'doc', 'docx', 'txt', 'png', 'jpg'], 'Unsupported file type')])
    details = TextAreaField('Details', validators=[DataRequired()])
    deadline = DateField('Deadline', validators=[DataRequired()])
    accept_terms = BooleanField('I agree to the Terms', validators=[InputRequired()])
    accept_privacy = BooleanField('I agree to the Privacy Policy', validators=[InputRequired()])

class ProfileForm(FlaskForm):
    name = StringField("Full Name", validators=[Optional()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("New Password", validators=[Optional()])
    confirm_password = PasswordField("Confirm Password", validators=[Optional(), EqualTo('password')])
    photo = FileField('Profile Photo', validators=[FileAllowed(['jpg', 'png', 'jpeg'], 'Images only!')])
    writer_portfolio = FileField('Writer Portfolio (PDF/DOC)', validators=[FileAllowed(['pdf', 'doc', 'docx'], 'Documents only!')])
    writer_resume = FileField('Writer Resume (PDF/DOC)', validators=[FileAllowed(['pdf', 'doc', 'docx'], 'Documents only!')])
    submit = SubmitField("Update Profile")

class SettingForm(FlaskForm):
    name = StringField("Full Name", validators=[Optional()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    phone = StringField("Phone Number", validators=[Optional()])
    academic_level = SelectField(
        "Academic Level",
        choices=[("", "Select level"), ("Undergrad", "Undergrad"), ("Masters", "Masters"), ("PhD", "PhD")],
        validators=[Optional()],
    )
    expertise_tags = StringField("Expertise Tags", validators=[Optional()])
    password = PasswordField("New Password", validators=[Optional()])
    confirm_password = PasswordField("Confirm Password", validators=[Optional(), EqualTo('password')])
    two_factor_enabled = BooleanField("Enable 2FA")
    profile_public = BooleanField("Show profile publicly")
    notify_email = BooleanField("Email notifications")
    notify_sms = BooleanField("SMS notifications")
    notify_in_app = BooleanField("In-app notifications")
    alert_order_updates = BooleanField("Order updates")
    alert_payment_confirmations = BooleanField("Payment confirmations")
    alert_revision_requests = BooleanField("Revision requests")
    alert_admin_announcements = BooleanField("Admin announcements")
    billing_method = SelectField(
        "Billing Method",
        choices=[("", "Not set"), ("Card", "Card"), ("PayPal", "PayPal"), ("Mobile Money", "Mobile Money"), ("Bank", "Bank Transfer")],
        validators=[Optional()],
    )
    payout_method = SelectField(
        "Payout Method",
        choices=[("", "Not set"), ("PayPal", "PayPal"), ("Bank", "Bank Transfer"), ("Mobile Money", "Mobile Money")],
        validators=[Optional()],
    )
    auto_deposit_notifications = BooleanField("Auto-deposit notifications")
    preferred_language = SelectField(
        "Language",
        choices=[("English", "English"), ("French", "French"), ("Spanish", "Spanish")],
        validators=[Optional()],
    )
    timezone = SelectField(
        "Time Zone",
        choices=[("UTC", "UTC"), ("Africa/Nairobi", "Africa/Nairobi"), ("America/New_York", "America/New_York"), ("Europe/London", "Europe/London")],
        validators=[Optional()],
    )
    preferred_channel = SelectField(
        "Preferred Communication Channel",
        choices=[("chat", "Chat"), ("email", "Email")],
        validators=[Optional()],
    )
    layout_mode = SelectField(
        "Dashboard Layout",
        choices=[("detailed", "Detailed"), ("compact", "Compact")],
        validators=[Optional()],
    )
    citation_style = SelectField(
        "Preferred Citation Style",
        choices=[("APA", "APA"), ("MLA", "MLA"), ("Chicago", "Chicago"), ("Harvard", "Harvard")],
        validators=[Optional()],
    )
    favorite_writers = StringField("Favorite Writers", validators=[Optional()])
    marketing_opt_in = BooleanField("Receive marketing/newsletter emails")
    photo = FileField('Profile Photo', validators=[FileAllowed(['jpg', 'png', 'jpeg'], 'Images only!')])
    submit = SubmitField("Save changes")

class ApplicationForm(FlaskForm):
    name = StringField("Full Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    education_level = SelectField(
        "Highest Education Level",
        choices=[("Bachelor", "Bachelors"), ("Masters", "Masters"), ("PhD", "PhD"), ("Other", "Other")],
        validators=[Optional()],
    )
    subject = StringField("Subject/Expertise", validators=[DataRequired()])
    years_experience = IntegerField("Years of Experience", validators=[Optional()])
    writing_styles = SelectMultipleField(
        "Writing Styles",
        choices=[("APA", "APA"), ("MLA", "MLA"), ("Chicago", "Chicago"), ("Harvard", "Harvard")],
        validators=[Optional()],
    )
    portfolio = FileField("Upload CV / Samples", validators=[FileAllowed(['pdf', 'doc', 'docx'], 'Documents only!')])
    bio = TextAreaField("Short Bio", validators=[DataRequired(), Length(max=500)])
    accept_terms = BooleanField("I agree to the Terms and Privacy Policy", validators=[InputRequired()])
    submit = SubmitField("Apply")
    
