import os
import random
import io
import base64
from uuid import uuid4
from datetime import datetime, timedelta

from flask import (
    Flask, render_template, redirect,
    url_for, flash, request, session
)
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email

from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import bcrypt
import qrcode
from twilio.rest import Client

# =====================================================
# APP CONFIG
# =====================================================
app = Flask(__name__)

# Secret key
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev")

# ---------------- DATABASE CONFIG ----------------
DATABASE_URL = os.environ.get("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set")

# Fix for postgres:// (Render/Railway)
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://")

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# =====================================================
# TWILIO CONFIG (FIXED & SAFE)
# =====================================================
TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN")
TWILIO_FROM_NUMBER = os.environ.get("TWILIO_FROM_NUMBER")

if not TWILIO_ACCOUNT_SID or not TWILIO_AUTH_TOKEN or not TWILIO_FROM_NUMBER:
    raise RuntimeError("Twilio environment variables are not set")

twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

# =====================================================
# DATABASE MODELS
# =====================================================
class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    parents_phone = db.Column(db.String(20))
    role = db.Column(db.String(20), default="student")

    requests = db.relationship("GatePassRequest", backref="student", lazy=True)


class GatePassRequest(db.Model):
    __tablename__ = "gate_pass_requests"

    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    student_name = db.Column(db.String(120))
    reason = db.Column(db.Text)
    out_date = db.Column(db.String(20))
    out_time = db.Column(db.String(20))
    status = db.Column(db.String(20), default="Pending")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    qr_token = db.Column(db.String(100), unique=True)
    qr_expires_at = db.Column(db.DateTime)
    qr_used = db.Column(db.Boolean, default=False)

# =====================================================
# FORMS
# =====================================================
class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    parents_phone = StringField("Parent Phone", validators=[DataRequired()])
    submit = SubmitField("Register")

# =====================================================
# HELPERS
# =====================================================
def send_sms(phone, message):
    try:
        twilio_client.messages.create(
            body=message,
            from_=TWILIO_FROM_NUMBER,
            to=phone
        )
    except Exception as e:
        print("Twilio Error:", e)


def generate_qr_code(data):
    qr = qrcode.QRCode(box_size=8, border=3)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()

# =====================================================
# ROUTES
# =====================================================
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        phone = form.parents_phone.data.strip()
        if not phone.startswith("+"):
            phone = "+91" + phone

        hashed = bcrypt.hashpw(
            form.password.data.encode(),
            bcrypt.gensalt()
        ).decode()

        user = User(
            name=form.name.data,
            email=form.email.data,
            password=hashed,
            parents_phone=phone
        )
        db.session.add(user)
        db.session.commit()

        flash("Registration successful", "success")
        return redirect(url_for("login"))

    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(email=request.form["email"]).first()
        if user and bcrypt.checkpw(
            request.form["password"].encode(),
            user.password.encode()
        ):
            session["user_id"] = user.id
            session["role"] = user.role
            session["name"] = user.name
            return redirect(url_for(
                "hod_dashboard" if user.role == "hod" else "student"
            ))

        flash("Invalid credentials", "danger")

    return render_template("login.html")


@app.route("/student", methods=["GET", "POST"])
def student():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user = User.query.get(session["user_id"])

    if request.method == "POST":
        # OTP verification phase
        if session.get("otp_phase"):
            if request.form.get("otp") != str(session.get("otp")):
                flash("Invalid OTP", "danger")
                return redirect(url_for("student"))

            req = GatePassRequest(
                student_id=user.id,
                student_name=user.name,
                **session.get("pending", {})
            )
            db.session.add(req)
            db.session.commit()

            session.pop("otp_phase", None)
            session.pop("otp", None)
            session.pop("pending", None)

            flash("Gate pass submitted successfully", "success")
            return redirect(url_for("student"))

        # First submit → generate OTP
        otp = random.randint(100000, 999999)
        session["otp"] = otp
        session["otp_phase"] = True
        session["pending"] = {
            "reason": request.form["reason"],
            "out_date": request.form["out_date"],
            "out_time": request.form["out_time"]
        }

        send_sms(user.parents_phone, f"OTP for gate pass: {otp}")
        flash("OTP sent to parent's mobile number", "info")
        return redirect(url_for("student"))

    requests = GatePassRequest.query.filter_by(student_id=user.id).all()
    now = datetime.utcnow()

    data = []
    for r in requests:
        qr = None
        if (
            r.status == "Approved"
            and r.qr_token
            and not r.qr_used
            and r.qr_expires_at
            and r.qr_expires_at > now
        ):
            url = url_for("verify_qr", token=r.qr_token, _external=True)
            qr = generate_qr_code(url)
        data.append({"r": r, "qr": qr})

    return render_template(
     "student.html",
     data=data,
     otp=session.get("otp_phase"),
     student_name=user.name   # ✅ ADD THIS
    )



@app.route("/hod")
def hod_dashboard():
    if session.get("role") != "hod":
        return redirect(url_for("login"))

    requests = GatePassRequest.query.order_by(
        GatePassRequest.created_at.desc()
    ).all()
    return render_template("hod.html", requests=requests)


@app.route("/hod/update/<int:id>", methods=["POST"])
def update_request(id):
    req = GatePassRequest.query.get_or_404(id)
    action = request.form.get("action")

    if action == "Approved":
        req.status = "Approved"
        req.qr_token = uuid4().hex
        req.qr_expires_at = datetime.utcnow() + timedelta(minutes=20)
        req.qr_used = False
    else:
        req.status = "Rejected"

    db.session.commit()
    return redirect(url_for("hod_dashboard"))


@app.route("/verify-qr/<token>")
def verify_qr(token):
    req = GatePassRequest.query.filter_by(qr_token=token).first()

    if not req:
        return render_template("qr_result.html", msg="Invalid QR Code")

    if req.qr_used:
        return render_template("qr_result.html", msg="QR already used")

    if datetime.utcnow() > req.qr_expires_at:
        return render_template("qr_result.html", msg="QR expired")

    req.qr_used = True
    db.session.commit()
    return render_template("qr_result.html", msg="Gate Pass Verified Successfully")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

with app.app_context():
    db.create_all()

# =====================================================
# MAIN
# =====================================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
