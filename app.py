from flask import (
    Flask,
    render_template,
    redirect,
    url_for,
    flash,
    request,
    session
)
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email
import bcrypt
from flask_mysqldb import MySQL
import random

# === NEW IMPORTS FOR QR ===
import qrcode
import io
import base64
from uuid import uuid4
from datetime import datetime, timedelta
import os
# Twilio import
from twilio.rest import Client

app = Flask(__name__)

# ================== MYSQL CONFIG ==================
app.config['MYSQL_HOST'] = os.environ.get('localhost')
app.config['MYSQL_USER'] = os.environ.get('root')
app.config['MYSQL_PASSWORD'] = os.environ.get('root')
app.config['MYSQL_DB'] = os.environ.get('minor')

# Flask-WTF / Session secret key
app.secret_key = 'sk'

mysql = MySQL(app)

# ================== TWILIO CONFIG ==================
import os

TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN")
TWILIO_FROM_NUMBER = os.environ.get("TWILIO_FROM_NUMBER")
app.secret_key = os.environ.get("SECRET_KEY", "dev")


twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)


def send_sms(phone, message):
    """
    Send SMS using Twilio.
    `phone` must be in E.164 format: e.g. +91XXXXXXXXXX
    """
    try:
        twilio_client.messages.create(
            body=message,
            from_=TWILIO_FROM_NUMBER,
            to=phone
        )
        print(f"SMS sent to {phone}: {message}")
    except Exception as e:
        # App crash na ho, bas log print ho jaye
        print("Twilio SMS error:", e)


# ============== QR HELPER ==============
def generate_qr_code(data: str) -> str:
    """
    Given a string (usually a URL), returns base64-encoded PNG of QR code.
    """
    qr = qrcode.QRCode(box_size=10, border=4)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_bytes = buf.getvalue()
    qr_b64 = base64.b64encode(qr_bytes).decode("utf-8")
    return qr_b64


# ================== FORMS ==================
class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    parents_phone = StringField("Parent's Phone", validators=[DataRequired()])
    submit = SubmitField("Register")


# ================== ROUTES ==================

@app.route('/')
def index():
    return render_template('index.html')


# ---------- REGISTER ----------
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data
        parents_phone = form.parents_phone.data.strip()

        # Ensure +91 format
        if parents_phone.startswith("0"):
            parents_phone = parents_phone[1:]
        if not parents_phone.startswith("+"):
            parents_phone = "+91" + parents_phone  # India assume kar raha hu

        hashed_password = bcrypt.hashpw(
            password.encode('utf-8'),
            bcrypt.gensalt()
        ).decode('utf-8')

        cur = mysql.connection.cursor()
        cur.execute(
            """
            INSERT INTO users (name, email, password, parents_phone)
            VALUES (%s, %s, %s, %s)
            """,
            (name, email, hashed_password, parents_phone)
        )
        mysql.connection.commit()
        cur.close()

        flash("Registration successful. Please login.", "success")
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


# ---------- LOGIN ----------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        cur = mysql.connection.cursor()
        cur.execute(
            "SELECT id, name, password, role FROM users WHERE email = %s",
            (email,)
        )
        user = cur.fetchone()
        cur.close()

        if user:
            user_id = user[0]
            user_name = user[1]
            stored_hash = user[2]
            role = user[3] if len(user) > 3 and user[3] else 'student'

            if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
                session['email'] = email
                session['student_id'] = user_id
                session['student_name'] = user_name
                session['role'] = role

                flash("Login successful!", "success")

                if role == 'hod':
                    return redirect(url_for('hod_dashboard'))
                else:
                    return redirect(url_for('student'))
            else:
                flash("Incorrect password!", "danger")
        else:
            flash("Email not found!", "danger")

    return render_template('login.html')


# ---------- STUDENT DASHBOARD (OTP + QR VIEW) ----------
@app.route('/student', methods=['GET', 'POST'])
def student():
    if 'email' not in session:
        flash("Please login first.", "warning")
        return redirect(url_for('login'))

    email = session['email']

    # user se id, name, parents_phone lo
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, name, parents_phone FROM users WHERE email = %s", (email,))
    user = cur.fetchone()
    cur.close()

    if not user:
        session.clear()
        flash("User not found. Please login again.", "danger")
        return redirect(url_for('login'))

    student_id = user[0]
    student_name = user[1]
    parents_phone = user[2]

    otp_phase = session.get('otp_phase', False)

    if request.method == 'POST':
        # Agar already OTP phase me hain -> ab OTP verify hoga
        if otp_phase:
            entered_otp = request.form.get('otp')
            real_otp = session.get('otp')
            pending = session.get('pending_request')

            if not real_otp or not pending:
                flash("Session expired. Please fill the form again.", "warning")
                session.pop('otp_phase', None)
                session.pop('otp', None)
                session.pop('pending_request', None)
                return redirect(url_for('student'))

            if entered_otp != str(real_otp):
                flash("Invalid OTP, please try again.", "danger")
                return redirect(url_for('student'))

            # OTP correct – insert request
            reason = pending['reason']
            out_date = pending['out_date']
            out_time = pending['out_time']

            cur = mysql.connection.cursor()
            cur.execute(
                """
                INSERT INTO gate_pass_requests
                    (student_id, student_name, reason, out_date, out_time)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (student_id, student_name, reason, out_date, out_time)
            )
            mysql.connection.commit()
            cur.close()

            # Clean up OTP state
            session.pop('otp_phase', None)
            session.pop('otp', None)
            session.pop('pending_request', None)

            flash("Gate pass request submitted after OTP verification!", "success")
            return redirect(url_for('student'))

        # ---------- First submit: generate & send OTP ----------
        reason = request.form.get('reason')
        out_date = request.form.get('out_date')
        out_time = request.form.get('out_time')

        if not reason or not out_date or not out_time:
            flash("Please fill all fields", "danger")
            return redirect(url_for('student'))

        otp = random.randint(100000, 999999)

        session['otp_phase'] = True
        session['otp'] = otp
        session['pending_request'] = {
            'reason': reason,
            'out_date': out_date,
            'out_time': out_time
        }

        # Twilio se parent ko OTP bhejna
        message = f"OTP for gate pass request of {student_name} is {otp}."
        send_sms(parents_phone, message)
        flash("OTP sent to your parent's registered mobile number. Please enter OTP to confirm.", "info")
        return redirect(url_for('student'))

    # ========== GET: display student's requests + QR if Approved ==========
    cur = mysql.connection.cursor()
    cur.execute(
        """
        SELECT id,
               reason,
               out_date,
               out_time,
               status,
               created_at,
               qr_token,
               qr_expires_at,
               qr_used
        FROM gate_pass_requests
        WHERE student_id = %s
        ORDER BY created_at DESC
        """,
        (student_id,)
    )
    rows = cur.fetchall()
    cur.close()

    # Convert rows -> list of dicts + generate QR for valid approved requests
    requests_list = []
    now = datetime.now()

    for row in rows:
        (req_id,
         reason,
         out_date,
         out_time,
         status,
         created_at,
         qr_token,
         qr_expires_at,
         qr_used) = row

        qr_code_data = None

        # QR tab hi dikhao jab:
        # - status Approved ho
        # - token ho
        # - QR expire na hua ho
        # - abhi tak use na hua ho
        if (
            status == 'Approved' and
            qr_token and
            qr_expires_at and
            not qr_used and
            now <= qr_expires_at
        ):
            verify_url = url_for("verify_qr", token=qr_token, _external=True)
            qr_code_data = generate_qr_code(verify_url)

        requests_list.append({
            "id": req_id,
            "reason": reason,
            "out_date": out_date,
            "out_time": out_time,
            "status": status,
            "created_at": created_at,
            "qr_code_data": qr_code_data,
            "qr_expires_at": qr_expires_at,
            "qr_used": qr_used
        })

    otp_required = session.get('otp_phase', False)

    return render_template(
        'student.html',
        student_name=student_name,
        requests_list=requests_list,
        otp_required=otp_required
    )


# ---------- HOD DASHBOARD ----------
@app.route('/hod', methods=['GET', 'POST'])
def hod_dashboard():
    if 'role' not in session or session['role'] != 'hod':
        flash("Access denied. HOD only.", "danger")
        return redirect(url_for('login'))

    cur = mysql.connection.cursor()
    cur.execute(
        """
        SELECT g.id,
               g.student_id,
               g.student_name,
               g.reason,
               g.out_date,
               g.out_time,
               g.status,
               g.created_at
        FROM gate_pass_requests AS g
        ORDER BY g.created_at DESC
        """
    )
    all_requests = cur.fetchall()
    cur.close()

    return render_template('hod.html', all_requests=all_requests)


# ---------- HOD: UPDATE STATUS + SMS + QR ON APPROVED ----------
@app.route('/hod/update/<int:request_id>', methods=['POST'])
def update_request_status(request_id):
    if 'role' not in session or session['role'] != 'hod':
        flash("Access denied. HOD only.", "danger")
        return redirect(url_for('login'))

    action = request.form.get('action')  # "Approved" ya "Rejected"

    if action not in ['Approved', 'Rejected']:
        flash("Invalid action.", "danger")
        return redirect(url_for('hod_dashboard'))

    cur = mysql.connection.cursor()

    # ---------- If Rejected: sirf status update ----------
    if action == 'Rejected':
        cur.execute(
            "UPDATE gate_pass_requests SET status = %s WHERE id = %s",
            (action, request_id)
        )
        mysql.connection.commit()
        cur.close()

        flash(f"Request #{request_id} marked as {action}.", "success")
        return redirect(url_for('hod_dashboard'))

    # ---------- If Approved: status + QR token + expiry ----------
    # Unique token & expiry 20 minutes later
    token = uuid4().hex
    expires_at = datetime.now() + timedelta(minutes=20)

    cur.execute(
        """
        UPDATE gate_pass_requests
        SET status = %s,
            qr_token = %s,
            qr_expires_at = %s,
            qr_used = 0
        WHERE id = %s
        """,
        (action, token, expires_at, request_id)
    )
    mysql.connection.commit()

    # Fetch request details (student, date, time, etc.)
    cur.execute(
        """
        SELECT student_id, student_name, reason, out_date, out_time
        FROM gate_pass_requests
        WHERE id = %s
        """,
        (request_id,)
    )
    req_row = cur.fetchone()

    if not req_row:
        cur.close()
        flash("Request not found after update.", "danger")
        return redirect(url_for('hod_dashboard'))

    student_id = req_row[0]
    student_name = req_row[1]
    reason = req_row[2]
    out_date = req_row[3]
    out_time = req_row[4]

    # Parent ka phone nikaalo
    cur.execute(
        "SELECT parents_phone FROM users WHERE id = %s",
        (student_id,)
    )
    user_row = cur.fetchone()
    cur.close()

    parents_phone = None
    if user_row:
        parents_phone = user_row[0]

    # SMS to parent that request is Approved (optional)
    if parents_phone:
        msg = (
            f"Gate pass request (ID: {request_id}) of {student_name} "
            f"for {out_date} {out_time} has been APPROVED by HOD."
        )
        send_sms(parents_phone, msg)

    # (Optional) HOD ke liye QR page same rahe
    verify_url = url_for("verify_qr", token=token, _external=True)
    qr_code_data = generate_qr_code(verify_url)

    return render_template(
        "qr_page.html",
        request_id=request_id,
        student_name=student_name,
        reason=reason,
        out_date=out_date,
        out_time=out_time,
        qr_code_data=qr_code_data,
        verify_url=verify_url,
        qr_expires_at=expires_at
    )


# ---------- QR VERIFY ROUTE ----------
@app.route('/verify-qr/<string:token>')
def verify_qr(token):
    """
    Guard QR scan karega -> is URL pe aayega.
    Token se request find karo, expiry & used check karo.
    """
    cur = mysql.connection.cursor()
    cur.execute(
        """
        SELECT id, student_name, reason, out_date, out_time, qr_expires_at, qr_used
        FROM gate_pass_requests
        WHERE qr_token = %s
        """,
        (token,)
    )
    row = cur.fetchone()

    if not row:
        cur.close()
        status = "invalid"
        msg = "❌ Invalid QR Code. Gate pass not found."
        return render_template("qr_result.html", status=status, msg=msg, gate_req=None)

    req_id = row[0]
    student_name = row[1]
    reason = row[2]
    out_date = row[3]
    out_time = row[4]
    qr_expires_at = row[5]
    qr_used = row[6]

    # Already used?
    if qr_used:
        cur.close()
        status = "used"
        msg = "⚠️ This QR code has already been used."
        gate_req = {
            "id": req_id,
            "student_name": student_name,
            "reason": reason,
            "out_date": out_date,
            "out_time": out_time,
            "qr_expires_at": qr_expires_at
        }
        return render_template("qr_result.html", status=status, msg=msg, gate_req=gate_req)

    now = datetime.now()
    if not qr_expires_at or now > qr_expires_at:
        cur.close()
        status = "expired"
        msg = "⛔ This QR code has expired. Please contact the HOD."
        gate_req = {
            "id": req_id,
            "student_name": student_name,
            "reason": reason,
            "out_date": out_date,
            "out_time": out_time,
            "qr_expires_at": qr_expires_at
        }
        return render_template("qr_result.html", status=status, msg=msg, gate_req=gate_req)

    # Yaha tak aaya => QR valid hai, ab ek hi baar use hona chahiye
    cur.execute(
        "UPDATE gate_pass_requests SET qr_used = 1 WHERE id = %s",
        (req_id,)
    )
    mysql.connection.commit()
    cur.close()

    status = "valid"
    msg = "✅ Gate Pass Verified Successfully. Entry Allowed."
    gate_req = {
        "id": req_id,
        "student_name": student_name,
        "reason": reason,
        "out_date": out_date,
        "out_time": out_time,
        "qr_expires_at": qr_expires_at
    }
    return render_template("qr_result.html", status=status, msg=msg, gate_req=gate_req)


# ---------- LOGOUT ----------
@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for('login'))


# ================== MAIN ==================
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

