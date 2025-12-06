from flask import Flask, render_template, request, redirect, session, jsonify, Blueprint, url_for
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import random
import os
import json
import urllib.parse
from groq import Groq

# REVERTED TO ORIGINAL WORKING PATHS
app = Flask(__name__, static_folder="frontend", template_folder="frontend")
app.secret_key = "change-this-secret-key"

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///brijeshpi.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), default="user")

class ServiceRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_name = db.Column(db.String(100), nullable=False)
    service_type = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20))
    budget = db.Column(db.String(500)) 
    status = db.Column(db.String(50), default="Pending")
    date = db.Column(db.String(50))

admin_bp = Blueprint('admin', __name__, template_folder='templates', static_folder='static', url_prefix='/admin')

@admin_bp.route('/')
def admin_login(): return render_template('admin/index.html')

@admin_bp.route('/dashboard')
def dashboard(): return render_template('admin/dashboard.html')

@admin_bp.route('/requests')
def requests():
    # Show 'New Booking' requests
    requests = ServiceRequest.query.filter(ServiceRequest.status == 'New Booking').order_by(ServiceRequest.id.desc()).all()
    return render_template('admin/requests.html', requests=requests)

@admin_bp.route('/accept/<int:request_id>')
def accept_request(request_id):
    req = ServiceRequest.query.get(request_id)
    if req:
        req.status = 'Accepted'
        db.session.commit()
    return redirect(url_for('admin.requests'))

@admin_bp.route('/reject/<int:request_id>')
def reject_request(request_id):
    req = ServiceRequest.query.get(request_id)
    if req:
        req.status = 'Rejected'
        db.session.commit()
    return redirect(url_for('admin.requests'))

@admin_bp.route('/orders')
def orders():
    # Show 'Accepted' or 'Completed' orders
    orders = ServiceRequest.query.filter(ServiceRequest.status.in_(['Accepted', 'Completed'])).order_by(ServiceRequest.id.desc()).all()
    return render_template('admin/orders.html', orders=orders)

@admin_bp.route('/complete/<int:request_id>')
def complete_order(request_id):
    req = ServiceRequest.query.get(request_id)
    if req:
        req.status = 'Completed'
        db.session.commit()
    return redirect(url_for('admin.orders'))

@admin_bp.route('/users')
def users(): return render_template('admin/users.html')
@admin_bp.route('/marketing')
def marketing(): return render_template('admin/marketing.html')
@admin_bp.route('/settings')
def settings(): return render_template('admin/settings.html')

app.register_blueprint(admin_bp)

app.config["MAIL_SERVER"] = "sandbox.smtp.mailtrap.io"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USE_SSL"] = False
app.config["MAIL_USERNAME"] = "937a678803ef42"
app.config["MAIL_PASSWORD"] = "52a38fe57090d2"
app.config["MAIL_DEFAULT_SENDER"] = "no-reply@brijeshpi.com"
mail = Mail(app)
groq_client = Groq(api_key=os.getenv("GROQ_API_KEY"))

@app.route("/chat", methods=["POST"])
def chat():
    user_message = request.json.get("message", "")
    if not user_message: return jsonify({"reply": "Please type a message."})
    
    if "chat_history" not in session: session["chat_history"] = []
    
    history = session["chat_history"]
    history.append({"role": "user", "content": user_message})
    if len(history) > 20: history = history[-20:]
    session["chat_history"] = history

    system_prompt = """
    You are Sarah, the Booking Agent.
    GOAL: Collect 8 details. Check history first.
    REQUIRED: 1.Name 2.Phone 3.Service 4.Issue 5.Urgency 6.Address 7.City 8.Time
    RULES:
    - If detail exists, MARK DONE.
    - Ask for NEXT missing detail.
    - IF ALL 8 ARE DONE, OUTPUT ONLY THIS JSON:
    {
      "SAVE_DB": true,
      "name": "...",
      "phone": "...",
      "service": "...",
      "issue": "...",
      "urgency": "...",
      "address": "...",
      "city": "...",
      "time": "..."
    }
    """

    try:
        messages = [{"role": "system", "content": system_prompt}] + history
        completion = groq_client.chat.completions.create(messages=messages, model="llama-3.3-70b-versatile", temperature=0.5)
        ai_reply = completion.choices[0].message.content
        
        if "SAVE_DB" in ai_reply:
            try:
                start = ai_reply.find("{")
                end = ai_reply.rfind("}") + 1
                if start != -1 and end != -1:
                    json_str = ai_reply[start:end]
                    json_data = json.loads(json_str)
                    
                    details_text = f"Issue: {json_data.get('issue')} | City: {json_data.get('city')} | Time: {json_data.get('time')}"
                    new_req = ServiceRequest(
                        client_name=json_data.get("name", "Unknown"),
                        service_type=json_data.get("service", "General"),
                        phone=json_data.get("phone", "N/A"),
                        budget=details_text[:499], 
                        status="New Booking",
                        date=datetime.now().strftime("%Y-%m-%d")
                    )
                    db.session.add(new_req)
                    db.session.commit()
                    
                    ADMIN_PHONE = "919944653073" 
                    wa_text = f"""*New Service Request*
-------------------
*Name:* {json_data.get('name')}
*Phone:* {json_data.get('phone')}
*Service:* {json_data.get('service')}
*Issue:* {json_data.get('issue')}
*Urgency:* {json_data.get('urgency')}
*Address:* {json_data.get('address')}, {json_data.get('city')}
*Time:* {json_data.get('time')}"""
                    
                    wa_url = f"https://wa.me/{ADMIN_PHONE}?text={urllib.parse.quote(wa_text)}"
                    
                    final_reply = f"""
                    ✅ <b>Booking Saved!</b><br>
                    I have sent your request to the admin panel.<br><br>
                    👇 <b>Click below to confirm on WhatsApp:</b><br>
                    <a href='{wa_url}' target='_blank' style='display:inline-block; padding:10px 20px; background-color:#25D366; color:white; text-decoration:none; border-radius:5px; margin-top:10px;'>Open WhatsApp</a>
                    """
                    session.pop("chat_history", None)
                else:
                    final_reply = "Error: AI format incorrect. Please type 'CONFIRM' to try again."
            except Exception as e:
                print("Save Error:", e)
                final_reply = f"System Error saving booking: {str(e)}"
        else:
            final_reply = ai_reply

        if "chat_history" in session:
            history = session["chat_history"]
            history.append({"role": "assistant", "content": final_reply})
            session["chat_history"] = history
            
        session.modified = True 
        return jsonify({"reply": final_reply})

    except Exception as e:
        print("Groq Error:", e)
        return jsonify({"reply": f"System Error: {str(e)}"}), 500

@app.route("/")
def home(): return app.send_static_file("index.html")
@app.route("/dashboard.html")
def user_dashboard():
    if "user" not in session: return redirect("/login")
    return app.send_static_file("dashboard.html")
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        if email == "admin@brijeshpi.com" and password == "admin123":
            session["user"] = "admin"
            return redirect("/admin/dashboard")
        user = User.query.filter_by(email=email).first()
        if user and user.password == password:
            session["user"] = user.email
            return redirect("/dashboard.html")
        return redirect("/login")
    return render_template("login.html")
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        username = request.form.get("full_name")
        if User.query.filter_by(email=email).first(): return "Email exists!"
        new_user = User(username=username, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect("/login")
    return app.send_static_file("signup.html")
@app.route("/logout")
def logout():
    session.pop("user", None); session.pop("chat_history", None)
    return redirect("/login")
@app.route("/forgot-password.html")
def forgot_password_page(): return app.send_static_file("forgot-password.html")
@app.route("/forgotpasswordotp.html")
def otp_page(): return app.send_static_file("forgotpasswordotp.html")
@app.route("/reset-password.html")
def reset_password_html(): return app.send_static_file("reset-password.html")
@app.route("/send-otp", methods=["POST"])
def send_otp():
    email = request.form.get("email", "").strip()
    otp = random.randint(100000, 999999)
    session["otp"] = otp; session["reset_email"] = email
    try:
        msg = Message(subject="BrijeshPI OTP", recipients=[email]); msg.body = f"OTP: {otp}"; mail.send(msg)
        return redirect("/forgotpasswordotp.html")
    except Exception as e: return f"Error: {e}", 500
@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    if request.form.get("otp", "").strip() == str(session.get("otp")): return redirect("/reset-password.html")
    return redirect("/forgotpasswordotp.html")
@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if request.method == "GET": return render_template("reset-password.html")
    session.pop("otp", None)
    return redirect("/login")

if __name__ == "__main__":
    with app.app_context(): db.create_all()
    app.run(debug=True)
