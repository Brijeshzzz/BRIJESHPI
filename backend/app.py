from flask import Flask, render_template, request, redirect, session, jsonify, Blueprint, url_for
from flask_mail import Mail, Message
import random
import os
import urllib.parse
from groq import Groq

# 1. Initialize Main App (Frontend)
app = Flask(__name__, static_folder="../frontend", template_folder="../frontend")
app.secret_key = "change-this-secret-key"

# ==========================================
# ⭐ NEW: ADMIN PANEL CONFIGURATION (Blueprint)
# ==========================================
admin_bp = Blueprint('admin', __name__, 
                     template_folder='../templates',
                     static_folder='../static',
                     url_prefix='/admin')

@admin_bp.route('/')
def admin_login():
    return render_template('admin/index.html')

@admin_bp.route('/dashboard')
def dashboard():
    return render_template('admin/dashboard.html')

@admin_bp.route('/requests')
def requests():
    return render_template('admin/requests.html')

@admin_bp.route('/orders')
def orders():
    return render_template('admin/orders.html')

@admin_bp.route('/users')
def users():
    return render_template('admin/users.html')

@admin_bp.route('/marketing')
def marketing():
    return render_template('admin/marketing.html')

@admin_bp.route('/settings')
def settings():
    return render_template('admin/settings.html')

app.register_blueprint(admin_bp)
# ==========================================


# ========= SMTP CONFIG =========
app.config["MAIL_SERVER"] = "sandbox.smtp.mailtrap.io"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USE_SSL"] = False
app.config["MAIL_USERNAME"] = "937a678803ef42"
app.config["MAIL_PASSWORD"] = "52a38fe57090d2"
app.config["MAIL_DEFAULT_SENDER"] = "no-reply@brijeshpi.com"

mail = Mail(app)
groq_client = Groq(api_key=os.getenv("GROQ_API_KEY"))

# Dummy user
USER = {"email": "brijeshpinfinity@gmail.com", "password": "psycho@123"}

# ========= Chatbot Route =========
@app.route("/chat", methods=["POST"])
def chat():
    user_message = request.json.get("message", "")
    if not user_message:
        return jsonify({"reply": "Please type a message."})

    if "chat_history" not in session:
        session["chat_history"] = []
    session["chat_history"].append({"role": "user", "content": user_message})
    if len(session["chat_history"]) > 15:
        session["chat_history"] = session["chat_history"][-15:]

    try:
        system_prompt = """
        You are the BrijeshPI Service Booking Agent.
        Your Job: Collect these 8 details from the user ONE BY ONE.
        """
        messages_to_send = [{"role": "system", "content": system_prompt}] + session["chat_history"]
        chat_completion = groq_client.chat.completions.create(
            messages=messages_to_send,
            model="llama-3.3-70b-versatile",
            temperature=0.6
        )
        ai_reply = chat_completion.choices[0].message.content
        session["chat_history"].append({"role": "assistant", "content": ai_reply})
        session.modified = True
        return jsonify({"reply": ai_reply})
    except Exception as e:
        print("Groq Error:", e)
        return jsonify({"reply": "Sorry, I am having trouble connecting right now."}), 500


# ========= Existing Frontend Routes =========
@app.route("/")
def home():
    return app.send_static_file("index.html")

# THIS IS THE USER DASHBOARD ROUTE
@app.route("/dashboard.html")
def user_dashboard():
    if "user" not in session:
        return redirect("/login")
    return app.send_static_file("dashboard.html")


# ⭐⭐⭐ FIXED LOGIN LOGIC ⭐⭐⭐
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        # 1. ADMIN CHECK
        if email == "admin@brijeshpi.com" and password == "admin123":
            session["user"] = "admin"
            return redirect("/admin/dashboard") 

        # 2. NORMAL USER CHECK
        elif email == USER["email"] and password == USER["password"]:
            session["user"] = email
            session.pop("chat_history", None) 
            return redirect("/dashboard.html") # Go to USER dashboard
            
        return redirect("/login")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("user", None)
    session.pop("chat_history", None)
    return redirect("/login")

@app.route("/forgot-password.html")
def forgot_password_page():
    return app.send_static_file("forgot-password.html")

@app.route("/forgotpasswordotp.html")
def otp_page():
    return app.send_static_file("forgotpasswordotp.html")

@app.route("/reset-password.html")
def reset_password_html():
    return app.send_static_file("reset-password.html")

@app.route("/send-otp", methods=["POST"])
def send_otp():
    email = request.form.get("email", "").strip()
    if email != USER["email"]:
        return redirect("/forgot-password.html")
    otp = random.randint(100000, 999999)
    session["otp"] = otp
    session["reset_email"] = email
    try:
        msg = Message(subject="BrijeshPI Reset OTP", recipients=[email])
        msg.body = f"Your OTP is: {otp}"
        mail.send(msg)
        return redirect("/forgotpasswordotp.html")
    except Exception as e:
        print("Mail Error:", e)
        return f"Error sending email: {e}", 500

@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    user_otp = request.form.get("otp", "").strip()
    real_otp = session.get("otp")
    if real_otp is not None and user_otp == str(real_otp):
        return redirect("/reset-password.html")
    else:
        return redirect("/forgotpasswordotp.html")

@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if request.method == "GET":
        return render_template("reset-password.html")
    new_pass = request.form.get("password")
    confirm_pass = request.form.get("confirm")
    if new_pass != confirm_pass:
        return redirect("/reset-password.html")
    USER["password"] = new_pass
    session.pop("otp", None)
    session.pop("reset_email", None)
    return redirect("/login")

if __name__ == "__main__":
    app.run(debug=True)
