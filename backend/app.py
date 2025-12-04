from flask import Flask, render_template, request, redirect, session, jsonify
from flask_mail import Mail, Message
import random
import os
import urllib.parse
from groq import Groq

app = Flask(__name__, static_folder="../frontend", template_folder="../frontend")
app.secret_key = "change-this-secret-key"

# ========= SMTP CONFIG (MAILTRAP SANDBOX) =========
app.config["MAIL_SERVER"] = "sandbox.smtp.mailtrap.io"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USE_SSL"] = False
app.config["MAIL_USERNAME"] = "937a678803ef42"
app.config["MAIL_PASSWORD"] = "52a38fe57090d2"
app.config["MAIL_DEFAULT_SENDER"] = "no-reply@brijeshpi.com"

mail = Mail(app)

# ========= Groq Client =========
groq_client = Groq(api_key=os.getenv("GROQ_API_KEY"))

# Dummy user
USER = {"email": "brijeshpinfinity@gmail.com", "password": "psycho@123"}


# ========= Chatbot Route (With Memory & WhatsApp Link) =========
@app.route("/chat", methods=["POST"])
def chat():
    user_message = request.json.get("message", "")
    if not user_message:
        return jsonify({"reply": "Please type a message."})

    # 1. Get or Initialize History
    if "chat_history" not in session:
        session["chat_history"] = []

    # 2. Append User Message
    session["chat_history"].append({"role": "user", "content": user_message})
    
    # 3. Limit History Size
    if len(session["chat_history"]) > 15:
        session["chat_history"] = session["chat_history"][-15:]

    try:
        # System Prompt - Booking Agent with WhatsApp Link Generation
        system_prompt = """
        You are the BrijeshPI Service Booking Agent.
        Your Job: Collect these 8 details from the user ONE BY ONE.
        
        Current Information Status:
        (Remember what the user has already told you in this conversation history)

        Required Details:
        1. Full Name
        2. Phone Number
        3. Service Type
        4. Issue Description
        5. Urgency (Normal/Urgent)
        6. Address & Landmark
        7. City & Pincode
        8. Preferred Time
        
        RULES:
        - Check the conversation history. If the user ALREADY gave a detail, DO NOT ask for it again.
        - Ask only ONE question at a time.
        - If the user answers multiple things, accept them and ask for what is MISSING.
        
        FINAL OUTPUT FORMAT:
        When ALL 8 details are collected and the user says YES/Confirm, output exactly this:
        
        New Service Request
        Name: [Name]
        Phone: [Phone]
        Service: [Service]
        Issue: [Issue]
        Urgency: [Urgency]
        Address: [Address]
        City: [City]
        Time: [Time]
        Booking Confirmation: YES
        
        [Click here to Send to WhatsApp](https://wa.me/919944653073?text=New%20Service%20Request%0A-------------------%0AName:%20[Name]%0APhone:%20[Phone]%0AService:%20[Service]%0AIssue:%20[Issue]%0AUrgency:%20[Urgency]%0AAddress:%20[Address]%0ACity:%20[City]%0ATime:%20[Time])
        """

        # 4. Construct Messages
        messages_to_send = [{"role": "system", "content": system_prompt}] + session["chat_history"]

        # Call Groq model
        chat_completion = groq_client.chat.completions.create(
            messages=messages_to_send,
            model="llama-3.3-70b-versatile",
            temperature=0.6
        )
        
        ai_reply = chat_completion.choices[0].message.content
        
        # 5. Append AI Reply to History & Save
        session["chat_history"].append({"role": "assistant", "content": ai_reply})
        session.modified = True

        return jsonify({"reply": ai_reply})
    except Exception as e:
        print("Groq Error:", e)
        return jsonify({"reply": "Sorry, I am having trouble connecting right now."}), 500


# ========= Existing Routes =========
@app.route("/")
def home():
    return app.send_static_file("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        if email == USER["email"] and password == USER["password"]:
            session["user"] = email
            session.pop("chat_history", None) 
            return redirect("/dashboard.html")
        return redirect("/login")
    return render_template("login.html")

@app.route("/dashboard.html")
def dashboard():
    if "user" not in session:
        return redirect("/login")
    return app.send_static_file("dashboard.html")

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
