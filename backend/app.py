from flask import Flask, render_template, request, redirect, session

app = Flask(__name__, static_folder="../frontend", template_folder="../frontend")
app.secret_key = "change-this-secret-key"

# updated user credentials
USER = {"email": "brijeshpinfinity@gmail.com", "password": "psycho@123"}


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
    return redirect("/login")


# ========= Static pages =========

@app.route("/forgot-password.html")
def forgot_password_page():
    return app.send_static_file("forgot-password.html")


@app.route("/forgotpasswordotp.html")
def otp_page():
    return app.send_static_file("forgotpasswordotp.html")


@app.route("/reset-password.html")
def reset_password_page():
    return app.send_static_file("reset-password.html")


# ========= Forgot password + OTP =========

@app.route("/send-otp", methods=["POST"])
def send_otp():
    email = request.form.get("email", "").strip()

    if email != USER["email"]:
        return redirect("/forgot-password.html")

    otp = 123456
    session["otp"] = otp
    print("DEBUG OTP (for testing):", otp)

    return redirect("/forgotpasswordotp.html")


@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    user_otp = request.form.get("otp")
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
    print("Password updated for", USER["email"], "=>", new_pass)

    session.pop("otp", None)
    return redirect("/login")


if __name__ == "__main__":
    app.run(debug=True)
