from flask import Flask, render_template, request, redirect, session

app = Flask(__name__, static_folder="../frontend", template_folder="../frontend")
app.secret_key = "change-this-secret-key"  # needed for sessions

# dummy user for now
USER = {"email": "brijeshpi@gmail.com", "password": "psycho"}


@app.route("/")
def home():
    # show your main landing page
    return app.send_static_file("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # read form values
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        # check against dummy user
        if email == USER["email"] and password == USER["password"]:
            session["user"] = email
            return redirect("/dashboard.html")

        # wrong credentials → stay on login
        return redirect("/login")

    # GET request → show login page
    return render_template("login.html")


@app.route("/dashboard.html")
def dashboard():
    # protect dashboard
    if "user" not in session:
        return redirect("/login")
    return app.send_static_file("dashboard.html")


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect("/login")


if __name__ == "__main__":
    app.run(debug=True)
