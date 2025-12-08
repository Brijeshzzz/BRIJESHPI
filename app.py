import feedparser
from flask import Flask, render_template, request, redirect, session, jsonify, Blueprint, url_for, flash
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
import random
import os
import json
import urllib.parse
from groq import Groq


# ---------------- CONFIGURATION ----------------
app = Flask(__name__, static_folder="frontend", template_folder="frontend")
app.secret_key = "change-this-secret-key"


# Prevent Caching
@app.after_request
def add_header(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "-1"
    return response


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///brijeshpi.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# Flask-Login Setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# ---------------- MODELS ----------------


class Follow(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    follower_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    followed_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default="user") 
    
    # Provider Logic
    is_provider = db.Column(db.Boolean, default=False) 
    provider_profile = db.relationship('ProviderProfile', backref='user', uselist=False)


    # Follow Helpers
    def is_following(self, user):
        return Follow.query.filter_by(follower_id=self.id, followed_id=user.id).first() is not None


    def follow(self, user):
        if not self.is_following(user):
            f = Follow(follower_id=self.id, followed_id=user.id)
            db.session.add(f)


    def unfollow(self, user):
        f = Follow.query.filter_by(follower_id=self.id, followed_id=user.id).first()
        if f: db.session.delete(f)
            
    def get_followers_count(self):
        return Follow.query.filter_by(followed_id=self.id).count()


    def get_following_count(self):
        return Follow.query.filter_by(follower_id=self.id).count()


    # â­ NEW: Get List of Followers â­
    def get_followers(self):
        follows = Follow.query.filter_by(followed_id=self.id).all()
        return [User.query.get(f.follower_id) for f in follows]


class ProviderProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True)
    service_category = db.Column(db.String(100))
    experience_years = db.Column(db.Integer)
    hourly_rate = db.Column(db.String(50))
    bio = db.Column(db.Text)


class ServiceRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_name = db.Column(db.String(100), nullable=False)
    service_type = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20))
    budget = db.Column(db.String(500)) 
    status = db.Column(db.String(50), default="Pending")
    date = db.Column(db.String(50))


class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price_range = db.Column(db.String(100))
    description = db.Column(db.String(500))
    icon = db.Column(db.String(50), default="fas fa-tools")


class Campaign(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    platform = db.Column(db.String(50)) 
    status = db.Column(db.String(20)) 
    reach = db.Column(db.Integer, default=0)
    conversions = db.Column(db.Integer, default=0)
    budget_spent = db.Column(db.Float, default=0.0)
    roi = db.Column(db.Float, default=0.0)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ---------------- ADMIN DECORATOR ----------------
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash("You do not have permission to access this page.", "danger")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# ---------------- ADMIN BLUEPRINT ----------------
admin_bp = Blueprint('admin', __name__, template_folder='templates', static_folder='static', url_prefix='/admin')


@admin_bp.route('/')
def admin_redirect(): return redirect(url_for('admin.dashboard'))


@admin_bp.route('/dashboard')
@login_required
@admin_required
def dashboard(): 
    total_requests = ServiceRequest.query.count()
    new_bookings = ServiceRequest.query.filter_by(status='New Booking').count()
    completed = ServiceRequest.query.filter_by(status='Completed').count()
    rejected = ServiceRequest.query.filter_by(status='Rejected').count()
    rate = round((completed / total_requests) * 100, 1) if total_requests > 0 else 0
    return render_template('admin/dashboard.html', total=total_requests, new=new_bookings, completed=completed, rejected=rejected, rate=rate)


@admin_bp.route('/requests')
@login_required
@admin_required
def requests():
    search_query = request.args.get('search', '').strip()
    service_filter = request.args.get('service', '').strip()
    date_filter = request.args.get('date', '').strip()
    query = ServiceRequest.query.filter(ServiceRequest.status == 'New Booking')
    if search_query: query = query.filter((ServiceRequest.client_name.ilike(f"%{search_query}%")) | (ServiceRequest.phone.ilike(f"%{search_query}%")))
    if service_filter: query = query.filter(ServiceRequest.service_type == service_filter)
    if date_filter: query = query.filter(ServiceRequest.date == date_filter)
    requests = query.order_by(ServiceRequest.id.desc()).all()
    all_services = Service.query.all()
    return render_template('admin/requests.html', requests=requests, services=all_services)


@admin_bp.route('/accept/<int:request_id>')
@login_required
@admin_required
def accept_request(request_id):
    req = ServiceRequest.query.get(request_id)
    if req: req.status = 'Accepted'; db.session.commit()
    return redirect(url_for('admin.requests'))


@admin_bp.route('/reject/<int:request_id>')
@login_required
@admin_required
def reject_request(request_id):
    req = ServiceRequest.query.get(request_id)
    if req: req.status = 'Rejected'; db.session.commit()
    return redirect(url_for('admin.requests'))


@admin_bp.route('/orders')
@login_required
@admin_required
def orders():
    orders = ServiceRequest.query.filter(ServiceRequest.status.in_(['Accepted', 'Completed'])).order_by(ServiceRequest.id.desc()).all()
    return render_template('admin/orders.html', orders=orders)


@admin_bp.route('/complete/<int:request_id>')
@login_required
@admin_required
def complete_order(request_id):
    req = ServiceRequest.query.get(request_id)
    if req: req.status = 'Completed'; db.session.commit()
    return redirect(url_for('admin.orders'))


@admin_bp.route('/users')
@login_required
@admin_required
def users(): 
    all_users = User.query.order_by(User.id.desc()).all()
    return render_template('admin/users.html', users=all_users)


@admin_bp.route('/services')
@login_required
@admin_required
def services():
    all_services = Service.query.all()
    return render_template('admin/services.html', services=all_services)


@admin_bp.route('/services/add', methods=['POST'])
@login_required
@admin_required
def add_service():
    name = request.form.get('name')
    price = request.form.get('price')
    icon = request.form.get('icon')
    if name:
        new_service = Service(name=name, price_range=price, icon=icon)
        db.session.add(new_service); db.session.commit()
        flash('Service Added!', 'success')
    return redirect(url_for('admin.services'))


@admin_bp.route('/services/delete/<int:service_id>')
@login_required
@admin_required
def delete_service(service_id):
    service = Service.query.get(service_id)
    if service: db.session.delete(service); db.session.commit()
    return redirect(url_for('admin.services'))


@admin_bp.route('/marketing')
@login_required
@admin_required
def marketing(): 
    total_users = User.query.count()
    total_orders = ServiceRequest.query.count()
    growth_percent = 12.5 
    revenue_estimate = total_orders * 150 
    campaigns = Campaign.query.all()
    return render_template('admin/marketing.html', users=total_users, orders=total_orders, growth=growth_percent, revenue=revenue_estimate, campaigns=campaigns)


@admin_bp.route('/marketing/campaign/add', methods=['POST'])
@login_required
@admin_required
def add_campaign():
    name = request.form.get('name')
    platform = request.form.get('platform')
    if name:
        new_camp = Campaign(name=name, platform=platform, status="Active", reach=0, conversions=0)
        db.session.add(new_camp); db.session.commit()
    return redirect(url_for('admin.marketing'))


@admin_bp.route('/settings')
@login_required
@admin_required
def settings(): return render_template('admin/settings.html')


app.register_blueprint(admin_bp)


# ---------------- EXTERNAL SERVICES ----------------
app.config["MAIL_SERVER"] = "sandbox.smtp.mailtrap.io"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USE_SSL"] = False
app.config["MAIL_USERNAME"] = "937a678803ef42"
app.config["MAIL_PASSWORD"] = "52a38fe57090d2"
app.config["MAIL_DEFAULT_SENDER"] = "no-reply@brijeshpi.com"
mail = Mail(app)
groq_client = Groq(api_key=os.getenv("GROQ_API_KEY"))


# ---------------- CHATBOT ----------------
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
    You are the BrijeshPI AI Assistant. 
    Your goal is to collect 8 details from the user to book a service.
    
    THE 8 REQUIRED DETAILS:
    1. Name | 2. Phone | 3. Service Type | 4. Specific Issue | 5. Urgency | 6. Address | 7. City | 8. Time


    STRICT CONVERSATION RULES:
    1. DO NOT use the name "Sarah". Refer to yourself as "BrijeshPI AI".
    2. DO NOT output a list of "DONE" items. Keep the checklist hidden.
    3. Speak naturally like a human.
    4. Ask for ONLY ONE missing detail at a time.


    ENDING THE CHAT:
    When (and ONLY when) you have ALL 8 details, output EXACTLY this JSON format:
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
        completion = groq_client.chat.completions.create(messages=messages, model="llama-3.3-70b-versatile", temperature=0.6)
        ai_reply = completion.choices[0].message.content
        
        # --- JSON HANDLING (Hidden from User) ---
        if "SAVE_DB" in ai_reply:
            try:
                start = ai_reply.find("{")
                end = ai_reply.rfind("}") + 1
                if start != -1 and end != -1:
                    json_str = ai_reply[start:end]
                    json_data = json.loads(json_str)
                    
                    details_text = f"Issue: {json_data.get('issue')} | Urgency: {json_data.get('urgency')} | Address: {json_data.get('address')} | City: {json_data.get('city')} | Time: {json_data.get('time')}"
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
-------------------------
*Name:* {json_data.get('name')}
*Phone:* {json_data.get('phone')}
*Service:* {json_data.get('service')}
*Issue:* {json_data.get('issue')}
*Urgency:* {json_data.get('urgency')}
*Address:* {json_data.get('address')}, {json_data.get('city')}
*Time:* {json_data.get('time')}"""
                    
                    wa_url = f"https://wa.me/{ADMIN_PHONE}?text={urllib.parse.quote(wa_text)}"
                    
                    final_reply = f"""
                    <div class="bg-green-50 p-4 rounded-lg border border-green-200">
                        <h3 class="font-bold text-green-800 mb-2">Booking Confirmed! âœ…</h3>
                        <p class="text-sm text-green-700 mb-4">I've sent your request to the team.</p>
                        <a href='{wa_url}' target='_blank' class="inline-block px-4 py-2 bg-green-500 text-white text-xs font-bold rounded hover:bg-green-600 transition">
                            Track on WhatsApp
                        </a>
                    </div>
                    """
                    session.pop("chat_history", None)
                else:
                    final_reply = "I have your details, but a system error occurred. Type 'CONFIRM' to retry."
            except Exception as e:
                print("Save Error:", e)
                final_reply = f"System Error: {str(e)}"
        else:
            final_reply = ai_reply


        # Only append non-booking messages to history
        if "chat_history" in session and "SAVE_DB" not in ai_reply:
            history = session["chat_history"]
            history.append({"role": "assistant", "content": final_reply})
            session["chat_history"] = history
            
        session.modified = True 
        return jsonify({"reply": final_reply})


    except Exception as e:
        print("Groq Error:", e)
        return jsonify({"reply": f"System Error: {str(e)}"}), 500


# ---------------- PUBLIC ROUTES ----------------
@app.route("/")
def home(): return app.send_static_file("index.html")


def get_real_feed():
    feed_data = []
    # Extended Image List to prevent duplicates
    images = [
        "https://images.unsplash.com/photo-1498050108023-c5249f4df085?w=800&auto=format&fit=crop",
        "https://images.unsplash.com/photo-1504639725590-34d0984388bd?w=800&auto=format&fit=crop",
        "https://images.unsplash.com/photo-1550751827-4bd374c3f58b?w=800&auto=format&fit=crop",
        "https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?w=800&auto=format&fit=crop",
        "https://images.unsplash.com/photo-1551288049-bebda4e38f71?w=800&auto=format&fit=crop",
        "https://images.unsplash.com/photo-1461749280684-dccba630e2f6?w=800&auto=format&fit=crop",
        "https://images.unsplash.com/photo-1486312338219-ce68d2c6f44d?w=800&auto=format&fit=crop",
        "https://images.unsplash.com/photo-1581091226825-a6a2a5aee158?w=800&auto=format&fit=crop",
        "https://images.unsplash.com/photo-1485827404703-89b55fcc595e?w=800&auto=format&fit=crop",
        "https://images.unsplash.com/photo-1526628953301-3e589a6a8b74?w=800&auto=format&fit=crop"
    ]
    random.shuffle(images) # Shuffle images first
    
    try:
        tc = feedparser.parse("https://techcrunch.com/feed/")
        for i, e in enumerate(tc.entries[:3]):
            feed_data.append({"source": "TechCrunch", "title": e.title, "link": e.link, "avatar": "https://upload.wikimedia.org/wikipedia/commons/b/b9/TechCrunch_logo.svg", "image": images[i % len(images)]})
    except: pass

    try:
        tv = feedparser.parse("https://www.theverge.com/rss/index.xml")
        for i, e in enumerate(tv.entries[:3]):
            feed_data.append({"source": "The Verge", "title": e.title, "link": e.link, "avatar": "https://upload.wikimedia.org/wikipedia/commons/a/af/The_Verge_logo.svg", "image": images[(i+3) % len(images)]})
    except: pass

    try:
        hn = feedparser.parse("https://news.ycombinator.com/rss")
        for i, e in enumerate(hn.entries[:3]):
            feed_data.append({"source": "Hacker News", "title": e.title, "link": e.link, "avatar": "https://upload.wikimedia.org/wikipedia/commons/b/b2/Y_Combinator_logo.svg", "image": images[(i+6) % len(images)]})
    except: pass
    
    random.shuffle(feed_data)
    return feed_data

@app.route("/api/feed")
@login_required
def api_feed():
    return jsonify(get_real_feed())



@app.route("/dashboard")
@login_required
def user_dashboard():
    if current_user.role == "admin": return redirect(url_for("admin.dashboard"))
    view_mode = session.get("view_mode", "client")
    if not current_user.is_provider: view_mode = "client"
    search_query = request.args.get("q", "").strip()
    search_results = []
    if search_query:
        search_results = User.query.filter(User.username.ilike(f"%{search_query}%"), User.id != current_user.id).all()
    feed_items = get_real_feed()
    return render_template("dashboard.html", user=current_user, view_mode=view_mode, search_results=search_results, search_query=search_query, feed_items=feed_items)


# â­ NEW: PUBLIC PROFILE ROUTE (Case-Insensitive Fix Applied) â­
@app.route("/profile/<username>")
@login_required
def public_profile(username):
    target_user = User.query.filter_by(username=username).first()
    if not target_user: target_user = User.query.filter(User.username.ilike(username)).first()
    if not target_user:
        for u in User.query.all():
            if u.username and u.username.strip().lower() == username.strip().lower():
                target_user = u; break
    if not target_user: return redirect(url_for("user_dashboard"))
    followers = target_user.get_followers()
    return render_template("public_profile.html", user=current_user, target_user=target_user, followers=followers)


# --- FOLLOW ROUTES ---
@app.route("/follow/<int:user_id>", methods=['POST'])
@login_required
def follow_user(user_id):
    user_to_follow = User.query.get(user_id)
    if user_to_follow:
        current_user.follow(user_to_follow)
        db.session.commit()
    return redirect(request.referrer or url_for('user_dashboard'))


@app.route("/unfollow/<int:user_id>", methods=['POST'])
@login_required
def unfollow_user(user_id):
    user_to_unfollow = User.query.get(user_id)
    if user_to_unfollow:
        current_user.unfollow(user_to_unfollow)
        db.session.commit()
    return redirect(request.referrer or url_for('user_dashboard'))


# --- ACCOUNT SWITCHING ROUTES ---
@app.route("/upgrade-to-provider", methods=["POST"])
@login_required
def upgrade_to_provider():
    if not current_user.is_provider:
        new_profile = ProviderProfile(user_id=current_user.id)
        current_user.is_provider = True
        db.session.add(new_profile); db.session.commit()
        session['view_mode'] = 'provider'
        flash("You are now a Service Partner!", "success")
    return redirect(url_for('user_dashboard'))


@app.route("/switch-view/<mode>")
@login_required
def switch_view(mode):
    if current_user.is_provider:
        if mode in ['client', 'provider']: session['view_mode'] = mode
    return redirect(url_for('user_dashboard'))


# ---------------- SECURE LOGIN & SIGNUP ----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            if user.role == 'admin': return redirect(url_for('admin.dashboard'))
            if user.is_provider: session['view_mode'] = 'provider'
            else: session['view_mode'] = 'client'
            return redirect(url_for('user_dashboard'))
        else: flash("Invalid email or password", "error"); return redirect("/login")
    return render_template("login.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        username = request.form.get("full_name")
        if User.query.filter_by(email=email).first(): return "Email exists!"
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password=hashed_pw, role="user", is_provider=False)
        db.session.add(new_user); db.session.commit()
        return redirect("/login")
    return app.send_static_file("signup.html")


@app.route("/logout")
@login_required
def logout():
    logout_user(); session.pop("chat_history", None); session.pop("view_mode", None); return redirect("/login")


# ---------------- PASSWORD RESET ----------------
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


# ---------------- MAIN EXECUTION ----------------
if __name__ == "__main__":
    with app.app_context(): 
        db.create_all()
        if not User.query.filter_by(email='brijeshpiadmin@gmail.com').first():
            print("Creating Master Admin...")
            admin_pw = generate_password_hash('Sathish@84', method='pbkdf2:sha256')
            admin = User(username='Master Admin', email='brijeshpiadmin@gmail.com', password=admin_pw, role='admin')
            db.session.add(admin)
            services = [
                Service(name="Plumber", price_range="$50-200", icon="fas fa-wrench"),
                Service(name="Electrician", price_range="$60-300", icon="fas fa-bolt"),
                Service(name="AC Service", price_range="$80-400", icon="fas fa-snowflake"),
                Service(name="Painter", price_range="$100+", icon="fas fa-paint-roller")
            ]
            db.session.add_all(services)
            campaigns = [
                Campaign(name="Summer Sale", platform="Facebook", status="Active", reach=12500, conversions=340, budget_spent=500.0, roi=120.5),
                Campaign(name="Google Ads Q1", platform="Google", status="Active", reach=45000, conversions=1200, budget_spent=1500.0, roi=210.0),
                Campaign(name="Email Blast", platform="Email", status="Completed", reach=5000, conversions=150, budget_spent=50.0, roi=300.0)
            ]
            db.session.add_all(campaigns)
            db.session.commit()
            print("System Initialized with Secured Admin!")
    app.run(debug=True)