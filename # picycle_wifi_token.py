# PiCycle Guard - WiFi + PostgreSQL + Login + Owner Proximity Check
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
import os, random, datetime, sys, math

sys.stdout.reconfigure(encoding='utf-8')

app = Flask(__name__)
app.secret_key = "supersecretkey"  # change this in production

# ---------------------- Railway PostgreSQL Setup ----------------------
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# ---------------------- Configuration ----------------------
OWNER_DISTANCE_THRESHOLD_M = 2.0  # meters
OWNER_LAST_SEEN_TIMEOUT = 300     # seconds (5 minutes)
ON_PI = False  # set True on Raspberry Pi with GPIO sensor

# ---------------------- Database Models ----------------------
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    device_token = db.Column(db.String(100))
    last_seen = db.Column(db.Float, default=0)
    last_lat = db.Column(db.Float, nullable=True)
    last_lon = db.Column(db.Float, nullable=True)
    created_at = db.Column(db.DateTime, default=db.func.now())

class Login(db.Model):
    __tablename__ = "logins"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100))
    ip_address = db.Column(db.String(100))
    login_time = db.Column(db.DateTime, default=db.func.now())

# ---------------------- Utility Functions ----------------------
def log_login(username, ip):
    db.session.add(Login(username=username, ip_address=ip))
    db.session.commit()

def log_alert(status, lat=None, lon=None):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] {status}"
    if lat and lon:
        entry += f" | Location: {lat}, {lon}"
    with open("alerts.log", "a", encoding="utf-8") as f:
        f.write(entry + "\n")
    print(entry)

def get_gps_coords():
    """Simulated GPS coordinate (replace with real GPS module on Pi)."""
    return 12.9716, 77.5946  # Bengaluru

def haversine_m(lat1, lon1, lat2, lon2):
    """Great-circle distance in meters between two points."""
    R = 6371000
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

def is_owner_nearby(username, cycle_lat, cycle_lon):
    """Return True if owner is within 2m and last update < 5 min old."""
    user = User.query.filter_by(username=username).first()
    if not user or not user.last_lat or not user.last_lon:
        return False
    if (datetime.datetime.now().timestamp() - float(user.last_seen)) > OWNER_LAST_SEEN_TIMEOUT:
        return False
    dist = haversine_m(cycle_lat, cycle_lon, user.last_lat, user.last_lon)
    print(f"[PROXIMITY] {username}: {dist:.2f}m from cycle (threshold {OWNER_DISTANCE_THRESHOLD_M}m)")
    return dist <= OWNER_DISTANCE_THRESHOLD_M

# ---------------------- Routes ----------------------
@app.route("/")
def home():
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template("index.html", username=session["username"])

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()
        user = User.query.filter_by(username=username).first()
        if user:
            if user.password == password:
                session["username"] = username
                log_login(username, request.remote_addr)
                return redirect(url_for("home"))
            else:
                error = "⚠️ Password does not match the username. Try again."
        else:
            error = "⚠️ No account found with the given username. Check the username or register your account."
    return render_template("login.html", error=error)

@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()
        if User.query.filter_by(username=username).first():
            error = "⚠️ Username already exists. Try a different one."
        else:
            token = f"TOKEN-{random.randint(10000, 99999)}"
            db.session.add(User(username=username, password=password, device_token=token))
            db.session.commit()
            session["username"] = username
            return redirect(url_for("home"))
    return render_template("register.html", error=error)

@app.route("/status")
def status():
    if "username" not in session:
        return jsonify({"error": "Not logged in"})
    status_text = "Monitoring..."
    maps_url = None
    cycle_lat, cycle_lon = get_gps_coords()

    vibration = False
    if ON_PI:
        try:
            import RPi.GPIO as GPIO
            vibration = GPIO.input(17) == 1
        except Exception:
            vibration = False
    else:
        vibration = random.choice([False, False, True])

    if vibration:
        owner_near = is_owner_nearby(session["username"], cycle_lat, cycle_lon)
        if owner_near:
            status_text = "✅ Owner nearby — ignoring vibration alert."
            print("[ALERT] Suppressed vibration alert (owner nearby).")
        else:
            status_text = "⚠️ Vibration Detected!"
            log_alert(status_text, cycle_lat, cycle_lon)
            maps_url = f"https://maps.google.com/?q={cycle_lat},{cycle_lon}"

    return jsonify({"status": status_text, "maps_url": maps_url})

@app.route("/keepalive", methods=["POST"])
def keepalive():
    """Update owner's GPS coordinates and timestamp."""
    data = request.get_json(silent=True) or {}
    lat, lon = data.get("lat"), data.get("lon")
    username = session.get("username")
    if not username:
        return jsonify({"ok": False, "error": "Not authenticated"}), 403
    try:
        lat, lon = float(lat), float(lon)
    except Exception:
        return jsonify({"ok": False, "error": "Invalid coordinates"}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"ok": False, "error": "User not found"}), 404

    user.last_seen = datetime.datetime.now().timestamp()
    user.last_lat = lat
    user.last_lon = lon
    db.session.commit()
    print(f"[KEEPALIVE] Updated {username}: lat={lat}, lon={lon}")
    return jsonify({"ok": True})

@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("login"))

# ---------------------- Run Flask ----------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    print("🚴 PiCycle Guard (WiFi + PostgreSQL + Proximity) running on http://127.0.0.1:5000/")
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
