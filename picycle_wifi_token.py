# picycle_wifi_final_proximity.py
# PiCycle Guard - WiFi-Based Version with Login, Registration, and Owner Proximity Check

from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import sqlite3, os, random, datetime, sys, math
from werkzeug.security import generate_password_hash, check_password_hash  # ✅ added secure hashing

sys.stdout.reconfigure(encoding='utf-8')

app = Flask(__name__)
app.secret_key = "supersecretkey"  # change for production
DB_FILE = "picycle.db"

# ---------------------- Configuration ----------------------
# distance threshold in meters under which owner's presence suppresses alerts
OWNER_DISTANCE_THRESHOLD_M = 2.0

# how recent (seconds) the owner's last location must be considered "current"
OWNER_LAST_SEEN_TIMEOUT = 300  # 5 minutes


# ---------------------- Database Setup ----------------------
def init_db():
    """Create DB and required tables/columns. Adds columns if missing (safe upgrade)."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    # Create users table if not exists (with base columns)
    c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        device_token TEXT,
        last_seen REAL DEFAULT 0,
        last_lat REAL DEFAULT NULL,
        last_lon REAL DEFAULT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    # Create logins table
    c.execute('''
    CREATE TABLE IF NOT EXISTS logins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        ip_address TEXT
    )
    ''')

    conn.commit()
    conn.close()


init_db()


# ---------------------- Helper Functions ----------------------
def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def get_user(username):
    """Return user record by username."""
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return user


def register_user(username, password):
    """Register new user securely (with password hashing)."""
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
    device_token = "TOKEN-" + str(random.randint(10000, 99999))
    conn = get_db_connection()
    try:
        conn.execute(
            "INSERT INTO users (username, password, device_token) VALUES (?, ?, ?)",
            (username, hashed_password, device_token),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def log_login(username, ip):
    """Log user login attempts."""
    conn = get_db_connection()
    conn.execute("INSERT INTO logins (username, ip_address) VALUES (?, ?)", (username, ip))
    conn.commit()
    conn.close()


def log_alert(status, lat=None, lon=None):
    """Log vibration alert with optional GPS data."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] {status}"
    if lat is not None and lon is not None:
        entry += f" | Location: {lat}, {lon}"
    with open("alerts.log", "a", encoding="utf-8") as f:
        f.write(entry + "\n")
    print(entry)


# ---------------------- Simulated IoT Logic ----------------------
ON_PI = False  # set True on actual Pi and wire sensor


def get_gps_coords():
    """
    Replace this with real GPS reading when on the Pi.
    For simulation we return a fixed coordinate.
    """
    return 12.9716, 77.5946  # Bengaluru (simulated)


# ---------------------- Proximity Utilities ----------------------
def haversine_m(lat1, lon1, lat2, lon2):
    """
    Calculate the great-circle distance between two points in meters.
    """
    R = 6371000  # Earth radius in meters
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)

    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c


def is_owner_nearby_for_username(username, cycle_lat, cycle_lon):
    """
    Returns True if the owner's last known position (stored in DB) is
    within OWNER_DISTANCE_THRESHOLD_M of the cycle coordinates and
    last_seen within OWNER_LAST_SEEN_TIMEOUT seconds.
    """
    user = get_user(username)
    if not user:
        return False

    last_seen = user["last_seen"]
    last_lat = user["last_lat"]
    last_lon = user["last_lon"]

    if last_lat is None or last_lon is None or last_seen is None:
        return False

    try:
        last_seen = float(last_seen)
    except Exception:
        return False

    # check recency
    if (datetime.datetime.now().timestamp() - last_seen) > OWNER_LAST_SEEN_TIMEOUT:
        return False

    # compute distance
    try:
        dist = haversine_m(cycle_lat, cycle_lon, float(last_lat), float(last_lon))
        # debug print
        print(f"[PROXIMITY] Distance owner->cycle = {dist:.2f} m (threshold {OWNER_DISTANCE_THRESHOLD_M} m)")
        return dist <= OWNER_DISTANCE_THRESHOLD_M
    except Exception as e:
        print("Error computing distance:", e)
        return False


# ---------------------- Flask Routes ----------------------
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

        user = get_user(username)

        if user:
            # ✅ Secure password verification
            if check_password_hash(user["password"], password):
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
    username_prefill = request.args.get("username", "")

    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()

        if register_user(username, password):
            session["username"] = username
            return redirect(url_for("home"))
        else:
            error = "⚠️ Username already exists. Try a different one."

    return render_template("register.html", error=error, username=username_prefill)


@app.route("/status")
def status():
    """
    Returns JSON with monitoring status. If vibration detected, it will check owner's proximity
    and suppress alert if owner is nearby.
    """
    if "username" not in session:
        return jsonify({"error": "Not logged in"})

    status_text = "Monitoring..."
    maps_url = None
    cycle_lat, cycle_lon = get_gps_coords()

    # Simulate or read real vibration input
    vibration = False
    if ON_PI:
        # Replace with real GPIO read, e.g., GPIO.input(VIBRATION_PIN) == 1
        try:
            import RPi.GPIO as GPIO
            vibration = GPIO.input(17) == 1
        except Exception:
            vibration = False
    else:
        vibration = random.choice([False, False, True])

    if vibration:
        # Check proximity: is the owner (the logged-in user) nearby?
        owner_near = is_owner_nearby_for_username(session["username"], cycle_lat, cycle_lon)

        if owner_near:
            status_text = "✅ Owner nearby — ignoring vibration alert."
            print("[ALERT] Vibration detected but owner nearby -> suppressed.")
        else:
            status_text = "⚠️  Vibration Detected!"
            log_alert(status_text, cycle_lat, cycle_lon)
            maps_url = f"https://maps.google.com/?q={cycle_lat},{cycle_lon}"

    return jsonify({"status": status_text, "maps_url": maps_url})


@app.route("/keepalive", methods=["POST"])
def keepalive():
    """
    Owner's device (browser/app) should POST JSON with { "lat": float, "lon": float }
    If user is logged-in on that device, the session username will be used to update
    the DB last_seen and last coordinates.
    """
    data = request.get_json(silent=True) or {}
    lat = data.get("lat")
    lon = data.get("lon")

    username = session.get("username")
    if not username:
        return jsonify({"ok": False, "error": "Not authenticated via session"}), 403

    try:
        lat = float(lat)
        lon = float(lon)
    except Exception:
        return jsonify({"ok": False, "error": "Invalid lat/lon"}), 400

    conn = get_db_connection()
    now_ts = datetime.datetime.now().timestamp()
    conn.execute("UPDATE users SET last_seen = ?, last_lat = ?, last_lon = ? WHERE username = ?",
                 (now_ts, lat, lon, username))
    conn.commit()
    conn.close()
    print(f"[KEEPALIVE] Updated {username} -> lat={lat}, lon={lon}, ts={now_ts}")
    return jsonify({"ok": True})


@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("login"))


# ---------------------- Run Flask ----------------------
if __name__ == "__main__":
    print("🚴 PiCycle Guard (WiFi + DB + Proximity + Secure Passwords) running at http://127.0.0.1:5000/")
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
