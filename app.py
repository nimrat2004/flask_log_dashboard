from flask import Flask, render_template
from flask_socketio import SocketIO
import time
import threading
import random
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, async_mode='threading')

# ── Sample Data ──────────────────────────────────────────────────────────────

USERS = ['Alice', 'Bob', 'Jashan', 'User 2', 'User 4', 'Morgan', 'Chen', 'Priya']
ACCESS_POINTS = [f'AP {i}' for i in [7, 20, 43, 48, 12, 31, 55, 6, 19]]
DIRECTIONS = ['ENTRY', 'ENTRY', 'ENTRY', 'EXIT']   # weighted toward ENTRY

ALERT_DESCRIPTIONS = [
    "Impossible Journey detected from {loc1} to {loc2}. Distance: {dist}m, Velocity: {vel} m/s",
    "Multiple failed badge attempts at {loc1} by {user}",
    "After-hours access attempt at {loc1} — outside permitted schedule",
    "Tailgating detected at {loc1}: two people, one credential",
    "Credential reuse detected: same badge at {loc1} and {loc2} simultaneously",
    "Rapid successive entries at {loc1} — possible relay attack",
]

LOCATIONS = [
    'Dalton PLC – Floor 1',
    'Beck and Sons – Floor 4',
    'Main Lobby',
    'Server Room B',
    'Executive Suite',
    'Parking – Level 2',
]

RISK_LEVELS = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
RISK_WEIGHTS = [40, 30, 20, 10]   # probability weights

LOG_MESSAGES = [
    "System heartbeat OK",
    "Badge reader {ap} online",
    "Door sensor {ap} — state nominal",
    "Access granted: {user} → {ap}",
    "Access denied: unknown credential at {ap}",
    "Camera feed {ap} connected",
    "Intrusion sensor {ap} — no motion",
    "Network link to {ap} stable",
    "Auth token refreshed for {user}",
    "Audit flush — {n} records written to DB",
]


def now_ts():
    return datetime.now().strftime('%H:%M:%S')


# ── Background Thread — emit mixed events ────────────────────────────────────

def emit_events():
    """Continuously emit three types of events to the dashboard."""
    count = 0

    while True:
        count += 1
        roll = random.random()

        # ── 1. Generic log stream (always) ──────────────────────────────────
        user = random.choice(USERS)
        ap   = random.choice(ACCESS_POINTS)
        msg_template = random.choice(LOG_MESSAGES)
        message = (msg_template
                   .replace('{user}', user)
                   .replace('{ap}',   ap)
                   .replace('{n}',    str(random.randint(50, 500))))

        socketio.emit('new_log', {
            'type':    'stream',
            'message': f'[{now_ts()}] #{count:04d}  {message}',
        })

        # ── 2. Access log (70 % of ticks) ───────────────────────────────────
        if roll < 0.70:
            direction = random.choice(DIRECTIONS)
            socketio.emit('new_log', {
                'type':         'access',
                'user':         user,
                'access_point': ap,
                'direction':    direction,
            })

        # ── 3. Security alert (15 % of ticks) ────────────────────────────────
        if roll > 0.85:
            loc1  = random.choice(LOCATIONS)
            loc2  = random.choice([l for l in LOCATIONS if l != loc1])
            dist  = round(random.uniform(100_000, 9_000_000), 2)
            vel   = round(random.uniform(5_000, 400_000), 2)
            risk  = random.choices(RISK_LEVELS, weights=RISK_WEIGHTS, k=1)[0]

            desc_template = random.choice(ALERT_DESCRIPTIONS)
            description = (desc_template
                           .replace('{loc1}', loc1)
                           .replace('{loc2}', loc2)
                           .replace('{dist}', f'{dist:,.2f}')
                           .replace('{vel}',  f'{vel:,.2f}')
                           .replace('{user}', user))

            socketio.emit('new_log', {
                'type':        'alert',
                'user':        user,
                'risk_level':  risk,
                'velocity':    f'{vel:,.2f} m/s',
                'description': description,
            })

        # Emit every 2 seconds
        time.sleep(2)


# ── Routes ───────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('dashboard.html')


# ── Start background thread ───────────────────────────────────────────────────

threading.Thread(target=emit_events, daemon=True).start()

if __name__ == '__main__':
    print("Starting SecureWatch dashboard at http://127.0.0.1:5000")
    socketio.run(app, debug=True)