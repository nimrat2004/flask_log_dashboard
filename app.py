import threading
import os
from dotenv import load_dotenv
from flask import Flask, render_template
from urllib.parse import quote_plus
from flask_sqlalchemy import SQLAlchemy
from capture_packet import start_sniffer
from flask import jsonify, request
from utils import get_hostname, my_current_ip, cleanup_old_logs

load_dotenv()
DB_PASSWORD = quote_plus(os.getenv("DB_PASSWORD"))
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://root:{DB_PASSWORD}@localhost/network_monitor'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

#Table 1: Packet Logs
class PacketLog(db.Model):
    __tablename__ = 'packet_logs'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime)
    src_ip = db.Column(db.String(45))
    dst_ip = db.Column(db.String(45))
    protocol = db.Column(db.String(10))
    src_port = db.Column(db.Integer)
    dst_port = db.Column(db.Integer)
    packet_size = db.Column(db.Integer)
    
    def __repr__(self):
        return f"{id}: {self.protocol}"

#Table 2: Incidents
class Incident(db.Model):
    __tablename__ = 'incidents'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime)
    src_ip = db.Column(db.String(45))
    dst_ip = db.Column(db.String(45))
    anomaly_type = db.Column(db.String(100))
    description = db.Column(db.Text)
    pcap_file = db.Column(db.String(255))
    hash_value = db.Column(db.String(255))

    def __repr__(self):
        return f"{id}: {self.anomaly_type}"


# ── Routes ───────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    cleanup_old_logs(PacketLog, db)

    logs = PacketLog.query.order_by(PacketLog.id.desc()).limit(50).all()
    alerts = Incident.query.order_by(Incident.id.desc()).limit(50).all()

    total_logs_count = PacketLog.query.count()
    total_alerts_count = Incident.query.count()

    for log in logs:
        target_ip = log.src_ip if my_current_ip == log.dst_ip else log.dst_ip
        log.hostname = get_hostname(target_ip)

    return render_template(
        'dashboard.html',
        logs=logs,
        alerts=alerts,
        total_logs_count=total_logs_count,
        total_alerts_count=total_alerts_count
    )


@app.route("/api/logs")
def get_logs():
    last_id = request.args.get('last_id', default=0, type=int)

    new_logs = (
        PacketLog.query
        .filter(PacketLog.id > last_id)
        .order_by(PacketLog.id.asc())
        .limit(40)
        .all()
    )

    total_logs_count = PacketLog.query.count()

    data = []
    for log in new_logs:
        target_ip = log.src_ip if my_current_ip == log.dst_ip else log.dst_ip
        data.append({
            "id": log.id,
            "timestamp": log.timestamp.strftime("%H:%M:%S"),
            "src_ip": log.src_ip,
            "dst_ip": log.dst_ip,
            "hostname": get_hostname(target_ip),   # now cached — no hang
            "protocol": log.protocol,
            "ports": f"{log.src_port} → {log.dst_port}",
            "size": log.packet_size
        })

    return jsonify({
        "logs": data,
        "total_logs": total_logs_count    # ← TRUE count, not batch size
    })


@app.route("/api/incidents")
def get_incidents():
    last_id = request.args.get('last_id', default=0, type=int)

    incidents = (
        Incident.query
        .filter(Incident.id > last_id)
        .order_by(Incident.id.asc())
        .limit(10)                     
        .all()
    )

    total_alerts_count = Incident.query.count()  

    data = []
    for inc in incidents:
        data.append({
            "id": inc.id,
            "timestamp": inc.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": inc.src_ip,
            "dst_ip": inc.dst_ip,
            "type": inc.anomaly_type,
            "desc": inc.description
        })

    return jsonify({
        "data": data,
        "total_alerts": total_alerts_count   
    })

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Simulate a real login check
        username = request.form.get('username')
        password = request.form.get('password')
        
        # This is where the "failure" happens
        if username == "admin" and password == "secret123":
            return "Login Successful"
        else:
            return "Invalid Credentials", 401 # 401 is key for detection
    return render_template('login.html')
# ── Routes ───────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print("Starting SecureWatch dashboard at http://127.0.0.1:5000")
    # ── Start background thread ───────────────────────────────────────────────
    #thread = threading.Thread(target=start_sniffer,args=(app, db, PacketLog, Incident), daemon=True).start()
    app.run(host='0.0.0.0', port=5000, debug=True)