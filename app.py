import threading
import os
from dotenv import load_dotenv
from flask import Flask, render_template
from urllib.parse import quote_plus
from flask_sqlalchemy import SQLAlchemy
from capture_packet import start_sniffer
from flask import jsonify, request
from utils import get_hostname, my_current_ip, generate_hash
from scapy.all import conf
from datetime import datetime

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

# def save_incident(timestamp,src_ip,dst_ip, anomaly_type,description):
# # prepare data for hashing
#     incident_data = {
#         "timestamp": str(timestamp),
#         "src_ip": src_ip,
#          "dst_ip": dst_ip,
#         "anomaly_type": anomaly_type,
#         "description": description
#     }

#     # generate hash
#     hash_value = generate_hash(incident_data)

#     incident = Incident(
#         timestamp=datetime.now(),
#         src_ip=src_ip,
#         dst_ip=dst_ip,
#         anomaly_type= anomaly_type,
#         description= description,
#         hash_value=hash_value,
#     )

#     db.session.add(incident)
#     db.session.commit()



# ── Routes ───────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    logs = PacketLog.query.order_by(PacketLog.id.desc()).limit(200).all()
    alerts = Incident.query.order_by(Incident.id.desc()).limit(200).all()

    for log in logs:
        target_ip = log.src_ip if my_current_ip == log.dst_ip else log.dst_ip
        log.hostname = get_hostname(target_ip)
        
    return render_template('dashboard.html', logs=logs, alerts=alerts)


@app.route("/api/logs")
def get_logs():
    # Get the last seen ID from the frontend request (default to 0)
    last_id = request.args.get('last_id', default=0, type=int)

    # 1. Fetch only new logs
    new_logs = PacketLog.query.filter(PacketLog.id > last_id).order_by(PacketLog.id.asc()).limit(100).all()
    
    # 2. Get the count of THIS specific batch
    total_logs = len(new_logs)
  
    last_id = request.args.get('last_id', default=0, type=int)

    data = []
    for log in new_logs:
        target_ip = log.src_ip if my_current_ip == log.dst_ip else log.dst_ip
        data.append({
            "id": log.id,
            "timestamp": log.timestamp.strftime("%H:%M:%S"),
            "src_ip": log.src_ip,
            "dst_ip": log.dst_ip,
            "hostname": get_hostname(target_ip),
            "protocol": log.protocol,
            "ports": f"{log.src_port} → {log.dst_port}",
            "size": log.packet_size
        })
    
    # Return as a dictionary
    return jsonify({
        "logs": data,
        "total_logs": total_logs,
       
    })

# Add a similar one for Incidents
@app.route("/api/incidents")
def get_incidents():
    last_id = request.args.get('last_id', default=0, type=int)
    incidents = Incident.query.filter(Incident.id > last_id).order_by(Incident.id.asc()).all()
    
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
    total_alerts = len(incidents)

    return jsonify({
        "data": data,
        "total_alerts": total_alerts
    })
# ── Routes ───────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print("Starting SecureWatch dashboard at http://127.0.0.1:5000")
    # ── Start background thread ───────────────────────────────────────────────
    #thread = threading.Thread(target=start_sniffer,args=(app, db, PacketLog, Incident), daemon=True).start()
    app.run(debug=True)