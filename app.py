import threading
import os
from dotenv import load_dotenv
from flask import Flask, render_template
from urllib.parse import quote_plus
from flask_sqlalchemy import SQLAlchemy
from capture_packet import start_sniffer

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
    logs = PacketLog.query.order_by(PacketLog.timestamp.desc()).all()
    return render_template('dashboard.html', logs=logs)

# ── Routes ───────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print("Starting SecureWatch dashboard at http://127.0.0.1:5000")
    # ── Start background thread ───────────────────────────────────────────────
    # thread = threading.Thread(target=start_sniffer,args=(app, db, PacketLog), daemon=True).start()
    app.run(debug=True)