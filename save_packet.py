
from datetime import datetime
from utils import generate_hash

def log_packet(PacketLog, db, src_ip, dst_ip, protocol, src_port, dst_port, packet_size):

    log = PacketLog(
        timestamp=datetime.now(),
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        src_port=src_port,
        dst_port=dst_port,
        packet_size=packet_size
        )
   
    db.session.add(log)
    db.session.commit()
 

def save_incident(Incident, db, src_ip, dst_ip, anomaly_type, desc):

    incident_data = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "anomaly_type": anomaly_type,
        "description": desc
    }
    hash_value = generate_hash(incident_data)

    incident = Incident(
        timestamp=datetime.now(),
        src_ip=src_ip,
        dst_ip=dst_ip,
        anomaly_type= anomaly_type,
        description= desc,
        hash_value=hash_value,
    )
    db.session.add(incident)
    db.session.commit()