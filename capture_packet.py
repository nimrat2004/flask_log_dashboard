from scapy.all import *
from datetime import datetime
from detect_anomaly import detect_port_scan, detect_icmp_flood
from utils import generate_hash
from utils import process_dns_packet, get_hostname

def start_sniffer(app, db, PacketLog, Incident):
    def process_packet(packet):
        with app.app_context():   

            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                protocol = "OTHER"
                src_port = None
                dst_port = None

                process_dns_packet(packet)

                # TCP
                if packet.haslayer(TCP):
                    protocol = "TCP"
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport

                # UDP
                elif packet.haslayer(UDP):
                    protocol = "UDP"
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport

                # Only for TCP/UDP packets
                if dst_port is not None:
                    detected, data = detect_port_scan(src_ip, dst_port)

                    if detected:
                        print(f"Port Scan Detected from {src_ip}")

                        # prepare data for hashing
                        incident_data = {
                            "timestamp": str(datetime.now()),
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "anomaly_type": "Port Scan",
                            "description": f"Ports scanned: {list(data['ports'])}"
                        }

                        # generate hash
                        hash_value = generate_hash(incident_data)

                        # Save to DB
                        incident = Incident(
                            timestamp=datetime.now(),
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            anomaly_type="Port Scan",
                            description=f"Ports scanned: {list(data['ports'])}",
                            hash_value=hash_value,
                        )

                        db.session.add(incident)
                        db.session.commit()

                # ICMP
                elif packet.haslayer(ICMP):
                    protocol = "ICMP"
                
                # ICMP Flood Detection
                if protocol == "ICMP":
                    detected, data = detect_icmp_flood(src_ip)

                    if detected:
                        print(f"ICMP Flood Detected from {src_ip}")

                        # prepare data for hashing
                        incident_data = {
                            "timestamp": str(datetime.now()),
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "anomaly_type": "ICMP Flood",
                            "description": f"ICMP packets: {data['count']} in short time"
                        }

                        # generate hash
                        hash_value = generate_hash(incident_data)

                        incident = Incident(
                            timestamp=datetime.now(),
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            anomaly_type="ICMP Flood",
                            description=f"ICMP packets: {data['count']} in short time",
                            hash_value=hash_value,
                        )

                        db.session.add(incident)
                        db.session.commit()

                packet_size = len(packet)

                if protocol in ["TCP", "UDP", "ICMP"] and dst_port in [80, 443, 53]:
                    # Create DB entry
                    log = PacketLog(
                        timestamp=datetime.now(),
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        protocol=protocol,
                        src_port=src_port,
                        dst_port=dst_port,
                        packet_size=packet_size
                    )
                    
                    # Save to DB
                    db.session.add(log)
                    db.session.commit()

                    # Print for debugging
                    print(f"{src_ip} → {dst_ip} | {protocol} | Size: {packet_size}")

    print("Sniffer started...")
    sniff(iface="Wi-Fi", prn=process_packet, store=0)
    #sniff(prn=process_packet, store=0)


        