from scapy.all import *
from datetime import datetime
from detect_anomaly import detect_port_scan, detect_icmp_flood, detect_dns_tunnel
from utils import generate_hash
from utils import process_dns_packet, get_hostname
from syn_flood_detector import detect_syn_flood
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, UDP, ICMP

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
                    tcp_layer = packet[TCP]
                    detected = False
                    data = None
                    if tcp_layer.flags & 0x02:
                        detected, data = detect_syn_flood(src_ip)

                        if detected:
                            print(f"SYN Flood Detected from {src_ip}")

                            # prepare data for hashing
                            incident_data = {
                                "timestamp": str(datetime.now()),
                                "src_ip": src_ip,
                                "dst_ip": dst_ip,
                                "anomaly_type": "SYNFlood",
                                "description": f"SYN Flood from {src_ip}. Total requests: {data['count']}"
                            }

                            # generate hash
                            hash_value = generate_hash(incident_data)

                            incident = Incident(
                                timestamp=datetime.now(),
                                src_ip=src_ip,
                                dst_ip=dst_ip,
                                anomaly_type="SYNFlood",
                                description=f"SYN Flood from {src_ip}. Total requests: {data['count']}",
                                hash_value=hash_value,
                            )

                            db.session.add(incident)
                            db.session.commit()

                # UDP
                elif packet.haslayer(UDP):
                    protocol = "UDP"
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    if src_port == 53 or dst_port == 53:
                        try:
                            # Manually extract the payload and force-load as DNS
                            raw_payload = bytes(packet[UDP].payload)
                            dns_data = DNS(raw_payload)
                            
                            
                            if dns_data.qr == 0:  # 0 means it's a Query, 1 is a Response
                                query_name = dns_data.qd.qname.decode('utf-8')
                                print(f"[*] Successfully Captured DNS: {query_name}")
                              
                                is_attack, desc = detect_dns_tunnel(packet[IP].src, query_name)
                                print("is_attack", is_attack)
                                if is_attack:
                                    incident_data = {
                                        "timestamp": str(datetime.now()),
                                        "src_ip": src_ip,
                                        "dst_ip": dst_ip,
                                        "anomaly_type": "DNS Tunneling",
                                        "description": desc
                                    }

                                    # generate hash
                                    hash_value = generate_hash(incident_data)
                             
                                    new_incident = Incident(
                                        timestamp=datetime.now(),
                                        src_ip=src_ip,
                                        dst_ip=dst_ip,
                                        anomaly_type="DNS Tunneling",
                                        description= desc,
                                        hash_value = hash_value

                                    )
                                    db.session.add(new_incident)
                                    db.session.commit()
                                    
                        except Exception as e:
                            
                            pass

                # ICMP
                elif packet.haslayer(ICMP):
                    protocol = "ICMP"
                    detected = False
                    data = None
                    
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

                packet_size = len(packet)

                if protocol == "ICMP" or (protocol in ["TCP", "UDP"] and (dst_port in [80, 443, 53] or src_port in [80, 443, 53])):
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
                    #print(f"{src_ip} → {dst_ip} | {protocol} | Size: {packet_size}")

    print("Sniffer started...")
    sniff(iface="Wi-Fi", prn=process_packet, filter= "", store=0)
    


        