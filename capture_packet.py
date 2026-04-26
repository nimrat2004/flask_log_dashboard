from scapy.all import *
from datetime import datetime
from detect_anomaly import detect_port_scan, detect_icmp_flood, detect_dns_tunnel
from utils import generate_hash
from utils import process_dns_packet, get_hostname
from syn_flood_detector import detect_syn_flood
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, UDP, ICMP, TCP
from brute_force_detector import detect_brute_force
from save_packet import log_packet, save_incident

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
                
                if packet.haslayer(TCP):
                    payload = ""
                    if packet[TCP].dport == 5000:
                    
                        payload_bytes = bytes(packet[TCP].payload)
                            
                        if payload_bytes:
                            payload = payload_bytes.decode('utf-8', errors='ignore')
                        
                        is_attack, desc = detect_brute_force(packet[IP].src, payload)
                       
                        if is_attack:
                            print(f"Brute Force Attack Detected {src_ip}")
                            save_incident(Incident, db, src_ip, dst_ip, "Brute Force",  desc)
                   
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
                            save_incident(Incident, db, src_ip, dst_ip, "SYN Flood",  f"SYN Flood from {src_ip}. Total requests: {data['count']}")

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
                            
                            if dns_data.qr == 0:  
                                query_name = dns_data.qd.qname.decode('utf-8')
                                is_attack, desc = detect_dns_tunnel(packet[IP].src, query_name)
                                if is_attack:
                                    print("DNS Tunneling Detected")
                                    save_incident(Incident, db, src_ip, dst_ip, "DNS Tunneling",  desc)
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
                        save_incident(Incident, db, src_ip, dst_ip, "ICMP Flood", f"ICMP packets: {data['count']} in short time")

                # Only for TCP/UDP packets
                if dst_port is not None:
                    detected, data = detect_port_scan(src_ip, dst_port)

                    if detected:
                        print(f"Port Scan Detected from {src_ip}")
                        save_incident(Incident, db, src_ip, dst_ip, "Port Scan", f"Ports scanned: {list(data['ports'])}")

                if protocol == "ICMP" or (protocol in ["TCP", "UDP"] and (dst_port in [80, 443, 53, 50000] or src_port in [80, 443, 53, 5000])):
                    packet_size = len(packet)
                    log_packet(PacketLog, db, src_ip, dst_ip, protocol, src_port, dst_port, packet_size)

                    # Print for debugging
                    #print(f"{src_ip} → {dst_ip} | {protocol} | Size: {packet_size}")

    print("Sniffer started...")
    sniff(iface="Wi-Fi", prn=process_packet, filter= "", store=0)
    


        