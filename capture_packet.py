from scapy.all import *
from datetime import datetime

def start_sniffer(app, db, PacketLog):
    def process_packet(packet):
        with app.app_context():   

            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                protocol = "OTHER"
                src_port = None
                dst_port = None

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

                # ICMP
                elif packet.haslayer(ICMP):
                    protocol = "ICMP"

                # DNS (runs over UDP)
                if packet.haslayer(DNS):
                    protocol = "DNS"

                packet_size = len(packet)

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
            sniff(prn=process_packet, store=0)


        