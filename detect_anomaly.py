import time
from datetime import datetime
#PORT SCAN DETECTION LOGIC
# ------------------------------
#TEST COMMAND: nmap -p 1-100 127.0.0.1

port_scan_tracker = {}
icmp_tracker = {}
# STRUCTURE
# port_scan_tracker = {
#     "192.168.1.10": {
#         "ports": {22, 80, 443},
#         "first_seen": time
#     }
# }
PORT_THRESHOLD = 10     # number of ports
TIME_WINDOW = 10      # seconds
ICMP_THRESHOLD = 4

def detect_port_scan(src_ip, dst_port):
    current_time = time.time()

    if src_ip not in port_scan_tracker:
        port_scan_tracker[src_ip] = {
            "ports": set(),
            "first_seen": current_time
        }

    # Add port
    port_scan_tracker[src_ip]["ports"].add(dst_port)

    elapsed = current_time - port_scan_tracker[src_ip]["first_seen"]

    # Check within time window
    if elapsed <= TIME_WINDOW:
        if len(port_scan_tracker[src_ip]["ports"]) >= PORT_THRESHOLD:
            data = port_scan_tracker[src_ip]

            # Reset tracker
            port_scan_tracker[src_ip] = {
                "ports": set(),
                "first_seen": current_time
            }

            return True, data 
    else:
        # Reset if time expired
        port_scan_tracker[src_ip] = {
            "ports": set([dst_port]),
            "first_seen": current_time
        }

    return False, None

import time

    # number of packets
       # seconds


def detect_icmp_flood(src_ip):
    TIME_WINDOW = 10 
    current_time = time.time()

    if src_ip not in icmp_tracker:
        icmp_tracker[src_ip] = {
            "count": 0,
            "first_seen": current_time
        }

    icmp_tracker[src_ip]["count"] += 1

    elapsed = current_time - icmp_tracker[src_ip]["first_seen"]

    if elapsed <= TIME_WINDOW:
        if icmp_tracker[src_ip]["count"] > ICMP_THRESHOLD:
            data = icmp_tracker[src_ip]

            # reset after detection
            icmp_tracker[src_ip] = {
                "count": 0,
                "first_seen": current_time
            }

            return True, data

    else:
        # reset if window expired
        icmp_tracker[src_ip] = {
            "count": 1,
            "first_seen": current_time
        }

    return False, None