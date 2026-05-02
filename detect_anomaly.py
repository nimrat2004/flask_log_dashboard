import time
from datetime import datetime
import re
from collections import Counter

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
PORT_THRESHOLD = 4     # number of ports
TIME_WINDOW = 20      # seconds
ICMP_THRESHOLD = 5

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


def detect_icmp_flood(src_ip):
    current_time = time.time()

    # Initialize
    if src_ip not in icmp_tracker:
        icmp_tracker[src_ip] = {
            "count": 1,
            "first_seen": current_time
        }
        return False, None

    # Calculate elapsed time
    elapsed = current_time - icmp_tracker[src_ip]["first_seen"]

    # Within time window
    if elapsed <= TIME_WINDOW:
        icmp_tracker[src_ip]["count"] += 1

        if icmp_tracker[src_ip]["count"] >= ICMP_THRESHOLD:
            data = icmp_tracker[src_ip]

            # Reset after detection
            icmp_tracker[src_ip] = {
                "count": 1,
                "first_seen": current_time
            }

            return True, data

    else:
        # Reset window
        icmp_tracker[src_ip] = {
            "count": 1,
            "first_seen": current_time
        }

    return False, None

# This dictionary MUST stay alive in memory to count packets
dns_stats = {} 

MAX_SUBDOMAIN_LENGTH = 10
QUERY_THRESHOLD = 3 # Lower this for easier testing

def detect_dns_tunnel(src_ip, query_name):
    # Clean the query string
    domain = query_name.strip('.')
    parts = domain.split('.')
    
    # Get the subdomain (everything before the main domain)
    subdomain = "".join(parts[:-2])
    sub_len = len(subdomain)

    if src_ip not in dns_stats:
        dns_stats[src_ip] = []

    # Store the current subdomain
    dns_stats[src_ip].append(subdomain)

    # DETECTION LOGIC
    # 1. Immediate Flag: Extremely long subdomain (Single packet detection)
    if sub_len > 60:
        desc = f"Critical: DNS Tunneling attempt. Subdomain length: {sub_len}"
        dns_stats[src_ip] = [] # Reset after catch
        return True, desc

    # 2. Frequency Flag: Many unique queries (Behavioral detection)
    if len(dns_stats[src_ip]) >= QUERY_THRESHOLD:
        unique_queries = len(set(dns_stats[src_ip]))
        
        # If > 70% of recent queries are unique and long
        if unique_queries > (QUERY_THRESHOLD * 0.7):
            desc = f"Suspicious DNS Activity: {unique_queries} unique queries detected."
            dns_stats[src_ip] = [] # Reset
            return True, desc

    return False, ""