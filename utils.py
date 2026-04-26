import hashlib
import json
import os
import socket
from scapy.layers.dns import DNS, DNSQR
from detect_anomaly import detect_dns_tunnel
from datetime import datetime

DNS_FILE = "dns_cache.json"
def generate_hash(data):
    data_string = json.dumps(data, sort_keys=True)
    return hashlib.sha256(data_string.encode()).hexdigest()

# --- 1. INITIALIZE CACHE ---
if os.path.exists(DNS_FILE):
    try:
        with open(DNS_FILE, "r") as f:
            dns_cache = json.load(f)
    except Exception:
        dns_cache = {}
else:
    dns_cache = {}

def save_dns_cache():
    try:
        with open(DNS_FILE, "w") as f:
            json.dump(dns_cache, f, indent=4)
    except Exception as e:
        print(f"Error saving DNS cache: {e}")

def process_dns_packet(packet):
    try:
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            dns_layer = packet[DNS]
            domain = packet[DNSQR].qname.decode().strip('.')

            if dns_layer.an:
                for i in range(dns_layer.ancount):
                    answer = dns_layer.an[i]

                    if answer.type == 1:
                        resolved_ip = answer.rdata

                        # Save mapping
                        dns_cache[resolved_ip] = domain

                        # Save to file
                        save_dns_cache()

    except Exception:
        pass
    
# # --- 3. THE HYBRID LOOKUP LOGIC ---
# def get_hostname(ip):
#     """
#     Finds a hostname using a 3-step priority:
#     1. Local JSON Cache
#     2. OS Reverse DNS (PTR lookup)
#     3. Fallback to 'Unknown'
#     """
#     # Step 1: Check internal cache (Passive discovery results)
#     if ip in dns_cache:
#         return dns_cache[ip]

#     # Step 2: Active Reverse DNS Lookup (Asking the network/router)
#     # This is useful for catching names of devices already connected 
#     # before you started the sniffer.
#     try:
#         # socket.gethostbyaddr performs a PTR query
#         hostname, alias, addresslist = socket.gethostbyaddr(ip)
        
#         # Update cache so we don't have to do a slow network query again
#         dns_cache[ip] = hostname
#         save_dns_cache()
#         return hostname
#     except (socket.herror, socket.gaierror, socket.timeout):
#         # herror: No record found for this IP
#         pass

#     # Step 3: Localhost Fallbacks
#     local_ips = {
#         "127.0.0.1": "localhost",
#         "0.0.0.0": "any",
#         "8.8.8.8": "google-public-dns"
#     }
    
#     return local_ips.get(ip, "Unknown")

# utils.py

# A local memory cache to avoid even reading the JSON file every time
memory_cache = {}
def get_hostname(ip):
  
    if ip in memory_cache:
        return memory_cache[ip]

    if ip in dns_cache:
        memory_cache[ip] = dns_cache[ip]
        return dns_cache[ip]

    local_mapping = {"127.0.0.1": "localhost", "0.0.0.0": "any"}
    if ip in local_mapping:
        return local_mapping[ip]

    return "Unknown"

import socket

def get_my_ip():
    """Returns the primary IP address of the local machine."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # We don't actually send data. This just opens a path to see 
        # which local interface would be used to reach the internet.
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        # Fallback to loopback if no network is available
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

# Use it like this:
my_current_ip = get_my_ip()

def cleanup_old_logs(PacketLog, db):
    # Get the 50th newest log's ID
    cutoff = PacketLog.query.order_by(PacketLog.id.desc()).offset(50).first()
    
    if cutoff:
        PacketLog.query.filter(PacketLog.id < cutoff.id).delete()
        db.session.commit()