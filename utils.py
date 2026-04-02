import hashlib
import json
import os
from scapy.layers.dns import DNS, DNSQR
# import socket

def generate_hash(data):
    # ensure consistent ordering
    data_string = json.dumps(data, sort_keys=True)
    return hashlib.sha256(data_string.encode()).hexdigest()

# hostname_cache = {}

# def get_hostname(ip):
#     if ip in hostname_cache:
#         return hostname_cache[ip]

#     try:
#         hostname = socket.gethostbyaddr(ip)[0]
#     except:
#         hostname = "Unknown"

#     hostname_cache[ip] = hostname
#     return hostname



DNS_FILE = "dns_cache.json"

# Load cache from file
if os.path.exists(DNS_FILE):
    with open(DNS_FILE, "r") as f:
        dns_cache = json.load(f)
else:
    dns_cache = {}

def save_dns_cache():
    with open(DNS_FILE, "w") as f:
        json.dump(dns_cache, f, indent=4)

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

def get_hostname(ip):
    return dns_cache.get(ip, "Unknown")