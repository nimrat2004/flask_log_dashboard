# detect_anomaly.py
from datetime import datetime, timedelta

login_history = {}

BRUTE_FORCE_THRESHOLD = 2  # attempts
TIME_WINDOW = 30           # seconds

def detect_brute_force(src_ip, payload):
    
    # Convert payload to lowercase to avoid case-sensitivity issues
    payload_str = str(payload).lower()
    
    # Broad check: If it's a POST request and mentions our login route
    if "post" in payload_str and "/login" in payload_str:
        now = datetime.now()
        
        if src_ip not in login_history:
            login_history[src_ip] = []
        
        login_history[src_ip].append(now)
        
        # Keep only last 30 seconds
        thirty_seconds_ago = now - timedelta(seconds=30)
        login_history[src_ip] = [t for t in login_history[src_ip] if t > thirty_seconds_ago]
        
        # DEBUG PRINT: This will tell us if the logic is even being triggered
        print(f"[DEBUG] Login attempt tracked for {src_ip}. Count: {len(login_history[src_ip])}")

        if len(login_history[src_ip]) >= 5:
            desc = f"Brute Force Detected: {len(login_history[src_ip])} attempts in 30s"
            login_history[src_ip] = [] # Reset
            return True, desc
            
    return False, ""