import time

syn_tracker = {}
SYN_THRESHOLD = 5
TIME_WINDOW = 20

def detect_syn_flood(src_ip):
    current_time = time.time()

    if src_ip not in syn_tracker:
        syn_tracker[src_ip] = {
            "count": 1,
            "first_seen": current_time
        }
        return False, None

    elapsed = current_time - syn_tracker[src_ip]["first_seen"]

    if elapsed <= TIME_WINDOW:
        syn_tracker[src_ip]["count"] += 1

        if syn_tracker[src_ip]["count"] >= SYN_THRESHOLD:
            data = syn_tracker[src_ip]

            syn_tracker[src_ip] = {
                "count": 1,
                "first_seen": current_time
            }

            return True, data

    else:
        syn_tracker[src_ip] = {
            "count": 1,
            "first_seen": current_time
        }

    return False, None