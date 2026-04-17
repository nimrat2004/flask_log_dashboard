import time

brute_force_tracker = {}
BF_THRESHOLD = 10        # failed attempts before alert
TIME_WINDOW = 60         # within 60 seconds

def detect_brute_force(src_ip):
    current_time = time.time()

    if src_ip not in brute_force_tracker:
        
        brute_force_tracker[src_ip] = {
            "count": 1,
            "first_seen": current_time
        }

        return False, None

    elapsed = current_time - brute_force_tracker[src_ip]["first_seen"]

    if elapsed <= TIME_WINDOW:
        brute_force_tracker[src_ip]["count"] += 1

        print(f"[BF DEBUG] {src_ip} → attempts: {brute_force_tracker[src_ip]['count']}")

        if brute_force_tracker[src_ip]["count"] >= BF_THRESHOLD:
            data = dict(brute_force_tracker[src_ip])

            # reset after detection
            brute_force_tracker[src_ip] = {
                "count": 1,
                "first_seen": current_time
            }

            return True, data
    else:
        # time window expired, reset
        brute_force_tracker[src_ip] = {
            "count": 1,
            "first_seen": current_time
        }

    return False, None