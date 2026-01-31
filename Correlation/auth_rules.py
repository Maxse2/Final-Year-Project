from datetime import datetime, timedelta
from collections import defaultdict

# Parses iso timestamps into a more readable format
def parse_iso(ts):
    return datetime.fromisoformat(ts)

# Bruteforce detection algorithm for auth.log - time window and threshold can be altered
def detect_bruteforce(events, windowminutes=5, threshold=5):
    window = timedelta(minutes=windowminutes)
    
    failedbyip = defaultdict(list)
    
    for e in events:
        if e.get("source") != "linux_auth":
            continue
        if e.get("event_type") != "FAILED_LOGIN":
            continue
        ip = e.get("ip_address")
        ts = e.get("event_timestamp")
        if not ip or not ts:
            continue
        
        try:
            failedbyip[ip].append(parse_iso(ts))
        except ValueError:
            continue
    alerts = []
    for ip,times in failedbyip.items():
        times.sort()
        start = 0
        
        for end in range(len(times)):
            while times[end] - times[start] > window:
                start += 1
        
            count = end-start+1
            if count >= threshold:
                alerts.append({
                    "alert_type": "POSSIBLE_BRUTE_FORCE",
                    "ip_address": ip,
                    "number_of_failed_logins": count,
                    "window_minutes":windowminutes,
                    "start_time":times[start].isoformat(),
                    "end_time": times[end].isoformat(),
                    })
                break
    return alerts
