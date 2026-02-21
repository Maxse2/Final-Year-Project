from dataclasses import dataclass, asdict
from datetime import timedelta
from typing import Any, Dict, List, Optional
import uuid

@dataclass
class PasswordSprayAlert:
    alert_type: str
    source_ip: str
    window_start: Any
    window_end: Any
    unique_user_count: int
    total_attempts: int
    usernames: list
    evidence: list
    alert_id: str
    
def get_event_timestamp(event):
    return event["event_timestamp"]
    
def detect_password_spray(
    events,
    window: timedelta=timedelta(minutes=10),
    min_unique_users=2,
    min_total_attempts=2,
    ):
    events_by_ip = {}
    alerts: List[PasswordSprayAlert] = []
    failed = [
        e for e in events
        if e.get("event_type") == "FAILED_LOGIN"
        and e.get("ip_address") is not None
        and e.get("username") is not None
    ]
    for e in failed:
        key_value=e.get("ip_address")
        events_by_ip.setdefault(str(key_value), []).append(e)
    for ip, ip_events in events_by_ip.items():
        ip_events.sort(key=lambda e: e["event_timestamp"])
        for i in range(len(ip_events)):
            start = ip_events[i]
            window_start = start["event_timestamp"]
            window_end = window_start + window
            window_events = []
            j=i
            while j <len(ip_events) and ip_events[j]["event_timestamp"]<= window_end:
                window_events.append(ip_events[j])
                j+=1
            usernames = {e["username"] for e in window_events}
            usernames = list(usernames)
            evidence = [e["event_id"] for e in window_events]
            unique_user_count = len(usernames)
            total_attempts = len(window_events)
            if unique_user_count >= min_unique_users and total_attempts >= min_total_attempts:
                alerts.append(
                    PasswordSprayAlert(
                        alert_type="PASSWORD_SPRAY",
                        source_ip=ip,
                        window_start=window_start,
                        window_end=window_end,
                        unique_user_count=unique_user_count,
                        total_attempts=total_attempts,
                        usernames=usernames,
                        evidence=evidence,
                        alert_id = str(uuid.uuid4()),
                        ))
    return alerts


