from __future__ import annotations
from dataclasses import dataclass, asdict
from datetime import timedelta
from typing import Any, Dict, List, Optional


@dataclass
class BruteForceAlert:
    alert_type: str                
    start: Any                 
    end: Any                     
    key: str                       
    count: int                     
    evidence: Dict[str, Any]        

def get_event_timestamp(event):
    return event["event_timestamp"]

def detect_bruteforce(
    events,
    *,
    threshold: 5,
    window: timedelta = timedelta(minutes=2),
    group_by:"ip",  
    ):
    failed = [e for e in events if e.get("event_type") == "FAILED_LOGIN"]
    failed = [e for e in failed if e.get("event_timestamp") is not None]
    failed.sort(key=get_event_timestamp)
    groups = {}
    for e in failed:
        if group_by == "ip":
            key_value = e.get("ip_address")
        elif group_by == "username":
            key_value = e.get("username")
        else:
            raise ValueError("group_by must be 'ip' or 'username'")
        if not key_value:
            continue
        groups.setdefault(str(key_value), []).append(e)
    
    alerts: List[BruteForceAlert] = []
    for key,evs in groups.items():
        start_idx=0
        for end_idx in range(len(evs)):
            while evs[end_idx]["event_timestamp"] - evs[start_idx]["event_timestamp"] > window:
                start_idx+= 1
            events_in_window = end_idx-start_idx+1
            if events_in_window >= threshold:
                alerts.append(
                    BruteForceAlert(
                        alert_type="POTENTIAL_BRUTE_FORCE",
                        start=evs[start_idx]["event_timestamp"],
                        end=evs[end_idx]["event_timestamp"],
                        key=f"{group_by}:{key}",
                        count=events_in_window,
                        evidence={
                            "threshold":threshold,
                            "window_seconds":int(window.total_seconds()),
                            "group_by":group_by,
                            }))
                start_idx=end_idx+1
                        
                        
                
    return alerts








