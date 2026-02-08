#NOT IMPOSSIBLE TRAVEL - RENAME TO SOMETHING ELSE

from __future__ import annotations
from dataclasses import dataclass
from datetime import timedelta
from ipaddress import ip_address, ip_network
from typing import Any, Dict, List, Optional, Literal

@dataclass
class SuspiciousTransitionAlert:
    alert_type: str                
    username: str
    start: Any                 
    end: Any
    delta: int
    prev_ip: str
    prev_zone: str
    curr_ip: str
    curr_zone: str               
    evidence: Dict[str, Any]     



Zone = Literal["internal","external","unknown"]

private_ranges = [
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ]

loopback = ip_network("127.0.0.0/8")

def get_event_timestamp(event):
    return event["event_timestamp"]

def zone_classifier(ip):
    if not ip:
        return "unknown"
    
    ip = ip.strip()
    if ip == "::1":
        return "internal"
    
    try:
        ip_obj = ip_address(ip)
    except ValueError:
        return "unknown"
    if ip_obj.version ==6:
        return "unknown"
    if ip_obj in loopback:
        return "internal"
    for net in private_ranges:
        if ip_obj in net:
            return "internal"
    return "external"

def detect_network_change(events,
                          *,
                          group_by="username",
                          window: timedelta = timedelta(minutes=2)):
    filtered = [e for e in events if e.get("event_type") == "SUCCESSFUL_LOGIN"]
    filtered = [e for e in filtered if e.get("event_timestamp") is not None]
    filtered.sort(key=get_event_timestamp)
    groups = {}
    for e in filtered:
        ip_addr = e["ip_address"]
        zone = zone_classifier(ip_addr)
        if zone == "unknown":
            continue
        if group_by == "username":
            key_value = e.get("username")
        else:
            raise ValueError("group_by must be 'username'")
        if not key_value:
            continue
        groups.setdefault(str(key_value), []).append(e)
    alerts: List[SuspiciousTransitionAlert] = []
    for username,user_event in groups.items():
        user_event.sort(key=get_event_timestamp)
        for i in range(len(user_event)-1):
            prev_event = user_event[i]
            curr_event = user_event[i+1]
            prev_ts = prev_event.get("event_timestamp")
            curr_ts = curr_event.get("event_timestamp")
            prev_id = prev_event.get("event_id")
            curr_id = curr_event.get("event_id")
            prev_ip=prev_event.get("ip_address")
            curr_ip = curr_event.get("ip_address")
            prev_zone= zone_classifier(prev_ip)
            curr_zone = zone_classifier(curr_ip)
            timedeltats = curr_ts - prev_ts
            if prev_zone != curr_zone:
                if timedeltats <= window:
                    alerts.append(
                        SuspiciousTransitionAlert(
                            alert_type="SUSPICIOUS_NETWORK_TRANSITION",
                            username=username,
                            start= prev_ts,
                            end= curr_ts,
                            delta= timedeltats,
                            prev_ip=prev_ip,
                            prev_zone=prev_zone,
                            curr_ip=curr_ip,
                            curr_zone=curr_zone,
                            evidence={
                                "window_seconds":int(window.total_seconds()),
                                "delta_seconds":int(timedeltats.total_seconds()),
                                "prev_event_id":prev_id,
                                "curr_event_id":curr_id},
                            ))
    return alerts
                                
                                
                            
                    
        
    
