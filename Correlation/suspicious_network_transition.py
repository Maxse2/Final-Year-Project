from __future__ import annotations
from datetime import timedelta
from ipaddress import ip_address, ip_network
from typing import List, Literal
from Engine.alerts import Alert, new_alert_id
from Engine.baserule import BaseRule

Zone = Literal["internal", "external", "unknown"]

private_ranges = [
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
]
loopback = ip_network("127.0.0.0/8")

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
    if ip_obj.version == 6:
        return "unknown"
    if ip_obj in loopback:
        return "internal"
    for net in private_ranges:
        if ip_obj in net:
            return "internal"
    return "external"

def get_event_timestamp(event):
    return event["event_timestamp"]

class SuspiciousNetworkTransitionRule(BaseRule):
    name = "Suspicious Network Transition"
    severity = "medium"

    def __init__(self, *, window: timedelta = timedelta(minutes=2)):
        self.window = window

    def run(self, events) -> List[Alert]:
        filtered = [e for e in events if e.get("event_type") == "SUCCESSFUL_LOGIN"]
        filtered = [e for e in filtered if e.get("event_timestamp") is not None]
        filtered.sort(key=get_event_timestamp)
        groups = {}
        for e in filtered:
            ip_addr = e.get("ip_address")
            if zone_classifier(ip_addr) == "unknown":
                continue
            username = e.get("username")
            if not username:
                continue
            groups.setdefault(str(username), []).append(e)
            
        alerts = []
        for username, user_events in groups.items():
            user_events.sort(key=get_event_timestamp)
            for i in range(len(user_events) - 1):
                prev_event = user_events[i]
                curr_event = user_events[i + 1]
                prev_ts = prev_event.get("event_timestamp")
                curr_ts = curr_event.get("event_timestamp")
                if prev_ts is None or curr_ts is None:
                    continue
                prev_ip = prev_event.get("ip_address")
                curr_ip = curr_event.get("ip_address")
                prev_zone = zone_classifier(prev_ip)
                curr_zone = zone_classifier(curr_ip)
                if prev_zone == "unknown" or curr_zone == "unknown":
                    continue
                delta = curr_ts - prev_ts
                if prev_zone != curr_zone and delta <= self.window:
                    alerts.append(
                        Alert(
                            alert_type="SUSPICIOUS_NETWORK_TRANSITION",
                            rule_name=self.name,
                            severity=self.severity,
                            start=prev_ts,
                            end=curr_ts,
                            key=f"username:{username}",
                            count=1,
                            evidence={
                                "prev_ip": prev_ip,
                                "prev_zone": prev_zone,
                                "curr_ip": curr_ip,
                                "curr_zone": curr_zone,
                                "window_seconds": int(self.window.total_seconds()),
                                "delta_seconds": int(delta.total_seconds()),
                                "prev_event_id": prev_event.get("event_id"),
                                "curr_event_id": curr_event.get("event_id"),
                            },
                            alert_id=new_alert_id(),
                            ))

        return alerts