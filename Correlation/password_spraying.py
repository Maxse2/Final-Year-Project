from __future__ import annotations
from datetime import timedelta
from typing import List
from Engine.alerts import Alert, new_alert_id
from Engine.baserule import BaseRule

class PasswordSprayRule(BaseRule):
    name = "Password Spray"
    severity = "high"

    def __init__(self, *, window: timedelta = timedelta(minutes=10), min_unique_users: int = 2, min_total_attempts: int = 2):
        self.window = window
        self.min_unique_users = min_unique_users
        self.min_total_attempts = min_total_attempts

    def run(self, events) -> List[Alert]:
        events_by_ip = {}
        alerts = []
        failed = [
            e for e in events
            if e.get("event_type") == "FAILED_LOGIN"
            and e.get("ip_address") is not None
            and e.get("username") is not None
            and e.get("event_timestamp") is not None
        ]

        for e in failed:
            ip = str(e.get("ip_address"))
            events_by_ip.setdefault(ip, []).append(e)
        for ip, ip_events in events_by_ip.items():
            ip_events.sort(key=lambda e: e["event_timestamp"])
            for i in range(len(ip_events)):
                window_start = ip_events[i]["event_timestamp"]
                window_end = window_start + self.window
                window_events = []
                j = i
                while j < len(ip_events) and ip_events[j]["event_timestamp"] <= window_end:
                    window_events.append(ip_events[j])
                    j += 1
                usernames = list({e["username"] for e in window_events})
                evidence_event_ids = [e.get("event_id") for e in window_events if e.get("event_id") is not None]
                unique_user_count = len(usernames)
                total_attempts = len(window_events)

                if unique_user_count >= self.min_unique_users and total_attempts >= self.min_total_attempts:
                    alerts.append(
                        Alert(
                            alert_type="PASSWORD_SPRAY",
                            rule_name=self.name,
                            severity=self.severity,
                            start=window_start,
                            end=window_end,
                            key=f"ip:{ip}",
                            count=total_attempts,
                            evidence={
                                "unique_user_count": unique_user_count,
                                "usernames": usernames,
                                "event_ids": evidence_event_ids,
                                "window_seconds": int(self.window.total_seconds()),
                                "min_unique_users": self.min_unique_users,
                                "min_total_attempts": self.min_total_attempts,
                            },
                            alert_id=new_alert_id(),
                            ))

        return alerts