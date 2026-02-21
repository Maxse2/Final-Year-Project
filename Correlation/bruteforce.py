from __future__ import annotations
from datetime import timedelta
from typing import Any, Dict, List
from Engine.alerts import Alert, new_alert_id
from Engine.baserule import BaseRule

def get_event_timestamp(event):
    return event["event_timestamp"]

class BruteForceRule(BaseRule):
    name = "Brute Force"
    severity = "high"

    def __init__(self, *, threshold: int = 5, window: timedelta = timedelta(minutes=2), group_by: str = "ip"):
        self.threshold = threshold
        self.window = window
        self.group_by = group_by

    def run(self, events):
        failed = [e for e in events if e.get("event_type") == "FAILED_LOGIN"]
        failed = [e for e in failed if e.get("event_timestamp") is not None]
        failed.sort(key=get_event_timestamp)
        groups: Dict[str, List[dict]] = {}
        for e in failed:
            if self.group_by == "ip":
                key_value = e.get("ip_address")
            elif self.group_by == "username":
                key_value = e.get("username")
            else:
                raise ValueError("group_by must be 'ip' or 'username'")
            if not key_value:
                continue
            groups.setdefault(str(key_value), []).append(e)
        alerts = []
        for key, evs in groups.items():
            start_idx = 0
            for end_idx in range(len(evs)):
                while evs[end_idx]["event_timestamp"] - evs[start_idx]["event_timestamp"] > self.window:
                    start_idx += 1

                events_in_window = end_idx - start_idx + 1
                if events_in_window >= self.threshold:
                    alerts.append(
                        Alert(
                            alert_type="POTENTIAL_BRUTE_FORCE",
                            rule_name=self.name,
                            severity=self.severity,
                            start=evs[start_idx]["event_timestamp"],
                            end=evs[end_idx]["event_timestamp"],
                            key=f"{self.group_by}:{key}",
                            count=events_in_window,
                            evidence={
                                "threshold": self.threshold,
                                "window_seconds": int(self.window.total_seconds()),
                                "group_by": self.group_by,
                            },
                            alert_id=new_alert_id(),
                        )
                    )
                    start_idx = end_idx + 1

        return alerts