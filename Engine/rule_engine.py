from __future__ import annotations
from typing import List
from Engine.baserule import BaseRule
from Engine.alerts import Alert, new_alert_id

class RuleEngine:
    def __init__(self,rules):
        self.rules=rules
    """
    Main Engine Function - takes current alert rules and combines into one, running each
    one against given data. Created alerts are stored in a list and returned at the end.
    If an exception occurs, it is stored as a seperate form of alert.
    """
    def run(self,events):
        all_alerts = []
        
        for rule in self.rules:
            try:
                all_alerts.extend(rule.run(events)) # Runs all correlation rules on given events.
            except Exception as e:
                # Error alert is created in case of exception.
                all_alerts.append(
                    Alert(
                        alert_type="RULE_ERROR",
                        rule_name=rule.name,
                        severity="error",
                        start=None,
                        end=None,
                        key=rule.name,
                        count=0,
                        evidence={"error": str(e)},
                        alert_id=new_alert_id(),
                        ))
        return all_alerts