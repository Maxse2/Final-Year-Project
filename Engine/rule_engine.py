from __future__ import annotations
from typing import List
from Engine.baserule import BaseRule
from Engine.alerts import Alert, new_alert_id

class RuleEngine:
    def __init__(self,rules):
        self.rules=rules
    
    def run(self,events):
        all_alerts = []
        
        for rule in self.rules:
            try:
                all_alerts.extend(rule.run(events))
            except Exception as e:
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