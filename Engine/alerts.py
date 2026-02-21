from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict
import uuid

@dataclass
class Alert:
    alert_type: str
    rule_name: str
    severity: str
    start: Any
    end: Any
    key: str
    count: int
    evidence: Dict[str, Any]
    alert_id: str

def new_alert_id() -> str:
    return str(uuid.uuid4())