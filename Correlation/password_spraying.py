from dataclasses import dataclass, asdict
from datetime import timedelta
from typing import Any, Dict, List, Optional

@dataclass
class PasswordSprayAlert:
    alert_type: str
    source_ip: str
    start: Any
    end: Any
    unique_user_count: int
    total_attempts: int
    evidence: Dict[str, Any]
    
def DetectPassSpray(
    events,
    window: timedelta = timedelta(minutes=2)
    
    