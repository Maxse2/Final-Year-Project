from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional, Dict

REQUIRED_KEYS = {
    "event_id",
    "event_timestamp",
    "hostname",
    "event_type",
    "source",
}

@dataclass(frozen=True)
class NormalisedEvent:
    event_id: str
    event_timestamp: datetime
    hostname :str
    event_type: str
    source: str
    ip_address: Optional[str] = None
    message: Optional[str] = None
    raw: Any = None
    
    def to_dict(self):
        return {
            "event_id":self.event_id,
            "event_timestamp":self.event_timestamp,
            "hostname":self.hostname,
            "ip_address":self.ip_address,
            "event_type":self.event_type,
            "message":self.message,
            "source":self.source,
            "raw":self.raw,
            }
    
def make_event(
    *,
    event_id:str,
    event_timestamp: datetime,
    hostname: str,
    event_type:str,
    source: str,
    ip_address: Optional[str] = None,
    message: Optional[str] = None,
    raw: Any = None,):
    
    ev = NormalisedEvent(
        event_id=event_id,
        event_timestamp=event_timestamp,
        hostname=hostname,
        event_type=event_type,
        source=source,
        ip_address=ip_address,
        message=message,
        raw=raw,
    )
    return ev.to_dict()

def validate_event(ev:Dict[str,Any]):
    missing = [k for k in REQUIRED_KEYS if k not in ev or ev[k] in (None,"")]
    if missing:
        raise ValueError(f"Normalised event missing required fields: {missing}")
    ts = ev["event_timestamp"]
    if not isinstance(ts,datetime):
        raise TypeError(f"event_timestamp must be datetime, got {type(ts)}")
    