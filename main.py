import json
import datetime
from datetime import timedelta
from typing import Any, Dict, Iterable
import os
import pandas as pd
from dataclasses import is_dataclass, asdict
from Normalisation.auth_log_normaliser import AuthLogNormaliser
from Normalisation.web_access_normaliser import WebAccessNormaliser
from Normalisation.normaliser_factory import get_normaliser
from Engine.rule_engine import RuleEngine
from Correlation.bruteforce import BruteForceRule
from Correlation.password_spraying import PasswordSprayRule
from Correlation.suspicious_network_transition import SuspiciousNetworkTransitionRule
from Storage.mongo import create_ingestion, insert_events, insert_alerts, ensure_indexes

ensure_indexes()

def _json_safe(obj):
    if isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    if isinstance(obj, datetime.timedelta):
        return obj.total_seconds()
    if isinstance(obj, dict):
        return {k: _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_json_safe(v) for v in obj]
    if hasattr(obj, "__dict__"):
        return _json_safe(obj.__dict__)
    return obj


def write_jsonl(records, path):
    with open(path, "w", encoding="utf-8") as f:
        for rec in records:
            if is_dataclass(rec):
                rec=asdict(rec)
            f.write(json.dumps(_json_safe(rec),ensure_ascii=False) + "\n")

path = r"C:\Users\maxst\OneDrive\Desktop\Project Development\misc files\bruteforcetesting\access.log"
filename = os.path.basename(path)

with open(path, "r", encoding="utf-8", errors="replace") as f:
    lines = f.readlines()

normaliser = get_normaliser(path)

if normaliser.source_name in ("linux_auth", "web_access"):
    events = normaliser.normalise(lines)

elif normaliser.source_name == "windows_security":
    events = normaliser.normalise(path)

print("Detected normaliser:", type(normaliser).__name__)
print("Events parsed:", len(events))
print("First Event:",events[0])
print("Last Event:",events[-1])
total_lines = sum(1 for l in lines if l.strip())
print("Non-empty lines:", total_lines)
if total_lines-len(events) != 0:
    print("Skipped:", total_lines - len(events),"likely due to malformed entries.")
    

datapath=r"C:\Users\maxst\OneDrive\Desktop\Project Development\exported data"
alerts_jsonl_path= os.path.join(datapath,"alerts.jsonl")
events_jsonl_path= os.path.join(datapath,"events.jsonl")
engine= RuleEngine([
    BruteForceRule(threshold=5, window=timedelta(minutes=2), group_by="ip"),
    PasswordSprayRule(window=timedelta(minutes=10), min_unique_users=3,min_total_attempts=6),
    SuspiciousNetworkTransitionRule(window=timedelta(minutes=2)),
    ])
alerts = engine.run(events)
ingestion_id=create_ingestion(
    filename=filename,
    source=normaliser.source_name,
    raw_line_count=total_lines,
    event_count=len(events),
    )
insert_events(ingestion_id,events)
insert_alerts(ingestion_id,alerts)
print("Saved ingestion:",ingestion_id)
write_jsonl(events,events_jsonl_path)
write_jsonl(alerts,alerts_jsonl_path)