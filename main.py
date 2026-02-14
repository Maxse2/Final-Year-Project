import json
import datetime
from typing import Any, Dict, Iterable
import os
import pandas as pd
from dataclasses import is_dataclass, asdict
from Normalisation.auth_log_normaliser import AuthLogNormaliser
from Normalisation.web_access_normaliser import WebAccessNormaliser
from Normalisation.normaliser_factory import get_normaliser
from Correlation.bruteforce import detect_bruteforce
from Correlation.suspicious_network_transition import detect_network_change


import datetime

def _json_safe(obj):
    if isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    if isinstance(obj, datetime.timedelta):
        return obj.total_seconds()   # store duration as seconds (recommended)
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
print("Skipped:", total_lines - len(events),"likely due to malformed entries.")
datapath=r"C:\Users\maxst\OneDrive\Desktop\Project Development\exported data"
jsonl_events_path = os.path.join(datapath, "Events.jsonl")
jsonl_bf_path= os.path.join(datapath, "BruteforceAlerts.jsonl")
jsonl_nt_path= os.path.join(datapath, "NetTransitionAlerts.jsonl")
bruteforcealerts = detect_bruteforce(events,group_by="ip",threshold=3)
net_transition_alerts = detect_network_change(events,group_by="username")
write_jsonl(events, jsonl_events_path)
write_jsonl(bruteforcealerts,jsonl_bf_path)
write_jsonl(net_transition_alerts,jsonl_nt_path)
df = pd.DataFrame(events)
df.to_csv("events.csv")