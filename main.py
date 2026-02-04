import os
import pandas as pd
from Normalisation.auth_log_normaliser import AuthLogNormaliser
from Normalisation.web_access_normaliser import WebAccessNormaliser
from Normalisation.normaliser_factory import get_normaliser
from Correlation.auth_rules import detect_bruteforce

path = r"C:\Users\maxst\OneDrive\Desktop\Project Development\misc files\security_events.csv"
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
print("First raw line:", repr(lines[0]))
print("First Event:",events[0])
print("Last Event:",events[-1])
total_lines = sum(1 for l in lines if l.strip())
print("Non-empty lines:", total_lines)
print("Skipped:", total_lines - len(events),"likely due to malformed entries.")
normalisedevents = pd.DataFrame(events)
normalisedevents.to_csv("Events.csv",escapechar="\\")