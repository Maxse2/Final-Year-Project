import os
import pandas as pd
from Normalisation.auth_log_normaliser import AuthLogNormaliser
from Normalisation.web_access_normaliser import WebAccessNormaliser
from Normalisation.normaliser_factory import get_normaliser
from Correlation.bruteforce import detect_bruteforce
from Correlation.suspicious_network_transition import detect_network_change

path = r"C:\Users\maxst\OneDrive\Desktop\Project Development\misc files\nettransitiontesting\auth.log"
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
normalisationpath = os.path.join(datapath,"Events.csv")
alertpath = os.path.join(datapath,"BruteforceAlerts.csv")
alertpath2 = os.path.join(datapath,"NetTransitionAlerts.csv")
normalisedevents = pd.DataFrame(events)
normalisedevents.to_csv(normalisationpath,escapechar="\\")
bruteforcealerts = detect_bruteforce(events,group_by="ip",threshold=3)
normalised_bf_alerts = pd.DataFrame(bruteforcealerts)
normalised_bf_alerts.to_csv(alertpath,escapechar="\\")
net_transition_alerts = detect_network_change(events,group_by="username")
normalised_nt_alerts = pd.DataFrame(net_transition_alerts)
normalised_nt_alerts.to_csv(alertpath2,escapechar="\\")