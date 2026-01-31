import os
import pandas as pd
from Normalisation.auth_log_normaliser import AuthLogNormaliser
from Normalisation.web_access_normaliser import WebAccessNormaliser
from Normalisation.normaliser_factory import get_normaliser
from Correlation.auth_rules import detect_bruteforce

path = r"C:\Users\maxst\OneDrive\Desktop\Project Development\misc files\auth.log"
filename = os.path.basename(path)

with open(path, "r", encoding="utf-8", errors="replace") as f:
    lines = f.readlines()

normaliser = get_normaliser(filename)
events = normaliser.normalise(lines)
alerts = detect_bruteforce(events, windowminutes=5,threshold=5)
df = pd.DataFrame.from_dict(alerts)
df.to_csv("alert_data.csv",index=False)

print("Detected normaliser:", type(normaliser).__name__)
print("Events parsed:", len(events))
print("Alerts:", alerts)