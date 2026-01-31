from Normalisation.auth_log_normaliser import AuthLogNormaliser
from Normalisation.web_access_normaliser import WebAccessNormaliser
import os
import pandas as pd

normalisers = {
    "linux_auth": AuthLogNormaliser(),
    "web_access": WebAccessNormaliser(),
    #More to be added in future
    }

def source_detection(file):
    # FILE NAME WILL LATER COME FROM FLASK. NO OS MODULE NEEDED IN FINAL PRODUCT.
    name = file.lower()
    
    if "auth" in name:
        return "linux_auth"
    if "access" in name:
        return "web_access"
    
    return "unknown"

def get_normaliser(file):
    source_type = source_detection(file)
    
    if source_type not in normalisers:
        raise ValueError(
            f"Unsupported source for file '{file}', supported: {list(normalisers)}"
            )
    return normalisers[source_type]




path = r"C:\Users\maxst\OneDrive\Desktop\Project Development\misc files\access.log"
filename = os.path.basename(path)

''' #Test  Script
with open(path, "r", encoding="utf-8", errors="replace") as f:
    lines = f.readlines()

normaliser = get_normaliser(filename)
events = normaliser.normalise(lines)
alerts = detect_bruteforce(events, threshold=5, window_minutes=5)


print("Detected normaliser:", type(normaliser).__name__)
print("Events parsed:", len(events))
print("First event:", events[0] if events else "No events")
df = pd.DataFrame(events)
df.to_csv("Normalised_Data.csv", index=False, escapechar="\\")'''