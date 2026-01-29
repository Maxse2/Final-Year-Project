from auth_log_normaliser import AuthLogNormaliser
import os
import pandas as pd

normalisers = {
    "linux_auth": AuthLogNormaliser()
    #More to be added in future
    }

def source_detection(file):
    # FILE NAME WILL LATER COME FROM FLASK. NO OS MODULE NEEDED IN FINAL PRODUCT.
    name = file.lower()
    
    if "auth" in name:
        return "linux_auth"
    
    return "Unknown"

def get_normaliser(file):
    source_type = source_detection(file)
    
    if source_type not in normalisers:
        raise ValueError(
            f"Unsupported source for file '{file}', supported: {list(normalisers)}"
            )
    return normalisers[source_type]




path = r"C:\Users\maxst\OneDrive\Desktop\Project Development\misc files\auth.log"
filename = os.path.basename(path)
# Dictionary of functional normalisers 

with open(path, "r", encoding="utf-8") as f:
    lines = f.readlines()

normaliser = get_normaliser(filename)
events = normaliser.normalise(lines)

print("Detected normaliser:", type(normaliser).__name__)
print("Events parsed:", len(events))
print("First event:", events[0] if events else "No events")
df = pd.DataFrame(events)
df.to_csv("Normalised_Data.csv", index=False, escapechar="\\")