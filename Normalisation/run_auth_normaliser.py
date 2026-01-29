import pandas as pd
import csv
from auth_log_normaliser import AuthLogNormaliser

path = r"C:\Users\maxst\OneDrive\Desktop\Project Development\misc files\auth.log"

with open(path, "r", encoding="utf-8") as f:
    lines = f.readlines()

normaliser = AuthLogNormaliser()
events = normaliser.normalise(lines)

df = pd.DataFrame(events)
df.to_csv("normalised_dataset.csv", index=False, quoting=csv.QUOTE_ALL, escapechar="\\")
print("Wrote normalised_dataset.csv with", len(df), "rows")
