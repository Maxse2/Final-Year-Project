# UNFINISHED
# TO DO - Write normaliser function, properly integreate to factory/main


import re
import pandas as pd
#add folder name back after testing
from base_normaliser import BaseNormaliser


class WindowsSecurityNormaliser(BaseNormaliser):

    source_name = "windows_security"

    # Labelling and classification for parsed events

    def event_classification(self,eventid):
        classifications = {
            4625: "FAILED_LOGIN",
            4624: "SUCCESSFUL_LOGIN",
            4740: "ACCOUNT_LOCKED",
            }
        if eventid in classifications:
            return classifications[eventid]
        else:
            return "OTHER"
        
        
        
    def extract_ipv4(self,message):
        match = self.ipv4_regex.search(message)
        return match.group(0) if match else None

    # Main normalisation function
    def normalise(self,lines):
        normalised = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            matched = self.auth_log_regex.match(line)
            if not matched:
                continue
            data = matched.groupdict()
            event_type = self.event_classification(data["message"], data["service"])
            ip = self.extract_ipv4(data['message'])
    
            normalised.append({
                "event_id": f"{data['service'].upper()}_{event_type.upper()}",
                "event_timestamp": data['timestamp'],
                "hostname": data['hostname'],
                "ip_address": ip,
                "event_type": event_type,
                "message": data["message"],
                "source": self.source_name,
                })
        return normalised


# Temporary path to test file
path = r"C:\Users\maxst\OneDrive\Desktop\Project Development\misc files\security_events.csv"

with open(path, "r", encoding="utf-8", errors="replace") as f:
    lines = f.readlines()
data = pd.read_csv(
    path, 
    skiprows=1, 
    names=['keywords', 'timestamp', 'source', 'event_id', 'task_category', 'message'],
    quotechar='"', 
    on_bad_lines='skip', 
    encoding='utf-8'
)
data['message'] = data['message'].replace(r'[\n\t\r]+', ' ', regex=True)
eventid = data['event_id']
records = data.to_dict("records")

normaliser = WindowsSecurityNormaliser()
rows = records[:80]
for row in rows:
    translation = normaliser.event_classification(row["event_id"])
    print(translation)
    