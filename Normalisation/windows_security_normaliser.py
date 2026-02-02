# UNFINISHED
# TO DO - Write normaliser function, properly integreate to factory/main


import re
import pandas as pd
#add folder name back after testing
from Normalisation.base_normaliser import BaseNormaliser
import datetime


class WindowsSecurityNormaliser(BaseNormaliser):
    
    source_name = "windows_security"
    
    
    ip_regex = re.compile(r"Source Network Address:\s*(?P<ip>(?:\d{1,3}\.){3}\d{1,3})")
    
    user_patterns = [
    re.compile(r"Account Name:\s*(?P<user>[^\r\n]+)"),
    re.compile(r"Target User Name:\s*(?P<user>[^\r\n]+)"),
    re.compile(r"Security ID:\s*(?P<user>[^\r\n]+)"),
    ]

    # Uses IP Regex to determine the source IP of an event
    def extract_ip(self,message):
        if not message:
            return None
        match = self.ip_regex.search(message)
        if not match:
            return None
        return match.group("ip")
    # Uses "user_patterns" regex list to search for a username/hostname
    def extract_username(self,message):
        if not message:
            return None
        for pattern in self.user_patterns:
            m = pattern.search(message)
            if m:
                user = m.group("user").strip()
                if user in {"-", ""}:
                    return None
                return user
        return None
            
    # Classifies events into universal tags for normalisation
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

    # Main normalisation function
    def normalise(self,csv):
        normalised = []
        data = pd.read_csv(
        csv, 
        skiprows=1, 
        names=['keywords', 'timestamp', 'source', 'event_id', 'task_category', 'message'],
        quotechar='"', 
        on_bad_lines='skip', 
        encoding='utf-8')
        
        data['timestamp'] = pd.to_datetime(data['timestamp'], dayfirst=True)
        datalist = data.to_dict("records")
        for row in datalist:
            event_type = self.event_classification(row["event_id"])
            message = row['message']
            ip = self.extract_ip(message)
            normalised.append({
                "event_type":row['event_id'],
                "event_id":f"WIN_{event_type}",
                "event_timestamp":row['timestamp'].isoformat(),
                "source":self.source_name,
                "message":message,
                "ip_address":ip,
                "username":self.extract_username(message)
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
data['timestamp'] = pd.to_datetime(data['timestamp'], dayfirst=True)
records = data.to_dict("records")
normaliser = WindowsSecurityNormaliser()
rows = records[:80]

