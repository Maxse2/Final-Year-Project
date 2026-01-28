import re
from datetime import datetime
from base_normaliser import BaseNormaliser

# Regular Expression algorithm for parsing auth.log files

auth_log_regex = re.compile(
    r'^(?P<timestamp>\S+)\s+'
    r'(?P<hostname>\S+)\s+'
    r'(?P<service>[A-Za-z0-9\-]+)\[(?P<pid>\d+)\]:\s+'
    r'(?P<message>.*)$'
)

# Labelling and classification for parsed events

def event_classification(message,service):
    msg = message.lower()
    
    # Classifies password-related events
    if service == "sshd":
        if "failed password" in msg:
            return "FAILED_LOGIN"
        if "accepted password" in msg:
            return "SUCCESSFUL_LOGIN"
    return "OTHER"

# Main normalisation function
def normalise_lines(lines):
    normalised = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        matched = auth_log_regex.match(line)
        if not matched:
            continue
    data = matched.groupdict()
    event_type = event_classification(data["message"], data["service"])
    
    normalised.append({
        "event_id": f"{data['service'].upper()}_{event_type.upper()}",
        "event_timestamp": data['timestamp'],
        "hostname": data['hostname'],
        "ip_address": None, # Will be revisited later in development
        "event_type:": event_type,
        "message": data["message"],
        "Source": "linux_auth",
        "service": data['service'],
        "pid" : data["pid"]
        })
    return normalised