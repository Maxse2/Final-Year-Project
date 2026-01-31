import re
from Normalisation.base_normaliser import BaseNormaliser

class AuthLogNormaliser(BaseNormaliser):

    source_name = "linux_auth"
    # Regular Expression algorithm for parsing auth.log files
    
    ipv4_regex = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

    auth_log_regex = re.compile(
        r'^(?P<timestamp>\S+)\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<service>[A-Za-z0-9\-]+)\[(?P<pid>\d+)\]:\s+'
        r'(?P<message>.*)$'
    )

    # Labelling and classification for parsed events

    def event_classification(self,message,service):
        msg = message.lower()
    
        # Classifies password-related events
        if service == "sshd":
            if "failed password" in msg:
                return "FAILED_LOGIN"
            if "accepted password" in msg:
                return "SUCCESSFUL_LOGIN"
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
                "service": data['service'],
                "pid" : data["pid"]
                })
        return normalised
