import re
from Normalisation.base_normaliser import BaseNormaliser

class WebAccessNormaliser(BaseNormaliser):

    source_name = "web_access"
    # Regular Expression algorithm for parsing auth.log files

    web_access_regex = re.compile(
        r'^(?P<ip>\S+)\s+\S+\s+\S+\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+\S+"\s+'
        r'(?P<status>\d{3})\s+(?P<size>\S+)'
        r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?$'
    )


    # Labelling and classification for parsed events

    def event_classification(self,status):
        # Classifies events based on status code
        if status.startswith("4"):
            return "CLIENT_ERROR"
        if status.startswith("5"):
            return "SERVER_ERROR"
        
    # Main normalisation function
    def normalise(self,lines):
        normalised = []
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            matched = self.web_access_regex.match(line)
            if not matched:
                continue
            
            data = matched.groupdict()
            event_type = self.event_classification(data["status"])
            
            normalised.append({
                "event_id": f"WEB_{event_type}",
                "event_timestamp": data['timestamp'],
                "hostname": None, # Access logs typically do not state a hostname
                "ip_address": data['ip'],
                "event_type": event_type,
                "message": line,
                "source": self.source_name,
                "http_method": data["method"],
                "path": data["path"],
                "status":data["status"],
                "size" :data["size"],
                "referrer": data.get("referrer"),
                "user_agent": data.get("user_agent"),
                })
        return normalised

