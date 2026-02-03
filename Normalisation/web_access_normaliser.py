import re
from Normalisation.base_normaliser import BaseNormaliser
from Normalisation.schema import make_event, validate_event
from datetime import datetime, timezone



class WebAccessNormaliser(BaseNormaliser):

    source_name = "web_access"
    
    # Regular Expression algorithm for parsing access logs 
    web_access_regex = re.compile(
        r'^(?P<client>\S+)\s+\S+\s+\S+\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<request>[^"]*)"\s+'
        r'(?P<status>\d{3})\s+(?P<size>\S+)'
        r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?\s*$'
    )

    
    # Takes raw request entry and splits into method, path and protocol entries.
    def parse_request(self,request):
        parts = request.split()
        method = parts[0] if len(parts) >0 else None
        path = parts[1] if len(parts) >1 else None
        protocol = parts[2] if len(parts) >2 else None
        return  method,path,protocol
    
    # Parses raw timestamp entries into python-readable Datetime variables.
    def parse_timestamp(self,ts):
        dt = datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z")
        return dt.astimezone(timezone.utc)
    
    # Classifies events based on status code
    def event_classification(self,status):
        if status.startswith("4"):
            return "CLIENT_ERROR"
        if status.startswith("5"):
            return "SERVER_ERROR"
        if status.startswith("3"):
            return "REDIRECT"
        return "OTHER"
    
    
    # Main normalisation function
    def normalise(self,lines):
        normalised = []
        for index,line in enumerate(lines):
            line = line.strip()
            if not line:
                continue
            matched = self.web_access_regex.match(line)
            if not matched:
                continue
            # Variables prepared here for normalisation.
            data = matched.groupdict()
            event_type = self.event_classification(data["status"])
            dtimestamp = self.parse_timestamp(data['timestamp'])
            hostname = "webserver"
            method,path,protocol = self.parse_request(data["request"])
            # Uses make_event to generate a normalised log entry based on
            # the default schema
            event = make_event(
                event_id=f"WEB_{event_type}_{index}",
                event_timestamp=dtimestamp,
                hostname=hostname,
                ip_address=data["client"],
                event_type=event_type,
                message=line,
                source=self.source_name,
                raw=line,
                )
            event["http_method"] = method
            event["path"]= path
            event["protocol"] = protocol
            event["status"]=int(data["status"])
            event["size"]= None if data["size"] == "-" else int(data["size"])
            event["referrer"]=data.get("referrer")
            event["user_agent"]=data.get("user_agent")
            validate_event(event)
            normalised.append(event)
        return normalised

