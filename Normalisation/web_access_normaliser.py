import re
from Normalisation.base_normaliser import BaseNormaliser
from Normalisation.schema import make_event, validate_event
from datetime import datetime, timezone
#PROTECTED PATHS ARE TAILORED TO LOCAL TESTING AS OF NOW


class WebAccessNormaliser(BaseNormaliser):

    source_name = "web_access"
    
    # Regular Expression algorithm for parsing access logs 
    web_access_regex = re.compile(
        r'^(?P<client>\S+)\s+'
        r'(?P<ident>\S+)\s+'
        r'(?P<authuser>\S+)\s+'
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
    def classify_event(self, status, path=None, authuser=None):
        protected_paths = ("/secure", "/secure/")
        is_protected = path and (path in protected_paths or path.startswith("/secure/"))
    
        if is_protected:
            if status in (401, 403):
                return "FAILED_LOGIN"
            if status == 200 and authuser and authuser not in ("-", ""):
                return "SUCCESSFUL_LOGIN"


        status_str = str(status)
        if status_str.startswith("4"):
            return "CLIENT_ERROR"
        if status_str.startswith("5"):
            return "SERVER_ERROR"
        if status_str.startswith("3"):
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
            authuser=data.get("authuser")
            method,path,protocol = self.parse_request(data["request"])
            status_int = int(data["status"])
            event_type = self.classify_event(status_int, path, authuser)
            dtimestamp = self.parse_timestamp(data['timestamp'])
            if event_type in ("FAILED_LOGIN", "SUCCESSFUL_LOGIN"):
                user_part = f"user={authuser}" if authuser and authuser not in ("-", "") else "user=unknown"
                message = f"Web auth {event_type.lower()}: {user_part} ip={data['client']} path={path} status={status_int}"
            else:
                message = f"Web request: ip={data['client']} {method} {path} -> {status_int}"

            hostname = "webserver"
            # Uses make_event to generate a normalised log entry based on
            # the default schema
            event = make_event(
                event_id=f"WEB_{event_type}_{index}",
                event_timestamp=dtimestamp,
                hostname=hostname,
                ip_address=data["client"],
                event_type=event_type,
                message=message,
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
            if authuser and authuser not in ("-",""):
                event["username"]=authuser
                
            validate_event(event)
            normalised.append(event)
        return normalised

