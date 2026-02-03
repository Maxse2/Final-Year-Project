import re
from Normalisation.base_normaliser import BaseNormaliser
from Normalisation.schema import make_event, validate_event
from datetime import datetime, timezone

class AuthLogNormaliser(BaseNormaliser):

    source_name = "linux_auth"
    
    # Regular Expression algorithms for parsing IPv4 addresses, auth.log files
    # and Service/PID from log entries
    ipv4_regex = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

    auth_log_regex = re.compile(
        r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T'
        r'\d{2}:\d{2}:\d{2}(?:\.\d+)?'
        r'(?:Z|[+-]\d{2}:\d{2}))\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<service_raw>[^:]+):\s+'
        r'(?P<message>.*)$'
    )
    
    service_pid_regex = re.compile(r'^(?P<service>.*?)(?:\[(?P<pid>\d+)\])?\]?$')

    # Takes raw service entry and splits into Service and PID entries.
    def parse_service_and_pid(self, service_raw: str):
        cleaned = service_raw.strip()
        if cleaned.startswith("(") and cleaned.endswith(")"):
            cleaned = cleaned[1:-1]
        m = self.service_pid_regex.match(cleaned)
        if not m:
            return cleaned, None
        service = m.group("service")
        pid = m.group("pid")
         # Returns both Service and PID,  unless PID doesn't exist.
        return service, int(pid) if pid else None

    # Parses raw timestamp entries into python-readable Datetime variables.
    def parse_auth_timestamp(self, ts):
        dt = datetime.fromisoformat(ts)
        return dt.astimezone(timezone.utc)

    # Gives an event classification based on event message. 
    def event_classification(self,message,service):
        msg = message.lower()
    
        # Classifies password-related events
        if service == "sshd":
            if "failed password" in msg:
                return "FAILED_LOGIN"
            if "accepted password" in msg:
                return "SUCCESSFUL_LOGIN"
        return "OTHER"

    # Extracts IPv4 addresses from message using pre-defined regex.
    def extract_ipv4(self,message):
        match = self.ipv4_regex.search(message)
        return match.group(0) if match else None

    # Main normalisation function
    def normalise(self,lines):
        normalised = []
        
        for index,line in enumerate(lines):
            line = line.replace("\x00", "").strip()
            if not line:
                continue
            
            matched = self.auth_log_regex.match(line)
            if not matched:
                continue
            # Variables prepared here for normalisation.
            data = matched.groupdict()
            ip = self.extract_ipv4(data['message'])
            timestamp_dt= self.parse_auth_timestamp(data["timestamp"])
            service, pid = self.parse_service_and_pid(data["service_raw"])
            event_type = self.event_classification(data["message"],service)
            # Uses make_event to generate a normalised log entry based on
            # the default schema
            event = make_event(
                event_id=f"AUTH_{service.upper()}_{event_type.upper()}_{index}",
                event_timestamp=timestamp_dt,
                hostname=data["hostname"],
                ip_address=ip,
                event_type=event_type,
                message=data["message"],
                source=self.source_name,
                raw=line,
                )
            event["service"] = service
            event["pid"] =  pid
            validate_event(event)
            normalised.append(event)
        return normalised
