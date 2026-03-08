import re
import pandas as pd
from Normalisation.base_normaliser import BaseNormaliser
from Normalisation.schema import make_event, validate_event
import datetime
import json


class WindowsSecurityNormaliser(BaseNormaliser):
    
    source_name = "windows_security"
    
    # Regex algorithm to extract an IP from otherwise lengthy
    # event log messages.
    ip_regex = re.compile(r"Source Network Address:\s*(?P<ip>(?:\d{1,3}\.){3}\d{1,3})")
    
    # List of regex algorithms for extraction of usernames from messages.
    user_patterns = [
        re.compile(r"Account For Which Logon Failed:\s*.*?Account Name:\s*(?P<user>[^\s]+)",
        re.IGNORECASE),
        re.compile(r"Target User Name:\s*(?P<user>.*?)(?=\s+(?:Account Domain|Logon ID|Logon Type|Failure Information|Caller Computer Name|Source Network Address|Process Name):|$)"),
        re.compile(r"Account Name:\s*(?P<user>.*?)(?=\s+(?:Account Domain|Logon ID|Logon Type|Failure Information|Caller Computer Name|Source Network Address|Process Name):|$)"),
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
                if "\\" in user:
                    user = user.split("\\")[-1]
                    
                return user.lower()
        return None
            
    # Classifies events into universal tags for normalisation
    def event_classification(self,eventid):
        classifications = {
            # More IDs to be added!
            4625: "FAILED_LOGIN",
            4624: "SUCCESSFUL_LOGIN",
            4740: "ACCOUNT_LOCKED",
            }
        if eventid in classifications:
            return classifications[eventid]
        else:
            return "OTHER"

    """
    Main Normalisation Function. Different from others as a .csv file is able to be
    exported from event viewer - uses Pandas to read exported logs, and transforms data
    into columns that adhere to this application's normalised structure. Normalised
    data is exported as a list of dictionaries.
    """
    def normalise(self,csv):
        normalised = []
        data = pd.read_csv(
        csv,
        header=0,
        names=["keywords","timestamp","provider","event_id","task_category","message"],
        quotechar='"', 
        on_bad_lines='skip', 
        encoding='utf-8',
        index_col=False)
        data.columns = data.columns.str.strip()
        data['timestamp'] = pd.to_datetime(data['timestamp'], dayfirst=True)
        data['message'] = data['message'].replace(r'[\n\t\r]+', ' ', regex=True)
        datalist = data.to_dict("records")
        for index, row in enumerate(datalist):
            try:
                event_code = int(row["event_id"]) # <--Extracts event ID from data
            except (TypeError, ValueError):
                continue
            event_type = self.event_classification(event_code)# <-- Event ID is classified here
            timestamp_dt = row["timestamp"].to_pydatetime()
            if timestamp_dt.tzinfo is None:
                timestamp_dt = timestamp_dt.replace(tzinfo=datetime.timezone.utc)
            else:
                timestamp_dt = timestamp_dt.astimezone(datetime.timezone.utc)
            message = row['message']
            ip = self.extract_ip(message)
            # Events are created in the normalised structure here.
            event = make_event(
                event_id=f"WIN_{event_code}_{timestamp_dt.timestamp()}_{index}",
                event_timestamp=timestamp_dt,
                hostname = "windows_host",
                ip_address=ip,
                event_type=event_type,
                message=message,
                source=self.source_name,
                raw=json.dumps(row, default=str),
                )
            event["event_code"] = event_code
            event["username"] = self.extract_username(message)
            event["task_category"] = row.get("task_category")
            event["provider"] = row.get("provider")
            validate_event(event)
            normalised.append(event)
        return normalised

