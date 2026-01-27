import re
from datetime import datetime
from base_normaliser import BaseNormaliser

auth_log_regex = re.compile(
    r'^(?P<timestamp>\S+)\s+'
    r'(?P<hostname>\S+)\s+'
    r'(?P<service>[A-Za-z0-9\-]+)\[(?P<pid>\d+)\]:\s+'
    r'(?P<message>.*)$'
)

test_line = (
    "2026-01-27T16:59:30.983438+00:00 Ubuntu "
    "systemd-logind[1040]: New seat seat0."
)

match = auth_log_regex.match(test_line)

if match:
    print("✅ Match found!\n")
    for name, value in match.groupdict().items():
        print(f"{name}: {value}")
else:
    print("❌ No match")