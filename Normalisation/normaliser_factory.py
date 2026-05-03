from Normalisation.auth_log_normaliser import AuthLogNormaliser
from Normalisation.web_access_normaliser import WebAccessNormaliser
from Normalisation.windows_security_normaliser import WindowsSecurityNormaliser
import os
import pandas as pd
# Normalisers that are currently functional within the system.
# If more are added, they must be entered onto this dictionary.
normalisers = {
    "linux_auth": AuthLogNormaliser(),
    "web_access": WebAccessNormaliser(),
    "windows_security": WindowsSecurityNormaliser(),
    }
# Detects source based on filenames.
def source_detection(file):
    name = file.lower()
    
    if "auth" in name:
        return "linux_auth"
    if "access" in name:
        return "web_access"
    if "windows" or "security" or "event" in name:
        return "windows_security"
    else:
        raise ValueError("Unsupported Log Type")
    
    return "unknown"
# Defines a normaliser module to use on a given file.
def get_normaliser(file):
    source_type = source_detection(file)
    
    if source_type not in normalisers:
        raise ValueError(
            f"Unsupported source for file '{file}', supported: {list(normalisers)}"
            )
    return normalisers[source_type]

