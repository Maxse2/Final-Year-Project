from Normalisation.auth_log_normaliser import AuthLogNormaliser
from Normalisation.web_access_normaliser import WebAccessNormaliser
from Normalisation.windows_security_normaliser import WindowsSecurityNormaliser
import os
import pandas as pd

normalisers = {
    "linux_auth": AuthLogNormaliser(),
    "web_access": WebAccessNormaliser(),
    "windows_security": WindowsSecurityNormaliser(),
    }

def source_detection(file):
    # FILE NAME WILL LATER COME FROM FLASK. NO OS MODULE NEEDED IN FINAL PRODUCT.
    name = file.lower()
    
    if "auth" in name:
        return "linux_auth"
    if "access" in name:
        return "web_access"
    if "windows" or "security" or "event" in name:
        return "windows_security"
    
    return "unknown"

def get_normaliser(file):
    source_type = source_detection(file)
    
    if source_type not in normalisers:
        raise ValueError(
            f"Unsupported source for file '{file}', supported: {list(normalisers)}"
            )
    return normalisers[source_type]

