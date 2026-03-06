import streamlit as st
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from Storage.mongo import ingestion_col, events_col, alerts_col
from dataclasses import is_dataclass, asdict
from Normalisation.auth_log_normaliser import AuthLogNormaliser
from Normalisation.web_access_normaliser import WebAccessNormaliser
from Normalisation.normaliser_factory import get_normaliser
from Engine.rule_engine import RuleEngine
from Correlation.bruteforce import BruteForceRule
from Correlation.password_spraying import PasswordSprayRule
from Correlation.suspicious_network_transition import SuspiciousNetworkTransitionRule
from Storage.mongo import create_ingestion, insert_events, insert_alerts, ensure_indexes


st.set_page_config(layout="wide")
alerts = []
events= []
placeholder= {"val1":1, "val2": 2}
# Sidebar
st.sidebar.title("LogView")

page = st.sidebar.radio(
    "Navigation",
    ["Dashboard", "Logs", "Alerts", "Correlation Rules"]
)

# Dashboard page
if page == "Dashboard":

    st.title("Dashboard")
    uploaded_file = st.file_uploader(
        "Upload a log file",
        type=["log", "txt", "csv"]
    )

    if uploaded_file is not None:
        st.write("File uploaded:", uploaded_file.name)
        
        lines = uploaded_file.read().decode("utf-8").splitlines()
        normaliser = get_normaliser(uploaded_file.name)
        if normaliser.source_name in ("linux_auth", "web_access"):
            events = normaliser.normalise(lines)

        elif normaliser.source_name == "windows_security":
            uploaded_file.seek(0)
            events = normaliser.normalise(uploaded_file)

        engine = RuleEngine([
            BruteForceRule(),
            PasswordSprayRule(),
            SuspiciousNetworkTransitionRule()
        ])

        alerts = engine.run(events)

    col1, col2, col3 = st.columns(3)

    col1.metric("Recent Logs",len(alerts[::10]))#needsvalue
    col2.metric("Alerts Triggered",len(alerts))
    col3.metric("High Alerts",placeholder["val1"])#needsvalue

    st.subheader("Recent Alerts")
    st.table(alerts)
    
