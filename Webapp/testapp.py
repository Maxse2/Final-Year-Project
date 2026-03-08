import streamlit as st
import os
import sys
import pandas as pd
import matplotlib.pyplot as plt
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

    if uploaded_file is not None and st.button("Process File"):
        st.write("File uploaded:", uploaded_file.name)
        
        lines = uploaded_file.read().decode("utf-8", errors="replace").splitlines()
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
        ensure_indexes()
        ingestion_id=create_ingestion(
            filename=uploaded_file.name,
            source=normaliser.source_name,
            raw_line_count=len(lines),
            event_count=len(events),
        )
        insert_events(ingestion_id,events)
        insert_alerts(ingestion_id,alerts)
        st.success(f"Processed {uploaded_file.name}")
        st.write("Events stored:",len(events))
        st.write("Alerts stored:",len(alerts))
        st.write("Ingestion ID:",ingestion_id)
    total_ingestions = ingestion_col().count_documents({})
    total_events = events_col().count_documents({})
    total_alerts = alerts_col().count_documents({})
    high_alerts = alerts_col().count_documents({"severity": "high"})
    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Uploads",total_ingestions)#needsvalue
    col2.metric("Events Stored",total_events)
    col3.metric("Alerts Stored",total_alerts)#needsvalue
    
    recent_alerts = list(
    alerts_col().find().sort("start", -1).limit(20)
    )
    recent_events = list(
    events_col().find().sort("start", -1).limit(20)
    )
    recent_alerts_df = pd.DataFrame(recent_alerts)
    recent_events_df = pd.DataFrame(recent_events)
    st.subheader("Recent Alerts")
    st.dataframe(recent_alerts_df)
    st.subheader("Recent Events")
    st.dataframe(recent_events_df)

if page == "Logs":
    all_events = list(events_col().find({}))
    all_alerts = list(alerts_col().find({}))
    events_df = pd.DataFrame(all_events)
    alerts_df = pd.DataFrame(all_alerts)
    events_df = events_df.drop(columns=["_id"], errors = "ignore")
    alerts_df = alerts_df.drop(columns=["_id"], errors = "ignore")
    uploaded_logs=list(
        ingestion_col().find(
            {},
            {"filename":1, "source": 1, "created_at":1,}
            ).sort("created_at",-1)
        )
    col1,col2=st.columns(2)
    if uploaded_logs:
        logs_df = pd.DataFrame(uploaded_logs)
        logs_df = logs_df.drop(columns=["_id"],errors="ignore")
    with col1:
        st.subheader("Uploaded Files")
        st.dataframe(logs_df,use_container_width=True)
        
    st.subheader("Log Visualisations")

    with st.container():
        st.markdown("---")
        tab1,tab2,tab3,tab4 = st.tabs([
            "Events",
            "Event Types",
            "Top Alert IPs",
            "Alerts",
            ])
        with tab1:
            col1,col2=st.columns(2)
            if not events_df.empty and "event_timestamp" in events_df.columns:
                events_df["event_timestamp"]=pd.to_datetime(events_df["event_timestamp"],errors="coerce")
                timeline=(
                    events_df
                    .dropna(subset=["event_timestamp"])
                    .set_index("event_timestamp")
                    .resample("1min")
                    .size()
                    .reset_index(name="count")
                    )
                with col1:
                    st.title("Event Information")
                    st.subheader("Event Timeline")
                    st.line_chart(timeline.set_index("event_timestamp"))
                    
            else:
                st.info("No timestamped event data.")
            if not alerts_df.empty and "end" in alerts_df.columns:
                alerts_df["end"]=pd.to_datetime(alerts_df["end"],errors="coerce")
                timeline=(
                    alerts_df
                    .dropna(subset=["end"])
                    .set_index("end")
                    .resample("1min")
                    .size()
                    .reset_index(name="count")
                    )
                with col2:
                    st.title("Alert Information")
                    st.subheader("Alert Timeline")
                    st.line_chart(timeline.set_index("end"))
                    
            else:
                st.info("No timestamped alert data.")
            col1,col2= st.columns(2)
            if not events_df.empty and "event_type" in events_df.columns:
                event_counts = events_df["event_type"].value_counts()
                with col1:
                    st.subheader("Event Frequency")
                    st.bar_chart(event_counts)
        with tab2:
            col1,col2,col3=st.columns(3)
                