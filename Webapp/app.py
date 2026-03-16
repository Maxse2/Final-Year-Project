import streamlit as st
from bson import ObjectId
import os
import sys
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
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
#Placeholder lists
alerts = []
events= []
# Sidebar for page selection
st.sidebar.title("LogView")

page = st.sidebar.radio(
    "Navigation",
    ["Dashboard", "Logs", "Alerts"]
)


#Dashboard page takes file uploads, puts them through the normalisation and alerting modules
#and displays quick metrics based on uploaded files,
#including 20 most recent events and alerts.

if page == "Dashboard":

    st.title("Dashboard")
    uploaded_file = st.file_uploader(
        "Upload a log file",
        type=["log", "txt", "csv"]
    )
    st.caption("Windows Event Logs MUST be named 'security_events.csv'!") # Due to Windows event logs being identified from filename

    # Main ingestion -> normalisation -> Alerting pipeline carried out here
    if uploaded_file is not None and st.button("Process File"):
        st.write("File uploaded:", uploaded_file.name)
        
        lines = uploaded_file.read().decode("utf-8", errors="replace").splitlines() # Auth and Apache normalisers take lines instead of the 
        normaliser = get_normaliser(uploaded_file.name)                             # Entire file
        
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
        # Correlation rule engine is run here to find alerts within given data. Ingestion ID is important in case user wants to delete an upload.
        alerts = engine.run(events)
        ensure_indexes()
        ingestion_id=create_ingestion(
            filename=uploaded_file.name,
            source=normaliser.source_name,
            raw_line_count=len(lines),
            event_count=len(events),
        )
        # Events and Alerts uploaded to Mongo here
        insert_events(ingestion_id,events)
        insert_alerts(ingestion_id,alerts)
        st.success(f"Processed {uploaded_file.name}")
        # Write lines display relevant metrics for user convenience.
        st.write("Events stored:",len(events))
        st.write("Alerts stored:",len(alerts))
        st.write("Ingestion ID:",ingestion_id)
    # Total ingestions, events and alerts are collected to display to the user.
    total_ingestions = ingestion_col().count_documents({})
    total_events = events_col().count_documents({})
    total_alerts = alerts_col().count_documents({})
    high_alerts = alerts_col().count_documents({"severity": "high"})
    col1, col2, col3, col4 = st.columns(4)
    
    col1.metric("Uploads",total_ingestions)
    col2.metric("Events Stored",total_events)
    col3.metric("Alerts Stored",total_alerts)
    # Dashboard displays 20 most recent events and alerts here.
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

#Logs page displays uploaded logs, and gives the option to delete them. The user can view important visualisations of their data  here,
#and filter them by date and time for more precise perspectives on events and alerts that have occured.

if page == "Logs":
    all_events = list(events_col().find({}))
    all_alerts = list(alerts_col().find({}))
    
    events_df = pd.DataFrame(all_events)
    alerts_df = pd.DataFrame(all_alerts)
    
    events_df = events_df.drop(columns=["_id"], errors = "ignore")
    alerts_df = alerts_df.drop(columns=["_id"], errors = "ignore")
    
    filtered_events_df = events_df.copy()
    filtered_alerts_df = alerts_df.copy()
    
    uploaded_logs=list(
        ingestion_col().find(
            {},
            {"filename":1, "source": 1, "created_at":1,}
            ).sort("created_at",-1)
        )
    
    logs_df = pd.DataFrame(uploaded_logs)
    
    if not logs_df.empty and "_id" in logs_df.columns:
        logs_df["upload_id"] = logs_df["_id"].astype(str)
    
    col1,col2=st.columns(2)
    
    # Nested code allows the deletion of files based on ingestion ID, which is stamped on all ingestions, alerts and events.
    if not logs_df.empty:
        delete_file= st.checkbox("Delete Files")
        if delete_file:
            
            delete_options = {
                f"{row['filename']} | {row['source']} | {row['created_at']}":str(row["_id"])
                for _,row in logs_df.iterrows()
                }
            selected_upload_label = st.selectbox(
                "Select an upload to delete: ",
                options=list(delete_options.keys())
                )
            if st.button("Delete selected upload"):
                selected_id = delete_options[selected_upload_label]
                # Entries in MongoDB are deleted in here, which will reflect immediately on the app.
                events_deleted=events_col().delete_many(
                    {"ingestion_id":selected_id}
                    ).deleted_count
                alerts_deleted = alerts_col().delete_many(
                    {"ingestion_id":selected_id}
                    ).deleted_count
                ingestion_col().delete_one({"_id": ObjectId(selected_id)})
                st.success(
                    f"Deleted upload, {events_deleted} linked events, and {alerts_deleted} linked alerts."
                    )
                st.rerun()
        
        
        
        
    with col1:
        st.subheader("Uploaded Files")
        if logs_df.empty:
            st.info("No uploaded files yet.")
        else:
            st.dataframe(
                logs_df[["filename","source","created_at"]],
                use_container_width=True
                )
        
    st.subheader("Log Visualisations")
    use_time_filter = st.checkbox("Enable time filter")
    start_dt=None
    end_dt=None
    # Nested code allows for time filtering, based on a date and time ranged specified by the user.
    if use_time_filter:
        fcol1,fcol2,fcol3,fcol4=st.columns(4)
        with fcol1:
            start_date=st.date_input("Start Date")
        with fcol2:
            start_time=st.time_input("Start Time")
        with fcol3:
            end_date=st.date_input("End Date")
        with fcol4:
            end_time=st.time_input("End Time")
        # Datetime variables based on the user's choice are stored here.
        start_dt = datetime.combine(start_date, start_time)
        end_dt = datetime.combine(end_date,end_time)
        if "event_timestamp" in events_df.columns:
            events_df["event_timestamp"] = pd.to_datetime(
                events_df["event_timestamp"],errors="coerce"
                )
        # "end" entry in alert data is used for full clarity.
        if "end" in alerts_df.columns:
            alerts_df["end"]=pd.to_datetime(
                alerts_df["end"],errors="coerce"
                )
        # Events and alerts are filtered here.
        if start_dt is not None and "event_timestamp" in filtered_events_df.columns:
            filtered_events_df = filtered_events_df[
                filtered_events_df["event_timestamp"] >= pd.Timestamp(start_dt)
                ]
        if end_dt is not None and "event_timestamp" in filtered_events_df.columns:
            filtered_events_df = filtered_events_df[
            filtered_events_df["event_timestamp"] <= pd.Timestamp(end_dt)
            ]
        if start_dt is not None and "end" in filtered_alerts_df.columns:
            filtered_alerts_df = filtered_alerts_df[
                filtered_alerts_df["end"] >= pd.Timestamp(start_dt)
                ]
        if end_dt is not None and "end" in filtered_alerts_df.columns:
            filtered_alerts_df = filtered_alerts_df[
            filtered_alerts_df["end"] <= pd.Timestamp(end_dt)
            ]
        st.caption(f"Filtered Events: {len(filtered_events_df)}")
        st.caption(f"Filtered Alerts: {len(filtered_alerts_df)}")
    # This container is dedicated to visualisations, generated using streamlit's
    # visualisation options such as st.line_chart and st.bar_chart
    with st.container():
        st.markdown("---")
        col1,col2=st.columns(2)
        if not filtered_events_df.empty and "event_timestamp" in filtered_events_df.columns:
            filtered_events_df["event_timestamp"]=pd.to_datetime(filtered_events_df["event_timestamp"],errors="coerce")
            timeline=(
                filtered_events_df
                .dropna(subset=["event_timestamp"])
                .set_index("event_timestamp")
                .resample("1min")
                .size()
                .reset_index(name="count")
                )
            # Col1 has a full timeline of events, with timestamp set as the key / X axis
            with col1:
                st.title("Event Information")
                st.subheader("Event Timeline")
                st.line_chart(timeline.set_index("event_timestamp"))
                    
        else:
            st.info("No timestamped event data.")
        if not filtered_alerts_df.empty and "end" in filtered_alerts_df.columns:
            filtered_alerts_df["end"]=pd.to_datetime(filtered_alerts_df["end"],errors="coerce")
            timeline=(
                filtered_alerts_df
                .dropna(subset=["end"])
                .set_index("end")
                .resample("1min")
                .size()
                .reset_index(name="count")
                )
            # Col 2 has a full timeline of alerts, with "end" timestamp set as the key / X axis
            with col2:
                st.title("Alert Information")
                st.subheader("Alert Timeline")
                st.line_chart(timeline.set_index("end"))
                    
        else:
            st.info("No timestamped alert data.")
        col1,col2= st.columns(2)
        # event_counts and alert_counts store event and alert types, and how many times they appear in the data.
        if not filtered_events_df.empty and "event_type" in filtered_events_df.columns:
            event_counts = filtered_events_df["event_type"].value_counts()
        if not filtered_alerts_df.empty and "alert_type" in filtered_alerts_df.columns:
            alert_counts = filtered_alerts_df["alert_type"].value_counts()
            # Col 1 and Col 2 present visualisations of these counts, in the form of bar charts.
            with col1:
                st.subheader("Event Frequency")
                st.bar_chart(event_counts)
            with col2:
                st.subheader("Alert Frequency")
                st.bar_chart(alert_counts)

#Alerts page takes and displays all alerts, along with filters for severity and alert type.
if page == "Alerts":
    st.title("Alerts")
    all_alerts = list(alerts_col().find({}))
    alerts_df = pd.DataFrame(all_alerts)
    alerts_df = alerts_df.drop(columns=["_id"], errors="ignore")
    filtered_alerts_df = alerts_df.copy()

    if alerts_df.empty:
        st.info("No alerts available yet.")
    else:
        if "start" in alerts_df.columns:
            alerts_df["start"] = pd.to_datetime(alerts_df["start"], errors="coerce")
        if "end" in alerts_df.columns:
            alerts_df["end"] = pd.to_datetime(alerts_df["end"], errors="coerce")
            
    scol1,scol2=st.columns(2)
    # Scol 1 scans data for severity values, and incorporates them into a filter.
    with scol1:
        severity_options= sorted(
            [x for x in filtered_alerts_df["severity"].dropna().unique()]
            ) if "severity" in filtered_alerts_df.columns else []
        selected_severity= st.multiselect(
            "Severity",
            options=severity_options,
            default=[]
            )
    # Scol 2 does the same thing as Scol1, except with alert types.
    with scol2:
        alert_type_options = sorted(
            [x for x in filtered_alerts_df["alert_type"].dropna().unique()]
            ) if "alert_type" in filtered_alerts_df.columns else []
        selected_alert_type = st.multiselect(
            "Alert Type",
            options=alert_type_options,
            default=[]
            )
    # Alerts data is filtered here.
    if selected_severity and "severity" in filtered_alerts_df.columns:
        filtered_alerts_df = filtered_alerts_df[
            filtered_alerts_df["severity"].isin(selected_severity)
            ]
    
    if selected_alert_type and "alert_type" in filtered_alerts_df.columns:
        filtered_alerts_df = filtered_alerts_df[
            filtered_alerts_df["alert_type"].isin(selected_alert_type)
            ]
    # Mcol 1 through 4 present important metrics regarding alerts.
    mcol1,mcol2,mcol3,mcol4=st.columns(4)
    with mcol1:
        st.metric("Total Alerts",len(filtered_alerts_df))
    with mcol2:
        high_count = len(filtered_alerts_df[filtered_alerts_df["severity"] == "high"]) if "severity" in filtered_alerts_df.columns else 0
        st.metric("High Alerts",high_count)
    with mcol3:
        medium_count = len(filtered_alerts_df[filtered_alerts_df["severity"] == "medium"]) if "severity" in filtered_alerts_df.columns else 0
        st.metric("Medium Alerts",medium_count)
    with mcol4:
        unique_types = filtered_alerts_df["alert_type"].nunique() if "alert_type" in filtered_alerts_df.columns else 0
        st.metric("Alert Types", unique_types)
        
    st.dataframe(filtered_alerts_df)














