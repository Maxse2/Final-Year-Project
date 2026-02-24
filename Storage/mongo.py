import os
import datetime
from dataclasses import asdict, is_dataclass
from pymongo import MongoClient
from pymongo.collection import Collection

# Ensures data fed to mongo is using the correct event indexes.
def ensure_indexes():
    events_col().create_index("ingestion_id")
    alerts_col().create_index("ingestion_id")
    alerts_col().create_index([("severity", 1), ("start", -1)])

# Turns given variable or dataclass into a dictionary.
def make_dict(x):
    return asdict(x) if is_dataclass(x) else dict(x)

# Establishes a connection to a local MongoDB database under the name "fyp_siem".
# Local connection is used for now.
def get_db():
    uri = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
    client = MongoClient(uri)
    return client["fyp_siem"]

# Creates an ingestion entry for ingested data to help users track what data
# has been uploaded. 
def create_ingestion(*,filename,source,raw_line_count,event_count):
    doc = {
        "filename":filename,
        "source":source,
        "created_at":datetime.datetime.utcnow(),
        "raw_line_count": raw_line_count,
        "event_count":event_count,
        }
    result = ingestion_col().insert_one(doc)
    return str(result.inserted_id)

# Ensures given events are dictionaries and inserts them into the Mongo database.
# Ingestion ID is stamped onto data passed through this function.
def insert_events(ingestion_id, events):
    docs = []
    for e in events:
        d = dict(e)
        d["ingestion_id"] = ingestion_id
        docs.append(d)
    events_col().insert_many(docs,ordered=False)

# Ensures given alerts are dictionaries and inserts them into the Mongo database.
# Ingestion ID is stamped onto data passed through this function.
def insert_alerts(ingestion_id,alerts):
    if not alerts:
        return
    docs = []
    for a in alerts:
        d = make_dict(a)
        d["ingestion_id"]=ingestion_id
        docs.append(d)
    alerts_col().insert_many(docs,ordered=False)

# Creates (or refers to existing) database collections for ingestions, events and alerts.
def ingestion_col():
    return get_db()["ingestions"]
def events_col():
    return get_db()["events"]
def alerts_col():
    return get_db()["alerts"]