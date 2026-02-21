import os
import datetime
from dataclasses import asdict, is_dataclass
from pymongo import MongoClient
from pymongo.collection import Collection

def ensure_indexes():
    events_col().create_index("ingestion_id")
    alerts_col().create_index("ingestion_id")
    alerts_col().create_index([("severity", 1), ("start", -1)])

def make_dict(x):
    return asdict(x) if is_dataclass(x) else dict(x)


def get_db():
    uri = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
    client = MongoClient(uri)
    return client["fyp_siem"]

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

def insert_events(ingestion_id, events):
    docs = []
    for e in events:
        d = dict(e)
        d["ingestion_id"] = ingestion_id
        docs.append(d)
    events_col().insert_many(docs,ordered=False)

def insert_alerts(ingestion_id,alerts):
    if not alerts:
        return
    docs = []
    for a in alerts:
        d = make_dict(a)
        d["ingestion_id"]=ingestion_id
        docs.append(d)
    alerts_col().insert_many(docs,ordered=False)

def ingestion_col():
    return get_db()["ingestions"]
def events_col():
    return get_db()["events"]
def alerts_col():
    return get_db()["alerts"]