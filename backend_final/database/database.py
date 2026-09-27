"""
database/database.py — Phase 14: Database write/read helpers
"""

import pandas as pd
from sqlalchemy.orm import sessionmaker
from .models import get_engine, init_db, SecurityEvent, Incident, Alert


def setup_database(db_path="sqlite:///database/security_analytics.db"):
    engine = get_engine(db_path)
    init_db(engine)
    return engine


def save_events(engine, events_df: pd.DataFrame):
    cols = [c.name for c in SecurityEvent.__table__.columns]
    df = events_df.rename(columns={
        "is_attack": "is_attack_ground_truth",
        "attack_type": "attack_type_ground_truth",
    })
    df = df.reindex(columns=cols)
    df.to_sql("security_events", engine, if_exists="replace", index=False)


def save_incidents(engine, incidents_df: pd.DataFrame):
    if incidents_df.empty:
        return
    cols = [c.name for c in Incident.__table__.columns]
    df = incidents_df.reindex(columns=cols)
    df.to_sql("incidents", engine, if_exists="replace", index=False)


def save_alerts(engine, alerts_df: pd.DataFrame):
    if alerts_df.empty:
        return
    cols = [c.name for c in Alert.__table__.columns]
    df = alerts_df.reindex(columns=cols)
    df.to_sql("alerts", engine, if_exists="replace", index=False)


def load_table(engine, table_name):
    return pd.read_sql_table(table_name, engine)


# ---------------------------------------------------------------------
# Real-time append helpers (used by the FastAPI streaming pipeline).
# Unlike save_events/save_incidents/save_alerts above (batch, replace-all,
# used by main.py), these APPEND single rows/records as they are scored,
# which is what a live system needs.
# ---------------------------------------------------------------------
def append_event(engine, event_row: dict):
    cols = [c.name for c in SecurityEvent.__table__.columns]
    row = {k: event_row.get(k) for k in cols}
    pd.DataFrame([row]).to_sql("security_events", engine, if_exists="append", index=False)


def append_incident(engine, incident_row: dict):
    cols = [c.name for c in Incident.__table__.columns]
    row = {k: incident_row.get(k) for k in cols}
    pd.DataFrame([row]).to_sql("incidents", engine, if_exists="append", index=False)


def append_alert(engine, alert_row: dict):
    cols = [c.name for c in Alert.__table__.columns]
    row = {k: alert_row.get(k) for k in cols}
    pd.DataFrame([row]).to_sql("alerts", engine, if_exists="append", index=False)
