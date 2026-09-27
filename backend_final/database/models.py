"""
database/models.py — Phase 14: Database schema (SQLite via SQLAlchemy)
"""

from sqlalchemy import Column, String, Float, Integer, DateTime, create_engine
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class SecurityEvent(Base):
    __tablename__ = "security_events"
    event_id = Column(String, primary_key=True)
    timestamp = Column(DateTime)
    log_source = Column(String)
    user = Column(String)
    source_ip = Column(String)
    destination_ip = Column(String)
    event_type = Column(String)
    resource = Column(String)
    status = Column(String)
    anomaly_score = Column(Float)
    is_anomaly = Column(Integer)
    predicted_attack_type = Column(String)
    attack_probability = Column(Float)
    behavior_deviation = Column(Float)
    risk_score = Column(Float)
    severity = Column(String)
    threat_category = Column(String)
    is_attack_ground_truth = Column(Integer)
    attack_type_ground_truth = Column(String)
    explanation = Column(String)  # JSON-encoded list of {feature, value, note} — why this event was flagged
    mitre_technique = Column(String)  # JSON-encoded {tactic, technique_id, technique} or null


class Incident(Base):
    __tablename__ = "incidents"
    incident_id = Column(String, primary_key=True)
    user = Column(String)
    start_time = Column(DateTime)
    end_time = Column(DateTime)
    event_count = Column(Integer)
    event_chain = Column(String)
    attack_types = Column(String)
    source_ips = Column(String)
    risk_score = Column(Float)
    severity = Column(String)
    threat_category = Column(String)


class Alert(Base):
    __tablename__ = "alerts"
    alert_id = Column(String, primary_key=True)
    source = Column(String)
    severity = Column(String)
    risk_score = Column(Float)
    threat_category = Column(String)
    user = Column(String)
    source_ip = Column(String)
    timestamp = Column(DateTime)
    evidence = Column(String)
    correlated_events = Column(Integer)
    incident_id = Column(String)
    response_actions = Column(String)
    response_status = Column(String)
    status = Column(String, default="OPEN")       # OPEN, INVESTIGATING, CONFIRMED, FALSE_POSITIVE, RESOLVED
    analyst_notes = Column(String, default="")
    notified = Column(Integer, default=0)          # 1 if a webhook notification was sent
    mitre_technique = Column(String)                # JSON-encoded {tactic, technique_id, technique} or null


def get_engine(db_path="sqlite:///database/security_analytics.db"):
    return create_engine(db_path)


def init_db(engine):
    Base.metadata.create_all(engine)
