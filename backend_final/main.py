"""
main.py — Orchestrates the FULL pipeline end-to-end:

  data -> ingestion -> normalization -> feature engineering ->
  anomaly detection -> attack classification -> behavior analysis ->
  event correlation -> risk scoring -> threat categorization ->
  alerting -> simulated response -> database storage

Run:
    python main.py
"""

import os
import sys
import pandas as pd
from sklearn.model_selection import train_test_split

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from preprocessing.log_parser import load_all_logs
from preprocessing.normalizer import build_unified_events
from features.auth_features import compute_auth_features
from features.network_features import compute_network_features
from features.behavior_features import compute_behavior_features
from models.anomaly_detector import AnomalyDetector
from models.attack_classifier import AttackClassifier
from behavior.behavior_model import BehaviorEngine
from correlation.event_correlator import correlate_events
from risk.risk_engine import compute_risk, compute_incident_risk
from alerts.alert_manager import generate_all_alerts
from response.response_engine import simulate_response
from database.database import setup_database, save_events, save_incidents, save_alerts

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
MODEL_DIR = os.path.join(BASE_DIR, "saved_models")


def run_pipeline():
    os.makedirs(MODEL_DIR, exist_ok=True)

    print("=" * 70)
    print("PHASE 2-3 : Log Ingestion + Normalization")
    print("=" * 70)
    auth_df, net_df, app_df = load_all_logs(
        os.path.join(DATA_DIR, "auth_logs.csv"),
        os.path.join(DATA_DIR, "network_logs.csv"),
        os.path.join(DATA_DIR, "application_logs.csv"),
    )
    unified = build_unified_events(auth_df, net_df, app_df)
    print(f"Unified security events: {len(unified):,}")

    print("\n" + "=" * 70)
    print("PHASE 4-5 : Feature Engineering")
    print("=" * 70)
    auth_feat = compute_auth_features(unified)
    net_feat = compute_network_features(unified)
    behav_feat = compute_behavior_features(unified)

    # Merge feature sets back onto the unified event table (left join on event_id)
    feat_cols_auth = ["event_id", "login_hour", "is_off_hours", "new_device",
                       "new_location", "ip_deviation", "failed_login_count_10min",
                       "login_frequency_1h"]
    feat_cols_net = ["event_id", "connection_count_1min", "unique_ports_recent",
                      "traffic_volume_zscore"]
    feat_cols_behav = ["event_id", "is_sensitive_resource", "privilege_escalation_flag",
                        "access_frequency_1h", "files_accessed_zscore"]

    full = unified.merge(auth_feat[feat_cols_auth], on="event_id", how="left")
    full = full.merge(net_feat[feat_cols_net], on="event_id", how="left")
    full = full.merge(behav_feat[feat_cols_behav], on="event_id", how="left")
    full = full.fillna(0)
    print(f"Feature matrix ready: {full.shape[0]:,} rows x {full.shape[1]} cols")

    print("\n" + "=" * 70)
    print("PHASE 6 : AI Anomaly Detection (Isolation Forest)")
    print("=" * 70)
    anomaly_model = AnomalyDetector(contamination=0.08)
    anomaly_model.fit(full)
    full = anomaly_model.score(full)
    anomaly_model.save(os.path.join(MODEL_DIR, "anomaly_model.pkl"))
    print(f"Anomalies flagged: {full['is_anomaly'].sum():,} / {len(full):,}")

    print("\n" + "=" * 70)
    print("PHASE 7 : Attack Classification (Random Forest)")
    print("=" * 70)
    train_df, test_df = train_test_split(
        full, test_size=0.25, random_state=42, stratify=full["is_attack"])
    clf = AttackClassifier()
    clf.fit(train_df, label_col="attack_type")
    full = clf.predict(full)
    clf.save(os.path.join(MODEL_DIR, "attack_model.pkl"))
    print(f"Predicted attack events: {(full['predicted_attack_type'] != 'none').sum():,}")

    print("\n" + "=" * 70)
    print("PHASE 8 : User/Entity Behavior Analysis")
    print("=" * 70)
    behavior_engine = BehaviorEngine()
    behavior_engine.build_baseline(auth_feat, behav_feat)
    full = behavior_engine.score_events(full)
    print(f"Mean behavior deviation: {full['behavior_deviation'].mean():.2f}")

    print("\n" + "=" * 70)
    print("PHASE 8b : Rule-Based Detection (IP/Session/DNS/ARP/MITM)")
    print("=" * 70)
    try:
        from rules.rules_engine import run_all_rules
        net_ttl = pd.read_csv(os.path.join(DATA_DIR, "network_ttl_logs.csv"), parse_dates=["timestamp"])
        session_df = pd.read_csv(os.path.join(DATA_DIR, "session_logs.csv"), parse_dates=["timestamp"])
        dns_df = pd.read_csv(os.path.join(DATA_DIR, "dns_logs.csv"), parse_dates=["timestamp"])
        arp_df = pd.read_csv(os.path.join(DATA_DIR, "arp_logs.csv"), parse_dates=["timestamp"])
        rule_events = run_all_rules(net_ttl, session_df, dns_df, arp_df)
        if not rule_events.empty:
            rule_events["event_id"] = rule_events["event_id"].astype(str)
            full = pd.concat([full, rule_events], ignore_index=True, sort=False).fillna(0)
        print(f"Rule-based detections added: {len(rule_events):,} "
              f"({rule_events['attack_type'].value_counts().to_dict() if not rule_events.empty else {}})")
    except FileNotFoundError:
        print("Extra log files not found — run `python data/generate_extra_logs.py` first. Skipping rules engine.")

    print("\n" + "=" * 70)
    print("PHASE 10-11 : Risk Scoring + Threat Categorization")
    print("=" * 70)
    full = compute_risk(full)
    print(full["severity"].value_counts().to_string())

    print("\n" + "=" * 70)
    print("PHASE 9 : Event Correlation (Incident Building)")
    print("=" * 70)
    incidents = correlate_events(full)
    if not incidents.empty:
        incidents = compute_incident_risk(incidents)
    print(f"Incidents created: {len(incidents):,}")

    print("\n" + "=" * 70)
    print("PHASE 12 : Alert Management")
    print("=" * 70)
    alerts = generate_all_alerts(incidents, full)
    print(f"Alerts generated: {len(alerts):,}")

    print("\n" + "=" * 70)
    print("PHASE 13 : Automated Response (Simulated)")
    print("=" * 70)
    alerts = simulate_response(alerts)
    if not alerts.empty:
        print(alerts["response_status"].value_counts().to_string())

    print("\n" + "=" * 70)
    print("PHASE 14 : Database Storage")
    print("=" * 70)
    os.chdir(BASE_DIR)
    engine = setup_database()
    save_events(engine, full)
    save_incidents(engine, incidents)
    save_alerts(engine, alerts)
    print("Saved to database/security_analytics.db")

    # Persist intermediate CSVs too (used by dashboard + evaluation)
    full.to_csv(os.path.join(DATA_DIR, "scored_events.csv"), index=False)
    incidents.to_csv(os.path.join(DATA_DIR, "incidents.csv"), index=False)
    alerts.to_csv(os.path.join(DATA_DIR, "alerts.csv"), index=False)

    print("\nPipeline complete.")
    return full, incidents, alerts


if __name__ == "__main__":
    run_pipeline()
