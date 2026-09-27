"""
alert_manager.py — Phase 12: Alert Management

Converts high-risk incidents (and standalone high-risk events, e.g.
network-only probes/DoS with no associated user) into structured,
prioritized alerts, matching the alert card format in Section 8 of the
design document.
"""

import pandas as pd

ALERT_THRESHOLD = 31  # anything MEDIUM or above becomes an alert


def generate_alerts_from_incidents(incidents_df: pd.DataFrame) -> pd.DataFrame:
    if incidents_df.empty:
        return pd.DataFrame(columns=[
            "alert_id", "source", "severity", "risk_score", "threat_category",
            "user", "source_ip", "timestamp", "evidence", "correlated_events"
        ])
    alerts = incidents_df[incidents_df["risk_score"] >= ALERT_THRESHOLD].copy()
    alerts["alert_id"] = ["ALT-" + str(i).zfill(5) for i in range(1, len(alerts) + 1)]
    alerts["source"] = "incident"
    alerts["timestamp"] = alerts["start_time"]
    alerts["evidence"] = alerts["event_chain"]
    alerts["correlated_events"] = alerts["event_count"]
    return alerts[[
        "alert_id", "source", "severity", "risk_score", "threat_category",
        "user", "source_ips", "timestamp", "evidence", "correlated_events", "incident_id"
    ]].rename(columns={"source_ips": "source_ip"}).sort_values("risk_score", ascending=False)


def generate_alerts_from_events(scored_events: pd.DataFrame) -> pd.DataFrame:
    """Catches standalone high-risk events (e.g. network probes/DoS with
    no user identity) that wouldn't be grouped by the user-based
    correlator."""
    net_events = scored_events[
        (scored_events["log_source"] == "network") & (scored_events["risk_score"] >= ALERT_THRESHOLD)
    ].copy()
    if net_events.empty:
        return pd.DataFrame(columns=[
            "alert_id", "source", "severity", "risk_score", "threat_category",
            "user", "source_ip", "timestamp", "evidence", "correlated_events", "incident_id"
        ])
    # collapse consecutive identical (source_ip, attack_type) bursts into one alert
    net_events = net_events.sort_values("timestamp")
    grouped = net_events.groupby(["source_ip", "predicted_attack_type"]).agg(
        risk_score=("risk_score", "max"),
        severity=("severity", lambda s: s.iloc[s.reset_index(drop=True).map(
            {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}).idxmax()]),
        threat_category=("threat_category", "first"),
        timestamp=("timestamp", "min"),
        correlated_events=("event_id", "count"),
    ).reset_index()
    grouped["alert_id"] = ["ALT-NET-" + str(i).zfill(5) for i in range(1, len(grouped) + 1)]
    grouped["source"] = "network_event"
    grouped["user"] = "N/A"
    grouped["evidence"] = grouped["predicted_attack_type"]
    grouped["incident_id"] = "N/A"
    return grouped[[
        "alert_id", "source", "severity", "risk_score", "threat_category",
        "user", "source_ip", "timestamp", "evidence", "correlated_events", "incident_id"
    ]].sort_values("risk_score", ascending=False)


def generate_all_alerts(incidents_df: pd.DataFrame, scored_events: pd.DataFrame) -> pd.DataFrame:
    a1 = generate_alerts_from_incidents(incidents_df)
    a2 = generate_alerts_from_events(scored_events)
    combined = pd.concat([a1, a2], ignore_index=True)
    return combined.sort_values("risk_score", ascending=False).reset_index(drop=True)
