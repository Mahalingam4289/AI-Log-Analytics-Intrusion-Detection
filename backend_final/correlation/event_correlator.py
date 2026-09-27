"""
event_correlator.py — Phase 9: Event Correlation

Groups individual suspicious events (per user, within a rolling time
window) into a single INCIDENT so the system tells an "attack story"
instead of flooding the analyst with disconnected alerts
(Section 5 of the design document).

An incident aggregates:
    - all correlated event_ids
    - the max anomaly_score, attack_probability, behavior_deviation observed
    - the set of attack_types / event_types seen (the "chain")
    - user, ip(s) involved
"""

import pandas as pd
from datetime import timedelta

CORRELATION_WINDOW_MINUTES = 15


def correlate_events(scored_df: pd.DataFrame, window_minutes=CORRELATION_WINDOW_MINUTES) -> pd.DataFrame:
    """
    scored_df must contain: timestamp, user, event_id, event_type,
    anomaly_score, attack_probability, behavior_deviation, source_ip,
    predicted_attack_type
    """
    df = scored_df.sort_values("timestamp").copy()
    incidents = []
    incident_id_counter = 1

    for user, grp in df.groupby("user"):
        if user in ("unknown", "N/A", None):
            # network-only events without a user aren't grouped by user;
            # they still surface individually via the alert manager.
            continue
        grp = grp.sort_values("timestamp").reset_index(drop=True)

        # Only consider events that show *some* signal worth correlating
        interesting = grp[
            (grp["anomaly_score"] >= 40) |
            (grp["attack_probability"] >= 40) |
            (grp["behavior_deviation"] >= 40)
        ].reset_index(drop=True)

        if interesting.empty:
            continue

        current_cluster = [interesting.iloc[0]]
        for i in range(1, len(interesting)):
            prev_ts = current_cluster[-1]["timestamp"]
            cur_ts = interesting.iloc[i]["timestamp"]
            if cur_ts - prev_ts <= timedelta(minutes=window_minutes):
                current_cluster.append(interesting.iloc[i])
            else:
                incidents.append(_build_incident(user, current_cluster, incident_id_counter))
                incident_id_counter += 1
                current_cluster = [interesting.iloc[i]]
        incidents.append(_build_incident(user, current_cluster, incident_id_counter))
        incident_id_counter += 1

    return pd.DataFrame(incidents)


def _build_incident(user, cluster_rows, incident_id):
    cluster = pd.DataFrame(cluster_rows)
    return dict(
        incident_id=f"INC-{incident_id:05d}",
        user=user,
        start_time=cluster["timestamp"].min(),
        end_time=cluster["timestamp"].max(),
        event_count=len(cluster),
        event_ids=",".join(cluster["event_id"].astype(str)),
        event_chain=" -> ".join(cluster["event_type"].astype(str)),
        attack_types=",".join(sorted(set(cluster.get("predicted_attack_type", pd.Series(["none"])).astype(str)) - {"none"}) or ["none"]),
        source_ips=",".join(sorted(set(cluster["source_ip"].astype(str)) - {"N/A", "unknown"})),
        max_anomaly_score=float(cluster["anomaly_score"].max()),
        max_attack_probability=float(cluster.get("attack_probability", pd.Series([0])).max()),
        max_behavior_deviation=float(cluster.get("behavior_deviation", pd.Series([0])).max()),
    )
