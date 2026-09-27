"""
rules/session_hijack.py

Rule-based detection of session hijacking: the same session_id observed
from two different source IPs within a short window is the classic
signature of a stolen session token/cookie being replayed by an
attacker while the legitimate session is still active.
"""

import pandas as pd
from datetime import timedelta

HIJACK_WINDOW_MINUTES = 15


def detect(session_df: pd.DataFrame) -> pd.DataFrame:
    df = session_df.sort_values("timestamp").copy()
    flags = []

    for session_id, grp in df.groupby("session_id"):
        grp = grp.sort_values("timestamp")
        seen_ips = {}
        first_ip = None
        for idx, row in grp.iterrows():
            ip = row["source_ip"]
            if first_ip is None:
                first_ip = ip
                seen_ips[ip] = row["timestamp"]
                continue
            if ip not in seen_ips:
                # A brand-new IP appeared for an already-active session
                gap = row["timestamp"] - min(seen_ips.values())
                if gap <= timedelta(minutes=HIJACK_WINDOW_MINUTES):
                    flags.append(dict(
                        event_id=f"RULE-SESSHIJACK-{idx}",
                        timestamp=row["timestamp"], source_ip=ip, user=row["user"],
                        attack_type="session_hijacking",
                        evidence=f"session {session_id} used from new IP {ip} "
                                 f"{gap.total_seconds()/60:.1f} min after first seen from {first_ip}",
                        risk_hint=80,
                    ))
            seen_ips[ip] = row["timestamp"]

    return pd.DataFrame(flags)
