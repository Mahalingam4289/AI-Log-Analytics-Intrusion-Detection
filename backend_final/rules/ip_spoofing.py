"""
rules/ip_spoofing.py

Rule-based (not ML) detection of IP spoofing: for each source IP, learn
its normal TTL range from its own history, then flag packets claiming
that IP whose TTL falls far outside that range — the classic signature
of a forged source address (the real packet took a different, usually
longer, network path than the genuine host).
"""

import pandas as pd

TTL_DEVIATION_THRESHOLD = 15  # hops


def detect(network_ttl_df: pd.DataFrame) -> pd.DataFrame:
    """Returns one row per flagged event with a unified shape:
    timestamp, source_ip, attack_type, evidence, risk_hint (0-100)."""
    df = network_ttl_df.sort_values("timestamp").copy()
    flags = []

    for ip, grp in df.groupby("source_ip"):
        baseline = grp["ttl"].expanding().median()
        deviation = (grp["ttl"] - baseline).abs()
        for idx, dev in deviation.items():
            if dev >= TTL_DEVIATION_THRESHOLD:
                row = df.loc[idx]
                flags.append(dict(
                    event_id=f"RULE-IPSPOOF-{idx}",
                    timestamp=row["timestamp"], source_ip=ip, user="unknown",
                    attack_type="ip_spoofing",
                    evidence=f"TTL={row['ttl']} deviates {dev:.0f} hops from this IP's baseline",
                    risk_hint=min(60 + dev, 95),
                ))
    return pd.DataFrame(flags)
