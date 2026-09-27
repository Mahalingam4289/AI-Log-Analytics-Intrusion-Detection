"""
rules/dns_spoofing.py

Rule-based detection of DNS spoofing / cache poisoning: once a domain's
"normal" resolved IP (or small set of IPs, for load-balanced services)
is established from history, any resolution to a new IP outside that
set is flagged — the standard signature of a poisoned cache or a
rogue/compromised DNS response.
"""

import pandas as pd

MIN_HISTORY_BEFORE_TRUSTING = 5


def detect(dns_df: pd.DataFrame) -> pd.DataFrame:
    df = dns_df.sort_values("timestamp").copy()
    flags = []

    for domain, grp in df.groupby("query_domain"):
        grp = grp.sort_values("timestamp").reset_index()
        known_ips = set()
        for i, row in grp.iterrows():
            if i < MIN_HISTORY_BEFORE_TRUSTING:
                known_ips.add(row["resolved_ip"])
                continue
            if row["resolved_ip"] not in known_ips:
                flags.append(dict(
                    event_id=f"RULE-DNSSPOOF-{row['index']}",
                    timestamp=row["timestamp"], source_ip=row.get("resolver", "N/A"),
                    user="unknown", attack_type="dns_spoofing",
                    evidence=f"{domain} resolved to {row['resolved_ip']}, outside its "
                             f"established set {sorted(known_ips)}",
                    risk_hint=85,
                ))
            else:
                known_ips.add(row["resolved_ip"])

    return pd.DataFrame(flags)
