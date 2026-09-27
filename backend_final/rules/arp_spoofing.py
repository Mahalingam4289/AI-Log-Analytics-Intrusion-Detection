"""
rules/arp_spoofing.py

Rule-based detection of ARP spoofing/cache poisoning — the standard
real-world PRECURSOR to network sniffing on a switched network. True
passive sniffing leaves no log trace on the victim side (it doesn't
generate traffic), so this module honestly detects the enabling attack
(ARP poisoning), not sniffing itself. That distinction is preserved all
the way to the dashboard's threat category text.

Signal: the same IP address associated with more than one MAC address
within a short window — a MAC changing for the gateway or a host is the
classic ARP cache poisoning signature.
"""

import pandas as pd

WINDOW_ROWS = 20  # recent observations to compare against per IP


def detect(arp_df: pd.DataFrame) -> pd.DataFrame:
    df = arp_df.sort_values("timestamp").copy()
    flags = []

    for ip, grp in df.groupby("ip"):
        grp = grp.sort_values("timestamp").reset_index()
        established_mac = grp.iloc[0]["mac_address"]
        for i, row in grp.iterrows():
            if row["mac_address"] != established_mac:
                flags.append(dict(
                    event_id=f"RULE-ARPSPOOF-{row['index']}",
                    timestamp=row["timestamp"], source_ip=ip, user="unknown",
                    attack_type="arp_spoofing",
                    evidence=f"{ip} now claims MAC {row['mac_address']}, "
                             f"was previously {established_mac} — possible ARP cache poisoning "
                             f"(precursor to network sniffing, not sniffing itself)",
                    risk_hint=75,
                ))
                established_mac = row["mac_address"]

    return pd.DataFrame(flags)
