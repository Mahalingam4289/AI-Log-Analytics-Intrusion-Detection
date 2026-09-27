"""
rules/mitm.py

Man-in-the-Middle is not directly detectable from logs as a single
signal — it's an INFERENCE from other signals co-occurring: an attacker
positions themselves on the network path (commonly via ARP spoofing)
and then intercepts/replays session traffic (showing up as session
hijacking). This module doesn't run its own detection; it looks for
temporal overlap between the two other detectors' outputs for the same
approximate timeframe and upgrades the classification.
"""

import pandas as pd
from datetime import timedelta

MITM_CORRELATION_WINDOW_MINUTES = 20


def detect(session_hijack_flags: pd.DataFrame, arp_spoof_flags: pd.DataFrame) -> pd.DataFrame:
    if session_hijack_flags.empty or arp_spoof_flags.empty:
        return pd.DataFrame()

    flags = []
    for _, sh_row in session_hijack_flags.iterrows():
        window_start = sh_row["timestamp"] - timedelta(minutes=MITM_CORRELATION_WINDOW_MINUTES)
        window_end = sh_row["timestamp"] + timedelta(minutes=MITM_CORRELATION_WINDOW_MINUTES)
        overlap = arp_spoof_flags[
            (arp_spoof_flags["timestamp"] >= window_start) &
            (arp_spoof_flags["timestamp"] <= window_end)
        ]
        if not overlap.empty:
            flags.append(dict(
                event_id=f"RULE-MITM-{sh_row['event_id']}",
                timestamp=sh_row["timestamp"], source_ip=sh_row["source_ip"],
                user=sh_row["user"], attack_type="mitm",
                evidence=f"session hijacking ({sh_row['evidence']}) co-occurred with ARP "
                         f"spoofing within {MITM_CORRELATION_WINDOW_MINUTES} min — "
                         f"consistent with an active man-in-the-middle position",
                risk_hint=95,
            ))
    return pd.DataFrame(flags)
