"""
rules/rules_engine.py

Orchestrates the 5 rule-based detectors and formats their output to
match the `security_events` shape the ML pipeline already produces, so
main.py can concatenate rule-triggered rows into the same DataFrame that
flows through correlation -> risk scoring -> alerting -> response,
without any changes to those downstream stages.

This is intentionally a SEPARATE detection path from the ML models
(Isolation Forest / Random Forest) — these 5 attacks don't have the kind
of labeled flow-level training data the ML models need, so they're
caught by deterministic rules instead. Both paths feed the same risk
engine, so severity/alerting/response is consistent regardless of which
path caught the attack.
"""

import pandas as pd

from . import ip_spoofing, session_hijack, dns_spoofing, arp_spoofing, mitm


def run_all_rules(network_ttl_df, session_df, dns_df, arp_df) -> pd.DataFrame:
    ip_spoof_flags = ip_spoofing.detect(network_ttl_df)
    session_flags = session_hijack.detect(session_df)
    dns_flags = dns_spoofing.detect(dns_df)
    arp_flags = arp_spoofing.detect(arp_df)
    mitm_flags = mitm.detect(session_flags, arp_flags)

    all_flags = pd.concat(
        [d for d in [ip_spoof_flags, session_flags, dns_flags, arp_flags, mitm_flags] if not d.empty],
        ignore_index=True,
    ) if any(not d.empty for d in [ip_spoof_flags, session_flags, dns_flags, arp_flags, mitm_flags]) else pd.DataFrame()

    if all_flags.empty:
        return all_flags

    # Shape to match the columns risk_engine.compute_risk / the correlator
    # / alert_manager expect from an ML-scored event, so it can be
    # concatenated directly into `full` in main.py.
    out = all_flags.copy()
    out["log_source"] = "rules_engine"
    out["destination_ip"] = "N/A"
    out["event_type"] = out["attack_type"]
    out["resource"] = "network"
    out["status"] = "N/A"
    out["predicted_attack_type"] = out["attack_type"]
    out["attack_probability"] = 100.0  # a fired rule is a certainty, not a probability estimate
    out["anomaly_score"] = out["risk_hint"]
    out["is_anomaly"] = 1
    out["behavior_deviation"] = out["risk_hint"]
    out["is_off_hours"] = 0
    out["new_device"] = 0
    out["ip_deviation"] = 1
    out["is_attack"] = 1
    return out
