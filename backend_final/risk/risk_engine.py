"""
risk_engine.py — Phase 10 & 11: Risk Scoring + Threat Categorization

Implements the research-prototype formula from Section 6 of the design
document:

    Risk Score = 0.40 * Anomaly Score
               + 0.30 * Attack Probability
               + 0.20 * Behavior Deviation
               + 0.10 * Asset Criticality

Severity bands:
    0-30    LOW
    31-60   MEDIUM
    61-80   HIGH
    81-100  CRITICAL

Threat categorization (Section 7) is expressed as classification /
suspicion, NOT definitive proof of intent, per the design document's
explicit caution.
"""

import pandas as pd

WEIGHTS = dict(anomaly=0.40, attack=0.30, behavior=0.20, asset=0.10)

SENSITIVE_RESOURCES = {"finance_db", "customer_data", "source_code_repo", "admin_console"}
ASSET_CRITICALITY = {
    "finance_db": 100, "customer_data": 100, "source_code_repo": 90,
    "admin_console": 95, "auth_service": 60, "hr_portal": 50,
    "email_server": 40, "billing_system": 70, "reports_db": 40,
    "network": 50,
}


def asset_criticality(resource: str) -> float:
    return ASSET_CRITICALITY.get(resource, 30)


def severity_band(risk_score: float) -> str:
    if risk_score <= 30:
        return "LOW"
    if risk_score <= 60:
        return "MEDIUM"
    if risk_score <= 80:
        return "HIGH"
    return "CRITICAL"


def categorize_threat(row) -> str:
    """Section 7 — classification, expressed as suspicion, not proof."""
    attack_type = str(row.get("predicted_attack_type", "none"))
    is_off_hours = row.get("is_off_hours", 0)
    behavior_dev = row.get("behavior_deviation", 0)
    new_device = row.get("new_device", 0)
    new_ip = row.get("ip_deviation", 0)

    if attack_type in ("probe", "dos"):
        return "Suspected External Attack"
    if attack_type == "ip_spoofing":
        return "Suspected IP Spoofing"
    if attack_type == "session_hijacking":
        return "Suspected Session Hijacking"
    if attack_type == "dns_spoofing":
        return "Suspected DNS Spoofing / Cache Poisoning"
    if attack_type == "arp_spoofing":
        return "Suspected Network Sniffing (ARP Spoofing Precursor)"
    if attack_type == "mitm":
        return "Suspected Man-in-the-Middle"
    if attack_type in ("account_compromise",) or (behavior_dev >= 50 and (new_device or new_ip)):
        return "Suspected Compromised Account"
    if attack_type in ("privilege_escalation", "data_exfiltration", "insider_threat"):
        return "Suspected Insider Threat"
    if attack_type == "brute_force":
        return "Suspected External Attack (Brute Force)"
    return "Unclassified / Low Concern"


def compute_risk(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    out["asset_criticality"] = out["resource"].apply(asset_criticality) if "resource" in out else 30

    out["risk_score"] = (
        WEIGHTS["anomaly"] * out.get("anomaly_score", 0).fillna(0)
        + WEIGHTS["attack"] * out.get("attack_probability", 0).fillna(0)
        + WEIGHTS["behavior"] * out.get("behavior_deviation", 0).fillna(0)
        + WEIGHTS["asset"] * out["asset_criticality"]
    ).round(2)

    out["severity"] = out["risk_score"].apply(severity_band)
    out["threat_category"] = out.apply(categorize_threat, axis=1)
    return out


def compute_incident_risk(incidents_df: pd.DataFrame) -> pd.DataFrame:
    """Apply the same formula at the incident level using the incident's
    max signal values, and roll up an incident-level threat category."""
    if incidents_df.empty:
        return incidents_df
    out = incidents_df.copy()
    out["asset_criticality"] = 70  # incidents already imply a sensitive chain; use a fixed default
    out["risk_score"] = (
        WEIGHTS["anomaly"] * out["max_anomaly_score"]
        + WEIGHTS["attack"] * out["max_attack_probability"]
        + WEIGHTS["behavior"] * out["max_behavior_deviation"]
        + WEIGHTS["asset"] * out["asset_criticality"]
    ).round(2)
    out["severity"] = out["risk_score"].apply(severity_band)

    def incident_category(row):
        types = str(row["attack_types"])
        if "account_compromise" in types or "brute_force" in types:
            return "Suspected Compromised Account"
        if "privilege_escalation" in types or "data_exfiltration" in types or "insider_threat" in types:
            return "Suspected Insider Threat"
        if "probe" in types or "dos" in types:
            return "Suspected External Attack"
        return "Unclassified / Under Review"

    out["threat_category"] = out.apply(incident_category, axis=1)
    return out
