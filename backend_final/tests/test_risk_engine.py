"""
tests/test_risk_engine.py — unit tests for risk/risk_engine.py and
risk/mitre_mapping.py. Pure functions, no server/DB needed, so these
run instantly and are the first thing to check after any change to
the scoring logic.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from risk.risk_engine import severity_band, asset_criticality, categorize_threat, compute_risk
from risk.mitre_mapping import get_mitre_info
import pandas as pd


def test_severity_band_boundaries():
    assert severity_band(0) == "LOW"
    assert severity_band(30) == "LOW"
    assert severity_band(31) == "MEDIUM"
    assert severity_band(60) == "MEDIUM"
    assert severity_band(61) == "HIGH"
    assert severity_band(80) == "HIGH"
    assert severity_band(81) == "CRITICAL"
    assert severity_band(100) == "CRITICAL"


def test_asset_criticality_known_and_unknown_resource():
    assert asset_criticality("finance_db") == 100
    assert asset_criticality("email_server") == 40
    assert asset_criticality("some_unlisted_resource") == 30  # default fallback


def test_categorize_threat_probe_is_external_attack():
    row = dict(predicted_attack_type="probe", is_off_hours=0, behavior_deviation=10,
               new_device=0, ip_deviation=0)
    assert categorize_threat(row) == "Suspected External Attack"


def test_categorize_threat_brute_force_without_compromise_signals():
    # Low behavior deviation and no new device/IP -> falls through to the
    # plain brute-force branch rather than being upgraded to "Compromised
    # Account" (that upgrade is intentional and tested separately below).
    row = dict(predicted_attack_type="brute_force", is_off_hours=0, behavior_deviation=10,
               new_device=0, ip_deviation=0)
    assert "Brute Force" in categorize_threat(row)


def test_categorize_threat_brute_force_with_compromise_signals_upgrades_category():
    # Same attack type, but strong behavior deviation + new device/IP should
    # correctly be treated as a likely account compromise, not just "brute
    # force in progress" — this precedence is intentional.
    row = dict(predicted_attack_type="brute_force", is_off_hours=1, behavior_deviation=80,
               new_device=1, ip_deviation=1)
    assert categorize_threat(row) == "Suspected Compromised Account"


def test_categorize_threat_insider():
    row = dict(predicted_attack_type="data_exfiltration", is_off_hours=0, behavior_deviation=20,
               new_device=0, ip_deviation=0)
    assert categorize_threat(row) == "Suspected Insider Threat"


def test_categorize_threat_unclassified_when_nothing_stands_out():
    row = dict(predicted_attack_type="none", is_off_hours=0, behavior_deviation=5,
               new_device=0, ip_deviation=0)
    assert categorize_threat(row) == "Unclassified / Low Concern"


def test_compute_risk_formula_weights():
    df = pd.DataFrame([dict(
        resource="finance_db", anomaly_score=100, attack_probability=100, behavior_deviation=100,
        predicted_attack_type="data_exfiltration", is_off_hours=0, new_device=0, ip_deviation=0,
    )])
    out = compute_risk(df)
    # 0.4*100 + 0.3*100 + 0.2*100 + 0.1*100 (finance_db criticality) = 100
    assert out["risk_score"].iloc[0] == 100.0
    assert out["severity"].iloc[0] == "CRITICAL"


def test_compute_risk_zero_signal_is_low_severity():
    df = pd.DataFrame([dict(
        resource="email_server", anomaly_score=0, attack_probability=0, behavior_deviation=0,
        predicted_attack_type="none", is_off_hours=0, new_device=0, ip_deviation=0,
    )])
    out = compute_risk(df)
    # asset criticality alone (40) * 0.1 = 4
    assert out["risk_score"].iloc[0] == 4.0
    assert out["severity"].iloc[0] == "LOW"


def test_mitre_mapping_known_attack_type():
    info = get_mitre_info("brute_force")
    assert info is not None
    assert info["technique_id"] == "T1110"
    assert info["tactic"] == "Credential Access"


def test_mitre_mapping_none_for_benign():
    assert get_mitre_info("none") is None


def test_mitre_mapping_unknown_label_returns_none_not_error():
    assert get_mitre_info("some_future_attack_type_v2") is None
