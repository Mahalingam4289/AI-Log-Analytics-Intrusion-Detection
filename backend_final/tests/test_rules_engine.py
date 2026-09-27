"""tests/test_rules_engine.py — unit tests for the Part B rule-based detectors."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pandas as pd
from rules import ip_spoofing, session_hijack, dns_spoofing, arp_spoofing, mitm


def test_ip_spoofing_flags_ttl_deviation():
    df = pd.DataFrame([
        dict(timestamp=pd.Timestamp("2026-01-01 00:00:00"), source_ip="10.0.0.5", destination_ip="x", ttl=64),
        dict(timestamp=pd.Timestamp("2026-01-01 00:00:01"), source_ip="10.0.0.5", destination_ip="x", ttl=63),
        dict(timestamp=pd.Timestamp("2026-01-01 00:00:02"), source_ip="10.0.0.5", destination_ip="x", ttl=20),  # spoofed
    ])
    flags = ip_spoofing.detect(df)
    assert len(flags) >= 1
    assert flags.iloc[0]["attack_type"] == "ip_spoofing"


def test_ip_spoofing_no_false_positive_on_stable_ttl():
    df = pd.DataFrame([
        dict(timestamp=pd.Timestamp("2026-01-01 00:00:00"), source_ip="10.0.0.5", destination_ip="x", ttl=64),
        dict(timestamp=pd.Timestamp("2026-01-01 00:00:01"), source_ip="10.0.0.5", destination_ip="x", ttl=63),
        dict(timestamp=pd.Timestamp("2026-01-01 00:00:02"), source_ip="10.0.0.5", destination_ip="x", ttl=64),
    ])
    assert ip_spoofing.detect(df).empty


def test_session_hijack_flags_new_ip_for_active_session():
    df = pd.DataFrame([
        dict(timestamp=pd.Timestamp("2026-01-01 09:00:00"), session_id="S1", user="u1", source_ip="10.0.0.1", action="login"),
        dict(timestamp=pd.Timestamp("2026-01-01 09:02:00"), session_id="S1", user="u1", source_ip="203.0.113.5", action="download"),
    ])
    flags = session_hijack.detect(df)
    assert len(flags) == 1
    assert flags.iloc[0]["attack_type"] == "session_hijacking"


def test_session_hijack_no_flag_for_same_ip():
    df = pd.DataFrame([
        dict(timestamp=pd.Timestamp("2026-01-01 09:00:00"), session_id="S1", user="u1", source_ip="10.0.0.1", action="login"),
        dict(timestamp=pd.Timestamp("2026-01-01 09:02:00"), session_id="S1", user="u1", source_ip="10.0.0.1", action="download"),
    ])
    assert session_hijack.detect(df).empty


def test_dns_spoofing_flags_ip_outside_history():
    rows = [dict(timestamp=pd.Timestamp("2026-01-01") + pd.Timedelta(minutes=i),
                 query_domain="corp.local", resolved_ip="10.0.0.5", resolver="r") for i in range(6)]
    rows.append(dict(timestamp=pd.Timestamp("2026-01-01 01:00:00"), query_domain="corp.local",
                      resolved_ip="203.0.113.9", resolver="r"))
    flags = dns_spoofing.detect(pd.DataFrame(rows))
    assert len(flags) == 1
    assert flags.iloc[0]["attack_type"] == "dns_spoofing"


def test_arp_spoofing_flags_mac_change():
    df = pd.DataFrame([
        dict(timestamp=pd.Timestamp("2026-01-01 00:00:00"), ip="10.0.0.1", mac_address="aa:aa:aa:aa:aa:aa"),
        dict(timestamp=pd.Timestamp("2026-01-01 00:00:01"), ip="10.0.0.1", mac_address="bb:bb:bb:bb:bb:bb"),
    ])
    flags = arp_spoofing.detect(df)
    assert len(flags) == 1
    assert flags.iloc[0]["attack_type"] == "arp_spoofing"
    assert "precursor" in flags.iloc[0]["evidence"].lower()


def test_mitm_requires_both_signals_to_overlap():
    session_flags = pd.DataFrame([dict(event_id="SH1", timestamp=pd.Timestamp("2026-01-01 10:00:00"),
                                        source_ip="1.2.3.4", user="u1", evidence="hijack")])
    arp_flags_close = pd.DataFrame([dict(timestamp=pd.Timestamp("2026-01-01 10:05:00"))])
    arp_flags_far = pd.DataFrame([dict(timestamp=pd.Timestamp("2026-01-02 10:05:00"))])

    assert len(mitm.detect(session_flags, arp_flags_close)) == 1
    assert mitm.detect(session_flags, arp_flags_far).empty
    assert mitm.detect(pd.DataFrame(), arp_flags_close).empty
