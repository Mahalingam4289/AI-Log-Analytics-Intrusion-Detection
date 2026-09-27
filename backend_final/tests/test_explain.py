"""tests/test_explain.py — unit tests for backend/app/explain.py"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.app.explain import explain_event


def test_explain_event_flags_high_failed_logins():
    features = {"failed_login_count_10min": 15, "is_off_hours": 0, "new_device": 0}
    result = explain_event(features, attack_model=None)
    assert len(result) >= 1
    assert any(r["feature"] == "failed_login_count_10min" for r in result)


def test_explain_event_quiet_event_returns_empty():
    features = {"failed_login_count_10min": 0, "login_frequency_1h": 1, "is_off_hours": 0,
                "new_device": 0, "new_location": 0, "ip_deviation": 0}
    result = explain_event(features, attack_model=None)
    assert result == []


def test_explain_event_respects_top_n():
    features = {"failed_login_count_10min": 20, "is_off_hours": 1, "new_device": 1,
                "new_location": 1, "ip_deviation": 1, "login_frequency_1h": 50}
    result = explain_event(features, attack_model=None, top_n=2)
    assert len(result) <= 2


def test_explain_event_output_shape():
    features = {"is_off_hours": 1}
    result = explain_event(features, attack_model=None)
    assert len(result) == 1
    entry = result[0]
    assert set(entry.keys()) == {"feature", "label", "value", "weight"}
    assert entry["label"] == "Login outside normal hours"
