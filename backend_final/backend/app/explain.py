"""
backend/app/explain.py

Lightweight, dependency-free "why was this flagged" explanations.

Rather than a full SHAP integration (heavy dependency, slow per-event),
this ranks the event's own feature values by (a) how unusual they are
for a security event in general and (b) how much the trained attack
classifier's global feature importances weight that feature. The result
is a short, human-readable list an analyst can read in under 5 seconds
— exactly what belongs in an alert drill-down.
"""

FEATURE_LABELS = {
    "failed_login_count_10min": "Failed logins in last 10 min",
    "login_frequency_1h": "Logins in last hour",
    "is_off_hours": "Login outside normal hours",
    "new_device": "Login from a new device",
    "new_location": "Login from a new location",
    "ip_deviation": "Login from an unrecognized IP",
    "connection_count_1min": "Connections in last 1 min",
    "unique_ports_recent": "Distinct ports contacted recently",
    "traffic_volume_zscore": "Traffic volume vs. this source's baseline",
    "access_frequency_1h": "Resource accesses in last hour",
    "files_accessed_zscore": "Files accessed vs. this user's baseline",
    "is_sensitive_resource": "Sensitive resource accessed",
    "privilege_escalation_flag": "Privilege escalation attempted",
}

# Rough "this value is worth flagging" thresholds, feature-by-feature.
# These are intentionally simple/interpretable rather than statistically
# derived — the goal is a readable explanation, not a second model.
FLAG_THRESHOLDS = {
    "failed_login_count_10min": 3,
    "login_frequency_1h": 8,
    "is_off_hours": 1,
    "new_device": 1,
    "new_location": 1,
    "ip_deviation": 1,
    "connection_count_1min": 15,
    "unique_ports_recent": 10,
    "traffic_volume_zscore": 2.5,
    "access_frequency_1h": 10,
    "files_accessed_zscore": 2.5,
    "is_sensitive_resource": 1,
    "privilege_escalation_flag": 1,
}


def _get_classifier_importances(attack_model):
    """Global (static) feature importances from the trained Random
    Forest — used only to rank/weight which triggered features matter
    most, not as a per-event value."""
    try:
        importances = attack_model.model.feature_importances_
        cols = attack_model.feature_columns
        return dict(zip(cols, importances))
    except Exception:
        return {}


def explain_event(feature_row: dict, attack_model=None, top_n=3):
    """Returns a short ranked list of the features that most explain why
    this event was flagged, e.g.:
        [{"feature": "failed_login_count_10min", "label": "Failed logins in last 10 min",
          "value": 14.0, "weight": 0.31}]
    Empty list means nothing in particular stood out (a "quiet" event).
    """
    importances = _get_classifier_importances(attack_model) if attack_model else {}
    triggered = []

    for feat, threshold in FLAG_THRESHOLDS.items():
        val = feature_row.get(feat, 0) or 0
        exceeded = (abs(val) >= threshold) if threshold else False
        if exceeded:
            weight = importances.get(feat, 0.05)
            triggered.append(dict(
                feature=feat,
                label=FEATURE_LABELS.get(feat, feat),
                value=round(float(val), 2),
                weight=round(float(weight), 4),
            ))

    triggered.sort(key=lambda x: x["weight"], reverse=True)
    return triggered[:top_n]
