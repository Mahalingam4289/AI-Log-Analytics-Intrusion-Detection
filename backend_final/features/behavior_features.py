"""
behavior_features.py — Stage 4: Application/behavior feature engineering.

    access_frequency_1h : resource accesses by user in prior 1 hour
    is_sensitive_resource : 1 if resource is in the sensitive set
    files_accessed_zscore : how unusual this event's file count is vs.
                             the user's own history
    privilege_escalation_flag : 1 if action == privilege_escalation
"""

import pandas as pd

SENSITIVE_RESOURCES = {"finance_db", "customer_data", "source_code_repo", "admin_console"}


def compute_behavior_features(unified: pd.DataFrame) -> pd.DataFrame:
    app = unified[unified["log_source"] == "application"].copy()
    app = app.sort_values("timestamp").reset_index(drop=True)

    app["is_sensitive_resource"] = app["resource"].isin(SENSITIVE_RESOURCES).astype(int)
    app["privilege_escalation_flag"] = (app["event_type"] == "privilege_escalation").astype(int)

    app["_orig_order"] = range(len(app))
    app_ts = app.set_index("timestamp")
    rows = []
    for u, grp in app_ts.groupby("user"):
        freq = grp["event_id"].rolling("60min").count()
        mean = grp["files_accessed"].rolling(20, min_periods=1).mean()
        std = grp["files_accessed"].rolling(20, min_periods=1).std().replace(0, 1).fillna(1)
        z = (grp["files_accessed"] - mean) / std
        rows.append(pd.DataFrame({
            "_orig_order": grp["_orig_order"].values,
            "access_frequency_1h": freq.values,
            "files_accessed_zscore": z.values,
        }))
    feat_df = pd.concat(rows).set_index("_orig_order")
    app = app.set_index("_orig_order")
    app["access_frequency_1h"] = feat_df["access_frequency_1h"]
    app["files_accessed_zscore"] = feat_df["files_accessed_zscore"].fillna(0)
    app = app.reset_index(drop=True)
    return app
