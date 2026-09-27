"""
behavior_model.py — Phase 8: User / Entity Behavior Analysis (UEBA)

Builds a per-user "normal profile" from historical auth + application
events:
    - normal login hour range
    - known devices
    - known locations / IPs
    - typical daily resource-access volume

Then scores every NEW event against that baseline to produce a
`behavior_deviation` score in [0, 100]. This mirrors Section 4 of the
design document (baseline vs. observed comparison).
"""

import numpy as np
import pandas as pd


class BehaviorEngine:
    def __init__(self):
        self.profiles = {}  # user -> profile dict

    def build_baseline(self, auth_features: pd.DataFrame, behavior_features: pd.DataFrame):
        for user, grp in auth_features.groupby("user"):
            normal = grp[grp["is_attack"] == 0] if "is_attack" in grp else grp
            if normal.empty:
                normal = grp
            hours = normal["login_hour"]
            devices = set(normal["device"])
            locations = set(normal["location"])
            ips = set(normal["source_ip"])

            app_grp = behavior_features[behavior_features["user"] == user]
            app_normal = app_grp[app_grp["is_attack"] == 0] if "is_attack" in app_grp else app_grp
            avg_files = app_normal["files_accessed"].mean() if not app_normal.empty else 0
            avg_access_freq = app_normal["access_frequency_1h"].mean() if not app_normal.empty else 0

            self.profiles[user] = dict(
                hour_min=int(hours.min()) if len(hours) else 9,
                hour_max=int(hours.max()) if len(hours) else 18,
                known_devices=devices,
                known_locations=locations,
                known_ips=ips,
                avg_files_per_event=float(avg_files) if not np.isnan(avg_files) else 0.0,
                avg_access_freq=float(avg_access_freq) if not np.isnan(avg_access_freq) else 0.0,
            )
        return self

    def _deviation_for_row(self, row) -> float:
        user = row.get("user")
        profile = self.profiles.get(user)
        if profile is None:
            return 50.0  # unknown user entirely -> moderate default deviation

        score = 0.0
        # time deviation
        hour = row.get("login_hour", None)
        if hour is not None and not (profile["hour_min"] - 1 <= hour <= profile["hour_max"] + 1):
            score += 30
        # device deviation
        if row.get("device") not in profile["known_devices"] and row.get("device") not in (None, "N/A"):
            score += 25
        # location deviation
        if row.get("location") not in profile["known_locations"] and row.get("location") not in (None, "N/A"):
            score += 20
        # ip deviation
        if row.get("source_ip") not in profile["known_ips"] and row.get("source_ip") not in (None, "N/A"):
            score += 15
        # resource access volume deviation
        files = row.get("files_accessed", 0) or 0
        baseline_files = profile["avg_files_per_event"] or 1
        if baseline_files > 0 and files > baseline_files * 5:
            score += 10

        return float(min(score, 100))

    def score_events(self, df: pd.DataFrame) -> pd.DataFrame:
        out = df.copy()
        out["behavior_deviation"] = out.apply(self._deviation_for_row, axis=1)
        return out
