"""
anomaly_detector.py — Phase 6: Unsupervised anomaly detection.

Uses Isolation Forest over numeric behavioral/network/auth features to
flag events that deviate from the learned "normal" distribution, WITHOUT
needing attack labels. This is what lets the framework catch previously
unseen attack patterns (Section 3B of the design doc).

Output: anomaly_score in [0, 100] (higher = more anomalous) and a binary
`is_anomaly` flag.
"""

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

FEATURE_COLUMNS = [
    "failed_login_count_10min", "login_frequency_1h", "is_off_hours",
    "new_device", "new_location", "ip_deviation",
    "connection_count_1min", "unique_ports_recent", "traffic_volume_zscore",
    "access_frequency_1h", "files_accessed_zscore", "is_sensitive_resource",
    "privilege_escalation_flag",
]


class AnomalyDetector:
    def __init__(self, contamination=0.08, random_state=42):
        self.model = IsolationForest(
            n_estimators=200, contamination=contamination,
            random_state=random_state, n_jobs=-1,
        )
        self.scaler = StandardScaler()
        self.feature_columns = FEATURE_COLUMNS

    def _prepare(self, df: pd.DataFrame) -> np.ndarray:
        X = df.reindex(columns=self.feature_columns, fill_value=0).fillna(0).to_numpy(dtype=float)
        return X

    def fit(self, df: pd.DataFrame):
        X = self._prepare(df)
        Xs = self.scaler.fit_transform(X)
        self.model.fit(Xs)
        # Store the raw-score range seen during training so that BOTH batch
        # scoring and single-event (real-time/online) scoring normalize to
        # the same 0-100 scale. Without this, scoring one event at a time
        # would always min-max to a degenerate single point.
        raw_scores = -self.model.score_samples(Xs)
        self.score_min = float(raw_scores.min())
        self.score_max = float(raw_scores.max())
        return self

    def score(self, df: pd.DataFrame) -> pd.DataFrame:
        X = self._prepare(df)
        Xs = self.scaler.transform(X)
        raw_scores = -self.model.score_samples(Xs)  # higher = more anomalous
        lo, hi = getattr(self, "score_min", raw_scores.min()), getattr(self, "score_max", raw_scores.max())
        if hi == lo:
            norm = np.zeros_like(raw_scores)
        else:
            norm = np.clip((raw_scores - lo) / (hi - lo) * 100, 0, 100)
        preds = self.model.predict(Xs)  # -1 = anomaly, 1 = normal

        out = df.copy()
        out["anomaly_score"] = norm.round(2)
        out["is_anomaly"] = (preds == -1).astype(int)
        return out

    def score_one(self, feature_dict: dict) -> tuple:
        """Score a single event (used by the real-time streaming pipeline)."""
        row = pd.DataFrame([feature_dict])
        scored = self.score(row)
        return float(scored["anomaly_score"].iloc[0]), int(scored["is_anomaly"].iloc[0])

    def save(self, path):
        joblib.dump({"model": self.model, "scaler": self.scaler,
                     "feature_columns": self.feature_columns,
                     "score_min": getattr(self, "score_min", 0.0),
                     "score_max": getattr(self, "score_max", 1.0)}, path)

    @classmethod
    def load(cls, path):
        obj = joblib.load(path)
        inst = cls()
        inst.model = obj["model"]
        inst.scaler = obj["scaler"]
        inst.feature_columns = obj["feature_columns"]
        inst.score_min = obj.get("score_min", 0.0)
        inst.score_max = obj.get("score_max", 1.0)
        return inst
