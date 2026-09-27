"""
attack_classifier.py — Phase 7: Supervised attack classification.

A Random Forest classifier trained on labeled events predicts a specific
attack category (brute_force, probe, dos, privilege_escalation,
data_exfiltration, account_compromise, insider_threat, none) plus an
`attack_probability` (max class probability among attack classes) used
later by the Risk Engine.
"""

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

from .anomaly_detector import FEATURE_COLUMNS


class AttackClassifier:
    def __init__(self, random_state=42):
        self.model = RandomForestClassifier(
            n_estimators=300, max_depth=12, random_state=random_state,
            class_weight="balanced", n_jobs=-1,
        )
        self.label_encoder = LabelEncoder()
        self.feature_columns = FEATURE_COLUMNS

    def _prepare(self, df: pd.DataFrame) -> np.ndarray:
        return df.reindex(columns=self.feature_columns, fill_value=0).fillna(0).to_numpy(dtype=float)

    def fit(self, df: pd.DataFrame, label_col="attack_type"):
        X = self._prepare(df)
        y = self.label_encoder.fit_transform(df[label_col])
        self.model.fit(X, y)
        return self

    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        X = self._prepare(df)
        proba = self.model.predict_proba(X)
        pred_idx = proba.argmax(axis=1)
        pred_labels = self.label_encoder.inverse_transform(pred_idx)

        classes = list(self.label_encoder.classes_)
        none_idx = classes.index("none") if "none" in classes else None
        if none_idx is not None:
            attack_prob = 1 - proba[:, none_idx]
        else:
            attack_prob = proba.max(axis=1)

        out = df.copy()
        out["predicted_attack_type"] = pred_labels
        out["attack_probability"] = (attack_prob * 100).round(2)
        return out

    def predict_one(self, feature_dict: dict) -> tuple:
        """Predict a single event (used by the real-time streaming pipeline)."""
        row = pd.DataFrame([feature_dict])
        scored = self.predict(row)
        return str(scored["predicted_attack_type"].iloc[0]), float(scored["attack_probability"].iloc[0])

    def save(self, path):
        joblib.dump({"model": self.model, "label_encoder": self.label_encoder,
                     "feature_columns": self.feature_columns}, path)

    @classmethod
    def load(cls, path):
        obj = joblib.load(path)
        inst = cls()
        inst.model = obj["model"]
        inst.label_encoder = obj["label_encoder"]
        inst.feature_columns = obj["feature_columns"]
        return inst
