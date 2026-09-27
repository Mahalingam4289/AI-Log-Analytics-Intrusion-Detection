"""
backend/app/settings_store.py

Runtime-adjustable detection thresholds, so an analyst can tune
sensitivity from the dashboard instead of editing source and
restarting. Deliberately a simple in-memory object — for a
multi-instance deployment, back this with the same Redis instance used
for correlation state (see state.py).
"""

from alerts.alert_manager import ALERT_THRESHOLD as DEFAULT_ALERT_THRESHOLD

DEFAULT_CORRELATION_THRESHOLD = 40


class SettingsStore:
    def __init__(self):
        self.alert_threshold = DEFAULT_ALERT_THRESHOLD
        self.correlation_signal_threshold = DEFAULT_CORRELATION_THRESHOLD
        self.notify_min_severity = "CRITICAL"

    def as_dict(self):
        return dict(
            alert_threshold=self.alert_threshold,
            correlation_signal_threshold=self.correlation_signal_threshold,
            notify_min_severity=self.notify_min_severity,
        )

    def update(self, **kwargs):
        for k, v in kwargs.items():
            if v is not None and hasattr(self, k):
                setattr(self, k, v)
        return self.as_dict()


settings = SettingsStore()
