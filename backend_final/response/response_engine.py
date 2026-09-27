"""
response_engine.py — Phase 13: Automated Response (SIMULATED ONLY)

Per Section 9 of the design document, no real infrastructure action is
taken. This module only records what a real SOAR platform WOULD do, so
the detect -> decide -> respond pipeline can be demonstrated safely.
"""

import pandas as pd

RESPONSE_PLAYBOOK = {
    "CRITICAL": ["Simulate: Block source IP", "Simulate: Disable user account",
                 "Simulate: Terminate active session", "Simulate: Revoke auth token",
                 "Notify: Security administrator (urgent)"],
    "HIGH": ["Simulate: Terminate active session", "Simulate: Force re-authentication",
             "Notify: Security administrator"],
    "MEDIUM": ["Simulate: Flag account for review", "Notify: SOC analyst (queued)"],
    "LOW": ["Log only: monitor for recurrence"],
}


def simulate_response(alerts_df: pd.DataFrame) -> pd.DataFrame:
    if alerts_df.empty:
        return alerts_df.assign(response_actions=[])
    out = alerts_df.copy()
    out["response_actions"] = out["severity"].map(
        lambda s: "; ".join(RESPONSE_PLAYBOOK.get(s, ["Log only"])))
    out["response_status"] = out["severity"].map(
        lambda s: "SIMULATED - ACTION TAKEN" if s in ("HIGH", "CRITICAL") else "SIMULATED - QUEUED")
    return out
