"""backend/app/routes/stats.py — GET /api/stats, /api/stats/timeline, /api/stats/distribution"""

from fastapi import APIRouter, Request
import pandas as pd

router = APIRouter()


@router.get("/api/stats")
def get_stats(request: Request):
    runtime = request.app.state.runtime
    return runtime.get_stats()


@router.get("/api/stats/severity-distribution")
def severity_distribution(request: Request):
    engine = request.app.state.engine
    try:
        df = pd.read_sql("SELECT severity, COUNT(*) as count FROM security_events GROUP BY severity", engine)
    except Exception:
        return []
    order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    df["order"] = df["severity"].map(order)
    df = df.sort_values("order").drop(columns="order")
    return df.to_dict(orient="records")


@router.get("/api/stats/attack-distribution")
def attack_distribution(request: Request):
    engine = request.app.state.engine
    try:
        df = pd.read_sql(
            "SELECT predicted_attack_type, COUNT(*) as count FROM security_events "
            "WHERE predicted_attack_type != 'none' GROUP BY predicted_attack_type", engine)
    except Exception:
        return []
    return df.to_dict(orient="records")


@router.get("/api/stats/timeline")
def timeline(request: Request, minutes: int = 30):
    engine = request.app.state.engine
    try:
        df = pd.read_sql(
            "SELECT timestamp, risk_score, severity, predicted_attack_type FROM security_events "
            "ORDER BY timestamp DESC LIMIT 500", engine, parse_dates=["timestamp"])
    except Exception:
        return []
    if df.empty:
        return []
    df = df.sort_values("timestamp")
    df["bucket"] = df["timestamp"].dt.floor("min")
    grouped = df.groupby("bucket").agg(
        avg_risk=("risk_score", "mean"),
        attack_count=("predicted_attack_type", lambda s: (s != "none").sum()),
        event_count=("risk_score", "count"),
    ).reset_index()
    return grouped.to_dict(orient="records")
