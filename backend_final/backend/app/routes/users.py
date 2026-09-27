"""backend/app/routes/users.py — per-user/entity activity summary and timeline"""

import json
from fastapi import APIRouter, Request, Query
import pandas as pd

router = APIRouter()


@router.get("/api/users/{entity}/summary")
def user_summary(entity: str, request: Request):
    """A quick profile of one user or source IP: how many events, first/last
    seen, attack type breakdown, and a per-day risk trend — everything an
    analyst needs before opening the full event list for this entity."""
    engine = request.app.state.engine
    query = "SELECT * FROM security_events WHERE user = :entity OR source_ip = :entity ORDER BY timestamp"
    df = pd.read_sql(query, engine, params={"entity": entity}, parse_dates=["timestamp"])

    if df.empty:
        return dict(entity=entity, total_events=0, first_seen=None, last_seen=None,
                    attack_breakdown=[], daily_risk=[], max_risk_score=0, alert_count=0)

    attack_counts = (
        df[df["predicted_attack_type"] != "none"]["predicted_attack_type"]
        .value_counts().reset_index()
    )
    attack_counts.columns = ["attack_type", "count"]

    df["date"] = df["timestamp"].dt.date.astype(str)
    daily = df.groupby("date").agg(avg_risk=("risk_score", "mean"),
                                    max_risk=("risk_score", "max"),
                                    event_count=("event_id", "count")).reset_index()

    alerts_df = pd.read_sql(
        "SELECT COUNT(*) as c FROM alerts WHERE user = :entity OR source_ip = :entity",
        engine, params={"entity": entity})
    alert_count = int(alerts_df["c"].iloc[0]) if not alerts_df.empty else 0

    return dict(
        entity=entity,
        total_events=len(df),
        first_seen=df["timestamp"].min().isoformat(),
        last_seen=df["timestamp"].max().isoformat(),
        max_risk_score=float(df["risk_score"].max()),
        attack_breakdown=json.loads(attack_counts.to_json(orient="records")),
        daily_risk=json.loads(daily.to_json(orient="records")),
        alert_count=alert_count,
    )


@router.get("/api/users/{entity}/events")
def user_events(entity: str, request: Request, limit: int = Query(200, le=2000)):
    engine = request.app.state.engine
    query = ("SELECT * FROM security_events WHERE user = :entity OR source_ip = :entity "
              "ORDER BY timestamp DESC LIMIT :limit")
    df = pd.read_sql(query, engine, params={"entity": entity, "limit": limit})
    return json.loads(df.to_json(orient="records", date_format="iso"))
