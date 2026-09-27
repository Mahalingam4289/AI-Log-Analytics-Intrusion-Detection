"""backend/app/routes/incidents.py — GET /api/incidents"""

import json
from fastapi import APIRouter, Request, Query
import pandas as pd

router = APIRouter()


@router.get("/api/incidents")
def get_incidents(request: Request, limit: int = Query(100, le=1000)):
    engine = request.app.state.engine
    try:
        df = pd.read_sql(
            "SELECT * FROM incidents ORDER BY start_time DESC LIMIT :limit",
            engine, params={"limit": limit})
    except Exception:
        return []
    return json.loads(df.to_json(orient="records", date_format="iso"))


@router.get("/api/incidents/open")
def get_open_incidents(request: Request):
    runtime = request.app.state.runtime
    out = []
    for key, bucket in runtime.state.correlation.items():
        out.append(dict(
            incident_id=bucket.incident_id, key=key,
            event_count=len(bucket.event_ids),
            attack_types=",".join(sorted(bucket.attack_types)) or "none",
            source_ips=",".join(sorted(bucket.source_ips)),
            start_time=bucket.start_time, last_time=bucket.last_time,
            max_anomaly_score=bucket.max_anomaly,
            max_attack_probability=bucket.max_attack_prob,
            max_behavior_deviation=bucket.max_behavior_dev,
        ))
    return out
