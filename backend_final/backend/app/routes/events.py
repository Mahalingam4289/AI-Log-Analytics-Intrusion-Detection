"""backend/app/routes/events.py — GET /api/events, CSV export"""

import io
import json
from fastapi import APIRouter, Request, Query
from fastapi.responses import StreamingResponse
import pandas as pd

router = APIRouter()


def _build_query(severity, log_source, user, start_date, end_date, search, limit):
    query = "SELECT * FROM security_events"
    clauses, params = [], {}
    if severity:
        clauses.append("severity = :severity"); params["severity"] = severity
    if log_source:
        clauses.append("log_source = :log_source"); params["log_source"] = log_source
    if user:
        clauses.append("user = :user"); params["user"] = user
    if start_date:
        clauses.append("timestamp >= :start_date"); params["start_date"] = start_date
    if end_date:
        clauses.append("timestamp <= :end_date"); params["end_date"] = end_date
    if search:
        clauses.append("(user LIKE :search OR source_ip LIKE :search OR threat_category LIKE :search "
                        "OR predicted_attack_type LIKE :search)")
        params["search"] = f"%{search}%"
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY timestamp DESC LIMIT :limit"
    params["limit"] = limit
    return query, params


@router.get("/api/events")
def get_events(request: Request, limit: int = Query(100, le=2000), severity: str = None,
               log_source: str = None, user: str = None, start_date: str = None,
               end_date: str = None, search: str = None):
    engine = request.app.state.engine
    query, params = _build_query(severity, log_source, user, start_date, end_date, search, limit)
    df = pd.read_sql(query, engine, params=params)
    return json.loads(df.to_json(orient="records", date_format="iso"))


@router.get("/api/events/export.csv")
def export_events_csv(request: Request, severity: str = None, log_source: str = None,
                       start_date: str = None, end_date: str = None):
    engine = request.app.state.engine
    query, params = _build_query(severity, log_source, None, start_date, end_date, None, 10000)
    try:
        df = pd.read_sql(query, engine, params=params)
    except Exception:
        df = pd.DataFrame()
    buf = io.StringIO()
    df.to_csv(buf, index=False)
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=events_export.csv"})
