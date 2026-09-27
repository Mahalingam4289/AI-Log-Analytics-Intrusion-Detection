"""backend/app/routes/alerts.py — GET /api/alerts, PATCH workflow, CSV export"""

import io
import json
from fastapi import APIRouter, Request, Query, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Optional
import pandas as pd

from ..auth import get_current_user

router = APIRouter()

VALID_STATUSES = {"OPEN", "INVESTIGATING", "CONFIRMED", "FALSE_POSITIVE", "RESOLVED"}


def _build_query(severity, status, user, start_date, end_date, search, limit):
    query = "SELECT * FROM alerts"
    clauses, params = [], {}
    if severity:
        clauses.append("severity = :severity"); params["severity"] = severity
    if status:
        clauses.append("status = :status"); params["status"] = status
    if user:
        clauses.append("user = :user"); params["user"] = user
    if start_date:
        clauses.append("timestamp >= :start_date"); params["start_date"] = start_date
    if end_date:
        clauses.append("timestamp <= :end_date"); params["end_date"] = end_date
    if search:
        clauses.append("(threat_category LIKE :search OR user LIKE :search OR source_ip LIKE :search "
                        "OR evidence LIKE :search)")
        params["search"] = f"%{search}%"
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY timestamp DESC LIMIT :limit"
    params["limit"] = limit
    return query, params


@router.get("/api/alerts")
def get_alerts(request: Request, limit: int = Query(100, le=2000), severity: str = None,
               status: str = None, user: str = None, start_date: str = None,
               end_date: str = None, search: str = None):
    engine = request.app.state.engine
    query, params = _build_query(severity, status, user, start_date, end_date, search, limit)
    try:
        df = pd.read_sql(query, engine, params=params)
    except Exception:
        return []
    return json.loads(df.to_json(orient="records", date_format="iso"))


@router.get("/api/alerts/export.csv")
def export_alerts_csv(request: Request, severity: str = None, status: str = None,
                       start_date: str = None, end_date: str = None):
    engine = request.app.state.engine
    query, params = _build_query(severity, status, None, start_date, end_date, None, 5000)
    try:
        df = pd.read_sql(query, engine, params=params)
    except Exception:
        df = pd.DataFrame()
    buf = io.StringIO()
    df.to_csv(buf, index=False)
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=alerts_export.csv"})


class AlertUpdatePayload(BaseModel):
    status: Optional[str] = None
    analyst_notes: Optional[str] = None


@router.patch("/api/alerts/{alert_id}")
def update_alert(alert_id: str, payload: AlertUpdatePayload, request: Request,
                  user: str = Depends(get_current_user)):
    """Alert lifecycle workflow: analyst sets status (OPEN -> INVESTIGATING ->
    CONFIRMED/FALSE_POSITIVE -> RESOLVED) and optional notes. Requires auth
    so the audit trail (who changed what) is meaningful."""
    if payload.status and payload.status not in VALID_STATUSES:
        raise HTTPException(status_code=400, detail=f"status must be one of {sorted(VALID_STATUSES)}")

    engine = request.app.state.engine
    sets, params = [], {"alert_id": alert_id}
    if payload.status is not None:
        sets.append("status = :status"); params["status"] = payload.status
    if payload.analyst_notes is not None:
        sets.append("analyst_notes = :analyst_notes"); params["analyst_notes"] = payload.analyst_notes
    if not sets:
        raise HTTPException(status_code=400, detail="Nothing to update")

    from sqlalchemy import text
    with engine.begin() as conn:
        result = conn.execute(
            text(f"UPDATE alerts SET {', '.join(sets)} WHERE alert_id = :alert_id"), params)
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"status": "updated", "alert_id": alert_id, "updated_by": user}
