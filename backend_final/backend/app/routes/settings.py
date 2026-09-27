"""backend/app/routes/settings.py — GET/PATCH runtime detection settings"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import Optional

from ..auth import get_current_user
from ..settings_store import settings

router = APIRouter()


class SettingsPayload(BaseModel):
    alert_threshold: Optional[float] = None
    correlation_signal_threshold: Optional[float] = None
    notify_min_severity: Optional[str] = None


@router.get("/api/settings")
def get_settings():
    return settings.as_dict()


@router.patch("/api/settings")
def update_settings(payload: SettingsPayload, user: str = Depends(get_current_user)):
    return settings.update(**payload.model_dump(exclude_unset=True))
