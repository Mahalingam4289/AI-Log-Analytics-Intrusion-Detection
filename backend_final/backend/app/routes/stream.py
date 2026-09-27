"""backend/app/routes/stream.py — control the simulated real-time feed"""

from fastapi import APIRouter, Request
from pydantic import BaseModel

router = APIRouter()


class SpeedPayload(BaseModel):
    events_per_second: float


@router.get("/api/stream/status")
def stream_status(request: Request):
    source = request.app.state.live_source
    task = request.app.state.stream_task
    return dict(
        running=bool(task and not task.done()),
        events_per_second=source.events_per_second if source.events_per_second is not None else 0,
        mode="udp" if source.events_per_second is None else "simulated",
    )


@router.post("/api/stream/start")
async def stream_start(request: Request):
    app_state = request.app.state
    if app_state.stream_task is None or app_state.stream_task.done():
        app_state.live_source._stop = False
        import asyncio
        app_state.stream_task = asyncio.create_task(app_state.run_stream())
    return {"status": "started"}


@router.post("/api/stream/stop")
async def stream_stop(request: Request):
    request.app.state.live_source.stop()
    return {"status": "stopping"}


@router.post("/api/stream/speed")
def stream_speed(request: Request, payload: SpeedPayload):
    request.app.state.live_source.set_rate(payload.events_per_second)
    return {"status": "ok", "events_per_second": payload.events_per_second}
