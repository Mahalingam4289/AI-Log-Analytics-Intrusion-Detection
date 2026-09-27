"""
backend/app/main.py — FastAPI real-time security analytics service.

Run with:
    uvicorn backend.app.main:app --reload --port 8000

Responsibilities:
    - On startup: ensure a trained anomaly model + attack classifier exist
      (bootstrapping them from the batch pipeline the first time), build
      the UEBA behavior baseline, and start the live event stream +
      correlation-sweep background tasks.
    - Serve REST endpoints for historical query (events/incidents/alerts/stats).
    - Serve a WebSocket (/ws/live) that pushes every scored event, alert,
      and incident update to connected dashboard clients in real time.
    - Expose stream control endpoints (start/stop/speed) so the frontend
      can pause/resume/adjust the simulated live feed.
"""

import os
import sys
import asyncio
import subprocess
from contextlib import asynccontextmanager

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, BASE_DIR)

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends
from fastapi.middleware.cors import CORSMiddleware
import pandas as pd

from models.anomaly_detector import AnomalyDetector
from models.attack_classifier import AttackClassifier
from behavior.behavior_model import BehaviorEngine
from features.auth_features import compute_auth_features
from features.behavior_features import compute_behavior_features
from preprocessing.log_parser import load_all_logs
from preprocessing.normalizer import build_unified_events
from database.database import setup_database

from .live_source import LiveLogSource
from .live_source_udp import UDPLogSource
from .pipeline_runtime import PipelineRuntime
from .websocket_manager import manager
from .auth import get_current_user, verify_ws_token
from .routes import events, incidents, alerts, stats, stream, auth as auth_routes, settings as settings_routes, users

MODEL_DIR = os.path.join(BASE_DIR, "saved_models")
DATA_DIR = os.path.join(BASE_DIR, "data")
ANOMALY_MODEL_PATH = os.path.join(MODEL_DIR, "anomaly_model.pkl")
ATTACK_MODEL_PATH = os.path.join(MODEL_DIR, "attack_model.pkl")
LOG_SOURCE_MODE = os.environ.get("SENTINEL_LOG_SOURCE", "simulated").lower()  # "simulated" | "udp"
REQUIRE_AUTH = os.environ.get("SENTINEL_REQUIRE_AUTH", "true").lower() in ("1", "true", "yes")


def _ensure_dataset_exists():
    """The UEBA baseline (_build_behavior_profiles) needs the historical
    CSVs on every startup, not just when training — so this check is
    separate from, and always runs before, the model-training check
    below. Without this, deleting saved_models/*.pkl but not data/*.csv
    (or vice versa, as happens when packaging a lean deliverable) would
    silently crash startup."""
    if not os.path.exists(os.path.join(DATA_DIR, "auth_logs.csv")):
        print("[bootstrap] No dataset found — generating synthetic logs...")
        subprocess.run([sys.executable, os.path.join(DATA_DIR, "generate_dataset.py")], check=True)


def _bootstrap_models_if_missing():
    """First-run only: trains the anomaly + attack models from the batch
    pipeline (main.py) so the API has something to load. In a real
    deployment this training would run offline / on a schedule against a
    data warehouse, not inside the API process."""
    if os.path.exists(ANOMALY_MODEL_PATH) and os.path.exists(ATTACK_MODEL_PATH):
        return
    print("[bootstrap] No trained models found — running batch pipeline once to train them...")
    subprocess.run([sys.executable, os.path.join(BASE_DIR, "main.py")], check=True)
    print("[bootstrap] Models trained and saved.")


def _build_behavior_profiles():
    """Builds the UEBA baseline from the historical batch logs, the same
    way main.py does, so the live pipeline starts with realistic 'normal'
    profiles instead of an empty state."""
    auth_df, net_df, app_df = load_all_logs(
        os.path.join(DATA_DIR, "auth_logs.csv"),
        os.path.join(DATA_DIR, "network_logs.csv"),
        os.path.join(DATA_DIR, "application_logs.csv"),
    )
    unified = build_unified_events(auth_df, net_df, app_df)
    auth_feat = compute_auth_features(unified)
    behav_feat = compute_behavior_features(unified)
    engine_be = BehaviorEngine()
    engine_be.build_baseline(auth_feat, behav_feat)
    return engine_be.profiles


def _seed_stream_state(runtime, live_source):
    """Cold-start fix: without this, every user's FIRST login event in the
    live stream would look like a brand new device/location/IP (the
    in-memory state starts empty), producing a burst of false 'new
    device' / 'ip deviation' signals the moment the server boots. Seed
    each user's known device/location/IP directly from the live source's
    own identity maps (the 'home' device/IP it will actually emit for
    normal logins) so the pipeline starts already warmed up — matching a
    real deployment where the UEBA baseline reflects weeks of prior
    history for the SAME identities the live feed uses."""
    from .live_source import USERS, HOME_IP, HOME_LOCATION, DEVICES
    for user in USERS:
        st = runtime.state.auth[user]
        st.devices.add(DEVICES[user][0])
        st.locations.add(HOME_LOCATION[user])
        st.ips.add(HOME_IP[user])


@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- startup ---
    _ensure_dataset_exists()
    _bootstrap_models_if_missing()

    anomaly_model = AnomalyDetector.load(ANOMALY_MODEL_PATH)
    attack_model = AttackClassifier.load(ATTACK_MODEL_PATH)
    behavior_profiles = _build_behavior_profiles()

    db_engine = setup_database(f"sqlite:///{os.path.join(BASE_DIR, 'database', 'security_analytics.db')}")

    runtime = PipelineRuntime(anomaly_model, attack_model, db_engine, behavior_profiles)

    if LOG_SOURCE_MODE == "udp":
        udp_port = int(os.environ.get("SENTINEL_UDP_PORT", 9999))
        live_source = UDPLogSource(port=udp_port)
        print(f"[startup] Using REAL UDP log ingestion on port {udp_port} "
              f"(set SENTINEL_LOG_SOURCE=simulated to go back to the demo feed).")
    else:
        live_source = LiveLogSource(events_per_second=4.0, attack_probability=0.02)
        _seed_stream_state(runtime, live_source)

    app.state.runtime = runtime
    app.state.engine = db_engine
    app.state.live_source = live_source
    app.state.stream_task = None

    async def run_stream():
        async for raw_event in live_source.stream():
            try:
                await runtime.process_event(raw_event)
            except Exception as e:
                print(f"[error] pipeline failed on event: {e}")

    app.state.run_stream = run_stream
    app.state.stream_task = asyncio.create_task(run_stream())
    app.state.sweep_task = asyncio.create_task(runtime.sweep_loop())
    print("[startup] Real-time pipeline is live. Connect to ws://<host>:8000/ws/live")

    yield

    # --- shutdown ---
    app.state.live_source.stop()
    app.state.runtime.stop()


app = FastAPI(title="AI Security Log Analytics API", version="1.1", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten to your frontend origin in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Login is always public; everything else requires a bearer token unless
# SENTINEL_REQUIRE_AUTH=false (handy for local development).
_auth_dep = [Depends(get_current_user)] if REQUIRE_AUTH else []

app.include_router(auth_routes.router)
app.include_router(events.router, dependencies=_auth_dep)
app.include_router(incidents.router, dependencies=_auth_dep)
app.include_router(alerts.router, dependencies=_auth_dep)
app.include_router(stats.router, dependencies=_auth_dep)
app.include_router(stream.router, dependencies=_auth_dep)
app.include_router(settings_routes.router, dependencies=_auth_dep)
app.include_router(users.router, dependencies=_auth_dep)


@app.websocket("/ws/live")
async def websocket_endpoint(ws: WebSocket, token: str = None):
    if REQUIRE_AUTH and not verify_ws_token(token or ""):
        await ws.close(code=4401)  # policy violation / unauthorized
        return
    await manager.connect(ws)
    try:
        # send an initial snapshot so a freshly-connected dashboard isn't empty
        await ws.send_json({"type": "stats", "data": app.state.runtime.get_stats()})
        while True:
            await ws.receive_text()  # client doesn't need to send anything; keeps the socket alive
    except WebSocketDisconnect:
        await manager.disconnect(ws)


@app.get("/api/health")
def health():
    return {"status": "ok"}
