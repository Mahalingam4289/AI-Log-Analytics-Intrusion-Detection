"""
backend/app/websocket_manager.py

Tracks connected WebSocket clients and broadcasts JSON messages to all
of them. Message shapes:

    {"type": "event",    "data": {...scored event...}}
    {"type": "alert",    "data": {...alert...}}
    {"type": "incident_update", "data": {...incident (open)...}}
    {"type": "stats",    "data": {...KPI counters...}}
"""

import json
import asyncio
from fastapi import WebSocket


class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        async with self._lock:
            self.active.append(ws)

    async def disconnect(self, ws: WebSocket):
        async with self._lock:
            if ws in self.active:
                self.active.remove(ws)

    async def broadcast(self, message: dict):
        payload = json.dumps(message, default=str)
        dead = []
        async with self._lock:
            targets = list(self.active)
        for ws in targets:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)
        if dead:
            async with self._lock:
                for ws in dead:
                    if ws in self.active:
                        self.active.remove(ws)


manager = ConnectionManager()
