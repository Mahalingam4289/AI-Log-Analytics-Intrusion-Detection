"""
backend/app/live_source_udp.py

A REAL (not simulated) ingestion connector: an asyncio UDP server that
accepts JSON-encoded log events pushed by an external forwarder — e.g.
rsyslog's omprog/omhttp, a Fluentd/Vector UDP output, a small agent on a
log source, or simply `nc -u` / a test script during development.

This has the exact same async-generator `stream()` interface as
live_source.LiveLogSource, so main.py can select either one via the
SENTINEL_LOG_SOURCE environment variable with zero changes anywhere
else in the pipeline.

Wire format: newline-free UTF-8 JSON per UDP datagram, shaped like:
    {"log_source": "auth", "user": "alice", "source_ip": "10.0.0.5",
     "device": "laptop-1", "location": "Chennai", "event_type": "login",
     "status": "FAILED"}
`timestamp` and `event_id` are filled in on receipt if the sender omits
them, so upstream forwarders don't need to worry about clock sync or ID
uniqueness.

Test it locally with:
    python3 -c "
import socket, json
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(json.dumps({'log_source':'auth','user':'user_001','source_ip':'10.0.0.5',
                      'device':'d1','location':'Chennai','event_type':'login',
                      'status':'FAILED'}).encode(), ('127.0.0.1', 9999))
"
"""

import asyncio
import json
import itertools
from datetime import datetime, timezone


class _UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, queue: asyncio.Queue):
        self.queue = queue

    def datagram_received(self, data, addr):
        try:
            payload = json.loads(data.decode("utf-8"))
            self.queue.put_nowait(payload)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            print(f"[udp_source] dropped malformed datagram from {addr}: {e}")


class UDPLogSource:
    """Drop-in replacement for LiveLogSource that ingests real events
    pushed over UDP instead of generating synthetic ones."""

    def __init__(self, host="0.0.0.0", port=9999):
        self.host = host
        self.port = port
        self._queue: asyncio.Queue = asyncio.Queue()
        self._stop = False
        self._transport = None
        self._counter = itertools.count(1)
        import uuid
        self._run_id = uuid.uuid4().hex[:6]
        # Kept for interface parity with LiveLogSource — a UDP feed's
        # rate is whatever senders push, not something we control here.
        self.events_per_second = None

    def set_rate(self, events_per_second: float):
        pass  # not meaningful for a push-based source; kept for interface parity

    def stop(self):
        self._stop = True
        if self._transport:
            self._transport.close()

    async def _ensure_listening(self):
        if self._transport is not None:
            return
        loop = asyncio.get_running_loop()
        self._transport, _ = await loop.create_datagram_endpoint(
            lambda: _UDPProtocol(self._queue), local_addr=(self.host, self.port))
        print(f"[udp_source] listening for log events on udp://{self.host}:{self.port}")

    def _normalize(self, payload: dict) -> dict:
        payload.setdefault("event_id", f"UDP-{self._run_id}-{next(self._counter):07d}")
        payload.setdefault("timestamp", datetime.now(timezone.utc).replace(tzinfo=None))
        if isinstance(payload.get("timestamp"), str):
            try:
                payload["timestamp"] = datetime.fromisoformat(payload["timestamp"])
            except ValueError:
                payload["timestamp"] = datetime.now(timezone.utc).replace(tzinfo=None)
        payload.setdefault("log_source", "application")
        return payload

    async def stream(self):
        await self._ensure_listening()
        while not self._stop:
            payload = await self._queue.get()
            yield self._normalize(payload)
