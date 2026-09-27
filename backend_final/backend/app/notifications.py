"""
backend/app/notifications.py

Sends a webhook notification (Slack-compatible payload shape, works with
Slack, Discord-via-adapter, or any endpoint that accepts a JSON `text`
field / Microsoft Teams connector) when a CRITICAL (or configurably
HIGH+) alert fires. No-ops cleanly if no webhook URL is configured, so
this is always safe to leave wired in.

Configure via environment variables:
    SENTINEL_WEBHOOK_URL         e.g. a Slack Incoming Webhook URL
    SENTINEL_NOTIFY_MIN_SEVERITY default "CRITICAL" (or "HIGH")
"""

import os
import json
import urllib.request
import urllib.error

WEBHOOK_URL = os.environ.get("SENTINEL_WEBHOOK_URL", "").strip()
MIN_SEVERITY = os.environ.get("SENTINEL_NOTIFY_MIN_SEVERITY", "CRITICAL")

SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def should_notify(severity: str) -> bool:
    if not WEBHOOK_URL:
        return False
    return SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK.get(MIN_SEVERITY, 3)


def send_alert_notification(alert: dict) -> bool:
    """Fire-and-forget style webhook POST. Returns True if a send was
    attempted successfully (2xx), False otherwise (including when no
    webhook is configured — that's a normal, silent no-op)."""
    if not should_notify(alert.get("severity", "LOW")):
        return False

    text = (
        f":rotating_light: *{alert.get('severity')}* alert — {alert.get('threat_category')}\n"
        f"User/Entity: `{alert.get('user')}`  Source IP: `{alert.get('source_ip')}`\n"
        f"Risk score: {alert.get('risk_score')}/100\n"
        f"Evidence: {alert.get('evidence')}\n"
        f"Simulated response: {alert.get('response_actions')}"
    )
    body = json.dumps({"text": text}).encode("utf-8")
    req = urllib.request.Request(
        WEBHOOK_URL, data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return 200 <= resp.status < 300
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
        print(f"[notify] webhook send failed: {e}")
        return False
