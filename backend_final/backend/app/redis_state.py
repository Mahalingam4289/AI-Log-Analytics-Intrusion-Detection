"""
backend/app/redis_state.py

Optional Redis-backed persistence for correlation buckets, so open
incidents survive a process restart and can be shared across multiple
backend instances (e.g. behind a load balancer). Purely additive: if
Redis isn't configured or isn't reachable, StreamState falls back to
pure in-memory correlation state with no behavior change — this module
is never required.

Enable with:
    SENTINEL_USE_REDIS=true
    SENTINEL_REDIS_URL=redis://localhost:6379/0   (default)
"""

import os
import json

USE_REDIS = os.environ.get("SENTINEL_USE_REDIS", "false").lower() in ("1", "true", "yes")
REDIS_URL = os.environ.get("SENTINEL_REDIS_URL", "redis://localhost:6379/0")
REDIS_KEY_PREFIX = "sentinel:correlation:"
REDIS_INDEX_KEY = "sentinel:correlation:keys"


def get_redis_client():
    """Returns a connected redis client, or None if Redis is disabled,
    the `redis` package isn't installed, or the server isn't reachable.
    Every call site treats None as 'operate in-memory only'."""
    if not USE_REDIS:
        return None
    try:
        import redis
        client = redis.Redis.from_url(REDIS_URL, decode_responses=True, socket_connect_timeout=1)
        client.ping()
        return client
    except Exception as e:
        print(f"[redis] unavailable, falling back to in-memory correlation state only: {e}")
        return None


def bucket_to_dict(bucket) -> dict:
    return dict(
        incident_id=bucket.incident_id,
        event_ids=bucket.event_ids,
        event_types=bucket.event_types,
        attack_types=list(bucket.attack_types),
        source_ips=list(bucket.source_ips),
        start_time=bucket.start_time.isoformat() if bucket.start_time else None,
        last_time=bucket.last_time.isoformat() if bucket.last_time else None,
        max_anomaly=bucket.max_anomaly,
        max_attack_prob=bucket.max_attack_prob,
        max_behavior_dev=bucket.max_behavior_dev,
    )


def dict_to_bucket(d: dict):
    from datetime import datetime
    from .state import CorrelationBucket
    bucket = CorrelationBucket(d["incident_id"])
    bucket.event_ids = d.get("event_ids", [])
    bucket.event_types = d.get("event_types", [])
    bucket.attack_types = set(d.get("attack_types", []))
    bucket.source_ips = set(d.get("source_ips", []))
    bucket.start_time = datetime.fromisoformat(d["start_time"]) if d.get("start_time") else None
    bucket.last_time = datetime.fromisoformat(d["last_time"]) if d.get("last_time") else None
    bucket.max_anomaly = d.get("max_anomaly", 0.0)
    bucket.max_attack_prob = d.get("max_attack_prob", 0.0)
    bucket.max_behavior_dev = d.get("max_behavior_dev", 0.0)
    return bucket


def save_bucket(client, key, bucket):
    if client is None:
        return
    try:
        client.set(REDIS_KEY_PREFIX + key, json.dumps(bucket_to_dict(bucket)))
        client.sadd(REDIS_INDEX_KEY, key)
    except Exception as e:
        print(f"[redis] save_bucket failed for {key}: {e}")


def delete_bucket(client, key):
    if client is None:
        return
    try:
        client.delete(REDIS_KEY_PREFIX + key)
        client.srem(REDIS_INDEX_KEY, key)
    except Exception as e:
        print(f"[redis] delete_bucket failed for {key}: {e}")


def load_all_buckets(client) -> dict:
    if client is None:
        return {}
    out = {}
    try:
        keys = client.smembers(REDIS_INDEX_KEY)
        for key in keys:
            raw = client.get(REDIS_KEY_PREFIX + key)
            if raw:
                out[key] = dict_to_bucket(json.loads(raw))
    except Exception as e:
        print(f"[redis] load_all_buckets failed: {e}")
    return out
