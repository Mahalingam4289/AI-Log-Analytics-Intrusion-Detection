"""
normalizer.py — Stage 3 (part 2): Normalization
Maps auth / network / application logs, which have different native
schemas, into ONE unified security-event schema so downstream feature
engineering and models don't need to know the source type.

Unified schema:
    timestamp, log_source, user, source_ip, destination_ip, event_type,
    protocol, status, device, resource, location, extra (dict of
    source-specific fields), is_attack, attack_type
"""

import pandas as pd
from .cleaner import clean_dataframe

UNIFIED_COLS = [
    "timestamp", "log_source", "user", "source_ip", "destination_ip",
    "event_type", "protocol", "status", "device", "resource", "location",
    "packet_count", "traffic_volume_kb", "destination_port",
    "files_accessed", "privilege_level", "is_attack", "attack_type",
]


def _empty_unified(n):
    return pd.DataFrame({c: [None] * n for c in UNIFIED_COLS})


def normalize_auth(df: pd.DataFrame) -> pd.DataFrame:
    df = clean_dataframe(df, required_cols=["timestamp", "user"])
    out = _empty_unified(len(df))
    out["timestamp"] = df["timestamp"]
    out["log_source"] = "auth"
    out["user"] = df["user"]
    out["source_ip"] = df["source_ip"]
    out["destination_ip"] = "internal_auth_server"
    out["event_type"] = df["event_type"]
    out["protocol"] = df.get("auth_method", "password")
    out["status"] = df["status"]
    out["device"] = df["device"]
    out["resource"] = "auth_service"
    out["location"] = df["location"]
    out["is_attack"] = df["is_attack"]
    out["attack_type"] = df["attack_type"]
    return out


def normalize_network(df: pd.DataFrame) -> pd.DataFrame:
    df = clean_dataframe(df, required_cols=["timestamp", "source_ip"])
    out = _empty_unified(len(df))
    out["timestamp"] = df["timestamp"]
    out["log_source"] = "network"
    out["user"] = "unknown"
    out["source_ip"] = df["source_ip"]
    out["destination_ip"] = df["destination_ip"]
    out["event_type"] = "network_flow"
    out["protocol"] = df["protocol"]
    out["status"] = "N/A"
    out["device"] = "N/A"
    out["resource"] = "network"
    out["location"] = "N/A"
    out["packet_count"] = df["packet_count"]
    out["traffic_volume_kb"] = df["traffic_volume_kb"]
    out["destination_port"] = df["destination_port"]
    out["is_attack"] = df["is_attack"]
    out["attack_type"] = df["attack_type"]
    return out


def normalize_application(df: pd.DataFrame) -> pd.DataFrame:
    df = clean_dataframe(df, required_cols=["timestamp", "user"])
    out = _empty_unified(len(df))
    out["timestamp"] = df["timestamp"]
    out["log_source"] = "application"
    out["user"] = df["user"]
    out["source_ip"] = "N/A"
    out["destination_ip"] = "N/A"
    out["event_type"] = df["action"]
    out["protocol"] = "N/A"
    out["status"] = "N/A"
    out["device"] = "N/A"
    out["resource"] = df["resource"]
    out["location"] = "N/A"
    out["files_accessed"] = df["files_accessed"]
    out["privilege_level"] = df["privilege_level"]
    out["is_attack"] = df["is_attack"]
    out["attack_type"] = df["attack_type"]
    return out


def build_unified_events(auth_df, net_df, app_df) -> pd.DataFrame:
    unified = pd.concat([
        normalize_auth(auth_df),
        normalize_network(net_df),
        normalize_application(app_df),
    ], ignore_index=True)

    numeric_fill = ["packet_count", "traffic_volume_kb", "destination_port", "files_accessed"]
    for c in numeric_fill:
        unified[c] = pd.to_numeric(unified[c], errors="coerce").fillna(0)

    unified["is_attack"] = pd.to_numeric(unified["is_attack"], errors="coerce").fillna(0).astype(int)
    unified["attack_type"] = unified["attack_type"].fillna("none")
    unified = unified.sort_values("timestamp").reset_index(drop=True)
    unified["event_id"] = unified.index.astype(str).map(lambda i: f"EVT-{int(i):07d}")
    return unified
