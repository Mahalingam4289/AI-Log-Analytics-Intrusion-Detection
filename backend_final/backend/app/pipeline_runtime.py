"""
backend/app/pipeline_runtime.py

The real-time counterpart to main.py's batch pipeline. Every event that
arrives from live_source.LiveLogSource is run through the SAME trained
models (anomaly_model.pkl, attack_model.pkl) and the SAME risk formula /
threat categorization / response playbooks used by the batch pipeline —
just incrementally, one event at a time, using backend/app/state.py for
rolling feature windows instead of pandas batch rolling.

Flow per event:
    raw event -> feature dict (state.py) -> anomaly score -> attack
    classification -> behavior deviation -> risk score -> severity/threat
    category -> persist + broadcast -> correlation bucket update

A background sweep task finalizes correlation buckets that have gone
quiet into incidents, generates alerts for anything >= the alert
threshold, runs the (simulated) response engine, persists, and
broadcasts.
"""

import asyncio
import sys
import os
import json
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import pandas as pd

from models.anomaly_detector import FEATURE_COLUMNS
from behavior.behavior_model import BehaviorEngine
from risk.risk_engine import asset_criticality, severity_band, categorize_threat, compute_incident_risk
from risk.mitre_mapping import get_mitre_info
from response.response_engine import RESPONSE_PLAYBOOK
from database.database import append_event, append_incident, append_alert

from .state import StreamState
from .websocket_manager import manager
from .explain import explain_event
from .notifications import send_alert_notification
from .settings_store import settings

CORRELATION_WINDOW_MINUTES = 15
SWEEP_INTERVAL_SECONDS = 15
ALERT_COOLDOWN_MINUTES = 5  # suppress a repeat alert for the same key within this window


class PipelineRuntime:
    def __init__(self, anomaly_model, attack_model, engine, behavior_profiles=None):
        self.anomaly_model = anomaly_model
        self.attack_model = attack_model
        self.engine = engine
        self.state = StreamState()
        if behavior_profiles:
            self.state.behavior_profiles = behavior_profiles
        self._behavior_engine = BehaviorEngine()
        self._behavior_engine.profiles = self.state.behavior_profiles
        self._alert_counter = 0
        self._running = False
        self._last_alert_time = {}  # key -> datetime, for alert cooldown/dedup
        import uuid
        self._run_id = uuid.uuid4().hex[:6]

    # ------------------------------------------------------------ helpers
    def _next_alert_id(self):
        self._alert_counter += 1
        return f"ALT-{self._run_id}-{self._alert_counter:06d}"

    def _feature_row(self, log_source, feats):
        row = {c: 0.0 for c in FEATURE_COLUMNS}
        row.update(feats)
        return row

    def _to_unified(self, raw):
        """Normalize a single raw event (as produced by live_source) into
        the same unified-schema fields the batch pipeline uses."""
        ls = raw["log_source"]
        base = dict(
            event_id=raw["event_id"], timestamp=raw["timestamp"], log_source=ls,
            user=raw.get("user", "unknown"),
            source_ip=raw.get("source_ip", "N/A"),
            destination_ip=raw.get("destination_ip", "N/A"),
            event_type=raw.get("event_type", ls),
            status=raw.get("status", "N/A"),
            device=raw.get("device", "N/A"),
            location=raw.get("location", "N/A"),
            resource=raw.get("resource", "auth_service" if ls == "auth" else ("network" if ls in ("network", "session", "dns", "arp") else "N/A")),
            packet_count=raw.get("packet_count", 0),
            traffic_volume_kb=raw.get("traffic_volume_kb", 0),
            destination_port=raw.get("destination_port", 0),
            files_accessed=raw.get("files_accessed", 0),
            privilege_level=raw.get("privilege_level", "user"),
        )
        # arp events key their identity on "ip" rather than "source_ip"
        if ls == "arp" and raw.get("source_ip") is None:
            base["source_ip"] = raw.get("ip", "N/A")
        if ls == "dns" and raw.get("source_ip") is None:
            base["source_ip"] = raw.get("resolver", "N/A")
        return base

    # ------------------------------------------------------------ core
    async def process_event(self, raw: dict):
        unified = self._to_unified(raw)
        ls = unified["log_source"]
        ts = unified["timestamp"]

        # --- Part B: rule-based checks (IP spoofing, session hijacking,
        # DNS spoofing, ARP spoofing, MITM) — these 5 attacks have no
        # labeled flow-level training data, so they're caught by
        # deterministic rules instead of the ML models. A rule firing
        # takes precedence over the ML path for that same event, since a
        # triggered rule is a certainty, not a probability estimate.
        rule_hit = None  # (attack_type, evidence, risk_hint)
        if ls == "network" and raw.get("ttl") is not None:
            flagged, evidence = self.state.check_ip_spoofing(unified["source_ip"], raw["ttl"], ts)
            if flagged:
                rule_hit = ("ip_spoofing", evidence, 85)
        elif ls == "session":
            flagged, evidence = self.state.check_session_hijack(raw.get("session_id"), unified["source_ip"], ts)
            if flagged:
                rule_hit = ("session_hijacking", evidence, 80)
                self.state.recent_session_hijack_flags.append((ts, evidence))
        elif ls == "dns":
            flagged, evidence = self.state.check_dns_spoofing(raw.get("query_domain"), raw.get("resolved_ip"), ts)
            if flagged:
                rule_hit = ("dns_spoofing", evidence, 85)
        elif ls == "arp":
            flagged, evidence = self.state.check_arp_spoofing(raw.get("ip"), raw.get("mac_address"), ts)
            if flagged:
                rule_hit = ("arp_spoofing", evidence, 75)
                self.state.recent_arp_flags.append((ts, evidence))

        if rule_hit and rule_hit[0] in ("session_hijacking", "arp_spoofing"):
            mitm_flagged, mitm_evidence = self.state.check_mitm(ts)
            if mitm_flagged:
                rule_hit = ("mitm", mitm_evidence, 95)

        if rule_hit is not None:
            predicted_attack_type, evidence_text, risk_hint = rule_hit
            anomaly_score, is_anomaly = float(risk_hint), 1
            attack_probability = 100.0
            behavior_deviation = float(risk_hint)
            feats = {"is_off_hours": 0, "new_device": 0, "ip_deviation": 1}
            feature_row = self._feature_row(ls, feats)
            explanation = [{"feature": "rule_engine", "label": "Rule-based detection",
                             "value": evidence_text, "weight": 1.0}]
        elif ls in ("session", "dns", "arp"):
            # Benign telemetry from the 3 new log sources — nothing fired,
            # log it at zero risk rather than running the ML path (these
            # sources have no ML feature support at all).
            anomaly_score, is_anomaly = 0.0, 0
            predicted_attack_type, attack_probability = "none", 0.0
            behavior_deviation = 0.0
            feats = {}
            feature_row = self._feature_row(ls, feats)
            explanation = []
        else:
            # 1. Feature computation (incremental, per-source) — the
            # existing ML path for auth / network (no TTL flag) / application
            if ls == "auth":
                feats = self.state.compute_auth_features(
                    unified["user"], ts, unified["status"], unified["device"],
                    unified["location"], unified["source_ip"])
            elif ls == "network":
                feats = self.state.compute_network_features(
                    unified["source_ip"], ts, unified["destination_port"], unified["traffic_volume_kb"])
            else:  # application
                feats = self.state.compute_app_features(
                    unified["user"], ts, unified["resource"], unified["files_accessed"], unified["event_type"])

            feature_row = self._feature_row(ls, feats)

            # 2. AI Anomaly Detection
            anomaly_score, is_anomaly = self.anomaly_model.score_one(feature_row)

            # 3. Attack Classification
            predicted_attack_type, attack_probability = self.attack_model.predict_one(feature_row)

            # 4. Behavior Analysis (UEBA)
            behavior_row = dict(user=unified["user"], login_hour=feats.get("login_hour"),
                                 device=unified["device"], location=unified["location"],
                                 source_ip=unified["source_ip"], files_accessed=unified["files_accessed"])
            behavior_deviation = self._behavior_engine._deviation_for_row(behavior_row)
            explanation = explain_event(feature_row, attack_model=self.attack_model)

        # 5. Risk Scoring + Threat Categorization
        asset_crit = asset_criticality(unified["resource"])
        risk_score = round(
            0.40 * anomaly_score + 0.30 * attack_probability +
            0.20 * behavior_deviation + 0.10 * asset_crit, 2)
        severity = severity_band(risk_score)
        threat_category = categorize_threat(dict(
            predicted_attack_type=predicted_attack_type,
            is_off_hours=feats.get("is_off_hours", 0),
            behavior_deviation=behavior_deviation,
            new_device=feats.get("new_device", 0),
            ip_deviation=feats.get("ip_deviation", 0),
        ))

        scored = dict(
            event_id=unified["event_id"], timestamp=ts, log_source=ls,
            user=unified["user"], source_ip=unified["source_ip"],
            destination_ip=unified["destination_ip"], event_type=unified["event_type"],
            resource=unified["resource"], status=unified["status"],
            anomaly_score=round(anomaly_score, 2), is_anomaly=is_anomaly,
            predicted_attack_type=predicted_attack_type,
            attack_probability=round(attack_probability, 2),
            behavior_deviation=round(behavior_deviation, 2),
            risk_score=risk_score, severity=severity, threat_category=threat_category,
            is_attack_ground_truth=None, attack_type_ground_truth=None,
        )
        scored["explanation"] = json.dumps(explanation)
        mitre = get_mitre_info(predicted_attack_type)
        scored["mitre_technique"] = json.dumps(mitre) if mitre else None

        # 6. Persist + broadcast the raw scored event (live feed)
        self.state.total_events += 1
        if is_anomaly:
            self.state.total_anomalies += 1
        if predicted_attack_type != "none":
            self.state.total_attacks += 1
        if severity == "CRITICAL":
            self.state.total_critical += 1

        try:
            append_event(self.engine, scored)
        except Exception as e:
            print(f"[warn] failed to persist event: {e}")

        await manager.broadcast({"type": "event", "data": scored})

        # 7. Correlation
        # NOTE: behavior_deviation defaults to 50 for identity-less network
        # flows (see BehaviorEngine._deviation_for_row) — that default
        # exists to flag genuinely unrecognized *users*, not to describe
        # anonymous network traffic, so it must NOT be used to trigger
        # correlation for network events (matches the batch pipeline,
        # where event_correlator.correlate_events only groups by known
        # users and treats network bursts separately via anomaly/attack
        # signal alone).
        key = unified["user"] if unified["user"] not in ("unknown", "N/A", None) else f"ip:{unified['source_ip']}"
        if ls == "network":
            signal = max(anomaly_score, attack_probability)
        else:
            signal = max(anomaly_score, attack_probability, behavior_deviation)
        if signal >= settings.correlation_signal_threshold:
            bucket = self.state.update_correlation(
                key, unified["event_id"], unified["event_type"], predicted_attack_type,
                unified["source_ip"], ts, anomaly_score, attack_probability, behavior_deviation,
                window_minutes=CORRELATION_WINDOW_MINUTES)
            await manager.broadcast({"type": "incident_update", "data": dict(
                incident_id=bucket.incident_id, key=key, event_count=len(bucket.event_ids),
                max_anomaly_score=bucket.max_anomaly, max_attack_probability=bucket.max_attack_prob,
                max_behavior_deviation=bucket.max_behavior_dev,
                attack_types=",".join(sorted(bucket.attack_types)) or "none",
            )})

        # 8. Periodic stats push
        if self.state.total_events % 10 == 0:
            await manager.broadcast({"type": "stats", "data": self.get_stats()})

    def get_stats(self):
        return dict(
            total_events=self.state.total_events,
            total_anomalies=self.state.total_anomalies,
            total_attacks=self.state.total_attacks,
            total_critical=self.state.total_critical,
            open_incidents=len(self.state.correlation),
        )

    # ------------------------------------------------------------ sweep
    async def finalize_bucket(self, key, bucket):
        user = key if not key.startswith("ip:") else "unknown"
        source_ips = ",".join(sorted(bucket.source_ips)) if bucket.source_ips else (
            key.replace("ip:", "") if key.startswith("ip:") else "")
        incident_row = dict(
            incident_id=bucket.incident_id, user=user,
            start_time=bucket.start_time, end_time=bucket.last_time,
            event_count=len(bucket.event_ids),
            event_chain=" -> ".join(bucket.event_types),
            attack_types=",".join(sorted(bucket.attack_types)) or "none",
            source_ips=source_ips,
            max_anomaly_score=bucket.max_anomaly, max_attack_probability=bucket.max_attack_prob,
            max_behavior_deviation=bucket.max_behavior_dev,
        )
        incident_df = compute_incident_risk(pd.DataFrame([incident_row]))
        incident_final = incident_df.iloc[0].to_dict()

        try:
            append_incident(self.engine, incident_final)
        except Exception as e:
            print(f"[warn] failed to persist incident: {e}")
        await manager.broadcast({"type": "incident_closed", "data": incident_final})

        if incident_final["risk_score"] >= settings.alert_threshold:
            in_cooldown = (
                key in self._last_alert_time and
                (datetime.now() - self._last_alert_time[key]) < timedelta(minutes=ALERT_COOLDOWN_MINUTES)
            )
            if in_cooldown:
                # Same entity already alerted recently — the incident/event
                # data is still persisted above, we just avoid flooding the
                # analyst with a near-duplicate alert for an ongoing burst.
                return
            self._last_alert_time[key] = datetime.now()

            primary_attack_type = incident_final["attack_types"].split(",")[0] if incident_final["attack_types"] != "none" else "none"
            mitre = get_mitre_info(primary_attack_type)

            alert_row = dict(
                alert_id=self._next_alert_id(), source="incident",
                severity=incident_final["severity"], risk_score=incident_final["risk_score"],
                threat_category=incident_final["threat_category"], user=user,
                source_ip=source_ips, timestamp=incident_final["start_time"],
                evidence=incident_final["event_chain"], correlated_events=incident_final["event_count"],
                incident_id=incident_final["incident_id"],
                response_actions="; ".join(RESPONSE_PLAYBOOK.get(incident_final["severity"], ["Log only"])),
                response_status=("SIMULATED - ACTION TAKEN"
                                  if incident_final["severity"] in ("HIGH", "CRITICAL")
                                  else "SIMULATED - QUEUED"),
                status="OPEN", analyst_notes="", notified=0,
                mitre_technique=json.dumps(mitre) if mitre else None,
            )
            if send_alert_notification(alert_row):
                alert_row["notified"] = 1
            try:
                append_alert(self.engine, alert_row)
            except Exception as e:
                print(f"[warn] failed to persist alert: {e}")
            await manager.broadcast({"type": "alert", "data": alert_row})

    async def sweep_loop(self):
        self._running = True
        while self._running:
            await asyncio.sleep(SWEEP_INTERVAL_SECONDS)
            stale = self.state.pop_stale_buckets(datetime.now(), window_minutes=CORRELATION_WINDOW_MINUTES)
            for key, bucket in stale:
                await self.finalize_bucket(key, bucket)

    def stop(self):
        self._running = False
