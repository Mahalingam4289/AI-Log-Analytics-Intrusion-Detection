"""
backend/app/state.py

Holds all IN-MEMORY rolling state needed to compute the same features as
features/auth_features.py, features/network_features.py, and
features/behavior_features.py — but incrementally, one event at a time,
instead of as a pandas batch job. This is what makes real-time scoring
possible: every new event updates a small rolling window per user /
per source-IP, and the current feature values are read off that window.

This state is intentionally in-process (a dict of deques). For a
multi-instance production deployment you would back this with Redis
(sorted sets per user/IP keyed by timestamp) — the interface below is
written so that swap is a drop-in replacement.
"""

from collections import deque, defaultdict
from datetime import timedelta
import statistics

SENSITIVE_RESOURCES = {"finance_db", "customer_data", "source_code_repo", "admin_console"}


class UserAuthState:
    __slots__ = ("failed_ts", "login_ts", "devices", "locations", "ips")

    def __init__(self):
        self.failed_ts = deque()
        self.login_ts = deque()
        self.devices = set()
        self.locations = set()
        self.ips = set()


class NetIPState:
    __slots__ = ("conn_ts", "recent_ports", "recent_volumes")

    def __init__(self):
        self.conn_ts = deque()
        self.recent_ports = deque(maxlen=50)
        self.recent_volumes = deque(maxlen=50)


class AppUserState:
    __slots__ = ("access_ts", "recent_files")

    def __init__(self):
        self.access_ts = deque()
        self.recent_files = deque(maxlen=20)


class CorrelationBucket:
    __slots__ = ("event_ids", "event_types", "attack_types", "source_ips",
                 "start_time", "last_time", "max_anomaly", "max_attack_prob",
                 "max_behavior_dev", "incident_id")

    def __init__(self, incident_id):
        self.incident_id = incident_id
        self.event_ids = []
        self.event_types = []
        self.attack_types = set()
        self.source_ips = set()
        self.start_time = None
        self.last_time = None
        self.max_anomaly = 0.0
        self.max_attack_prob = 0.0
        self.max_behavior_dev = 0.0


class StreamState:
    """Aggregates all rolling state used by the real-time pipeline."""

    def __init__(self):
        self.auth = defaultdict(UserAuthState)
        self.net = defaultdict(NetIPState)
        self.app = defaultdict(AppUserState)

        # --- Part B: rolling state for the 5 rule-based detectors ---
        self.ip_ttl_baseline = {}                          # ip -> established TTL
        self.session_ips = defaultdict(dict)                # session_id -> {ip: last_seen_ts}
        self.dns_known_ips = defaultdict(set)                # domain -> set of historically-seen IPs
        self.arp_established_mac = {}                        # ip -> established MAC
        self.recent_session_hijack_flags = deque(maxlen=50)  # for MITM temporal correlation
        self.recent_arp_flags = deque(maxlen=50)

        # UEBA baseline profiles, seeded from historical batch data at
        # startup by behavior/behavior_model.BehaviorEngine, then read here.
        self.behavior_profiles = {}

        # Correlation state, keyed by "user" for auth/app events and by
        # "ip:<source_ip>" for user-less network events. Kept as a local
        # in-memory dict for fast reads always; optionally mirrored to
        # Redis (see redis_state.py) so buckets survive a restart or can
        # be shared across instances. Redis is entirely optional — if
        # disabled/unavailable, behavior is identical to pure in-memory.
        from .redis_state import get_redis_client, load_all_buckets
        self._redis = get_redis_client()
        self.correlation = load_all_buckets(self._redis) if self._redis else {}
        self._incident_counter = 0
        import uuid
        self._run_id = uuid.uuid4().hex[:6]

        # Simple in-memory counters for fast KPI reads without hitting DB.
        self.total_events = 0
        self.total_anomalies = 0
        self.total_attacks = 0
        self.total_critical = 0

    # ---------------------------------------------------------- Auth
    def compute_auth_features(self, user, ts, status, device, location, source_ip):
        st = self.auth[user]
        window_10 = ts - timedelta(minutes=10)
        window_60 = ts - timedelta(minutes=60)

        if status == "FAILED":
            st.failed_ts.append(ts)
        st.login_ts.append(ts)

        while st.failed_ts and st.failed_ts[0] < window_10:
            st.failed_ts.popleft()
        while st.login_ts and st.login_ts[0] < window_60:
            st.login_ts.popleft()

        new_device = int(device not in st.devices)
        new_location = int(location not in st.locations)
        ip_deviation = int(source_ip not in st.ips)
        st.devices.add(device)
        st.locations.add(location)
        st.ips.add(source_ip)

        hour = ts.hour
        is_off_hours = int(hour < 6 or hour > 22)

        return dict(
            failed_login_count_10min=float(len(st.failed_ts)),
            login_frequency_1h=float(len(st.login_ts)),
            is_off_hours=is_off_hours,
            new_device=new_device,
            new_location=new_location,
            ip_deviation=ip_deviation,
            login_hour=hour,
        )

    # ---------------------------------------------------------- Network
    def compute_network_features(self, source_ip, ts, destination_port, traffic_volume_kb):
        st = self.net[source_ip]
        window_1min = ts - timedelta(minutes=1)

        st.conn_ts.append(ts)
        while st.conn_ts and st.conn_ts[0] < window_1min:
            st.conn_ts.popleft()

        # Use a realistic prior (typical benign traffic ~1-500kb) instead of
        # mean=0/std=1 so a source IP seen for the first time doesn't get a
        # wildly inflated z-score that falsely looks like a DoS burst.
        if st.recent_volumes:
            mean = statistics.mean(st.recent_volumes)
            std = statistics.pstdev(st.recent_volumes) if len(st.recent_volumes) > 1 else 60.0
            std = std if std > 0 else 60.0
        else:
            mean, std = 120.0, 60.0
        z = (traffic_volume_kb - mean) / std

        st.recent_ports.append(destination_port)
        st.recent_volumes.append(traffic_volume_kb)

        return dict(
            connection_count_1min=float(len(st.conn_ts)),
            unique_ports_recent=float(len(set(st.recent_ports))),
            traffic_volume_zscore=float(z),
        )

    # ---------------------------------------------------------- Application
    def compute_app_features(self, user, ts, resource, files_accessed, event_type):
        st = self.app[user]
        window_60 = ts - timedelta(minutes=60)
        st.access_ts.append(ts)
        while st.access_ts and st.access_ts[0] < window_60:
            st.access_ts.popleft()

        mean = statistics.mean(st.recent_files) if st.recent_files else 0.0
        std = statistics.pstdev(st.recent_files) if len(st.recent_files) > 1 else 1.0
        std = std if std > 0 else 1.0
        z = (files_accessed - mean) / std
        st.recent_files.append(files_accessed)

        return dict(
            access_frequency_1h=float(len(st.access_ts)),
            files_accessed_zscore=float(z),
            is_sensitive_resource=int(resource in SENSITIVE_RESOURCES),
            privilege_escalation_flag=int(event_type == "privilege_escalation"),
        )

    # ---------------------------------------------------------- Correlation
    def next_incident_id(self):
        self._incident_counter += 1
        return f"INC-{self._run_id}-{self._incident_counter:06d}"

    def update_correlation(self, key, event_id, event_type, attack_type, source_ip,
                            ts, anomaly_score, attack_prob, behavior_dev, window_minutes=15):
        bucket = self.correlation.get(key)
        if bucket is not None and (ts - bucket.last_time) > timedelta(minutes=window_minutes):
            # stale -> start fresh, caller is responsible for having already
            # finalized/persisted the old bucket before calling this again
            bucket = None

        if bucket is None:
            bucket = CorrelationBucket(self.next_incident_id())
            bucket.start_time = ts
            self.correlation[key] = bucket

        bucket.event_ids.append(event_id)
        bucket.event_types.append(event_type)
        if attack_type and attack_type != "none":
            bucket.attack_types.add(attack_type)
        if source_ip and source_ip not in ("N/A", "unknown"):
            bucket.source_ips.add(source_ip)
        bucket.last_time = ts
        bucket.max_anomaly = max(bucket.max_anomaly, anomaly_score)
        bucket.max_attack_prob = max(bucket.max_attack_prob, attack_prob)
        bucket.max_behavior_dev = max(bucket.max_behavior_dev, behavior_dev)

        if self._redis is not None:
            from .redis_state import save_bucket
            save_bucket(self._redis, key, bucket)

        return bucket

    def pop_stale_buckets(self, now, window_minutes=15):
        """Return and remove buckets that have gone quiet, so they can be
        finalized into an incident + alert by the caller."""
        stale_keys = [k for k, b in self.correlation.items()
                      if (now - b.last_time) > timedelta(minutes=window_minutes)]
        stale = []
        for k in stale_keys:
            stale.append((k, self.correlation.pop(k)))
            if self._redis is not None:
                from .redis_state import delete_bucket
                delete_bucket(self._redis, k)
        return stale

    # -------------------------------------------------- Part B: rule checks
    # Same detection logic as rules/*.py, adapted to run incrementally on a
    # single incoming event instead of a full historical DataFrame.

    def check_ip_spoofing(self, ip, ttl, ts):
        baseline = self.ip_ttl_baseline.get(ip)
        self.ip_ttl_baseline[ip] = ttl if baseline is None else (baseline * 0.9 + ttl * 0.1)
        if baseline is not None and abs(ttl - baseline) >= 15:
            return True, f"TTL={ttl} deviates {abs(ttl-baseline):.0f} hops from {ip}'s baseline ({baseline:.0f})"
        return False, None

    def check_session_hijack(self, session_id, ip, ts, window_minutes=15):
        seen = self.session_ips[session_id]
        if seen and ip not in seen:
            first_ip, first_ts = next(iter(seen.items()))
            gap = ts - min(seen.values())
            if gap <= timedelta(minutes=window_minutes):
                seen[ip] = ts
                return True, f"session {session_id} used from new IP {ip}, {gap.total_seconds()/60:.1f} min after {first_ip}"
        seen[ip] = ts
        return False, None

    def check_dns_spoofing(self, domain, resolved_ip, ts, min_history=5):
        known = self.dns_known_ips[domain]
        if len(known) >= min_history and resolved_ip not in known:
            evidence = f"{domain} resolved to {resolved_ip}, outside its established set {sorted(known)}"
            return True, evidence
        known.add(resolved_ip)
        return False, None

    def check_arp_spoofing(self, ip, mac, ts):
        established = self.arp_established_mac.get(ip)
        if established is not None and mac != established:
            self.arp_established_mac[ip] = mac
            return True, f"{ip} now claims MAC {mac}, was previously {established} (possible ARP cache poisoning, precursor to sniffing)"
        self.arp_established_mac[ip] = mac
        return False, None

    def check_mitm(self, ts, window_minutes=20):
        """Fires only when a session-hijack flag and an ARP-spoof flag both
        occurred within the correlation window of each other — MITM is
        never detected directly, only inferred from this overlap."""
        for sh_ts, sh_evidence in list(self.recent_session_hijack_flags):
            for arp_ts, arp_evidence in list(self.recent_arp_flags):
                if abs((sh_ts - arp_ts).total_seconds()) <= window_minutes * 60:
                    return True, f"session hijacking ({sh_evidence}) co-occurred with ARP spoofing ({arp_evidence})"
        return False, None
