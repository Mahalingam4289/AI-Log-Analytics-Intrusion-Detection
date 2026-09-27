"""
backend/app/live_source.py

Simulates a REAL-TIME multi-surface log feed: one event at a time,
continuously, mixed across auth / network / application sources, with
occasional injected attack bursts (brute force, port scan, DoS,
privilege escalation + exfiltration) so the live demo has something to
detect.

This is the ONLY module you need to replace to plug in a real feed:
    - Kafka: iterate a consumer.poll() loop and yield each decoded message
    - Syslog: run an asyncio UDP/TCP server and yield each parsed line
    - Cloud provider APIs: poll on an interval and yield each new record

Everything downstream (pipeline_runtime.py) consumes plain dicts shaped
like the ones yielded here, so it doesn't know or care where they came
from.
"""

import asyncio
import random
from datetime import datetime, timezone

RNG = random.Random(7)

USERS = [f"user_{i:03d}" for i in range(1, 41)]
LOCATIONS = ["Chennai", "Vellore", "Bangalore", "Mumbai", "Delhi", "Unknown"]
DEVICES = {u: [f"device_{u[-3:]}_{d}" for d in range(2)] for u in USERS}
RESOURCES = ["reports_db", "hr_portal", "finance_db", "customer_data",
             "source_code_repo", "email_server", "billing_system", "admin_console"]
SENSITIVE_RESOURCES = {"finance_db", "customer_data", "source_code_repo", "admin_console"}
PROTOCOLS = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS"]
COMMON_PORTS = [80, 443, 22, 3389, 53, 8080]
SCAN_PORTS = list(range(1, 1025))

HOME_IP = {u: f"10.0.{RNG.randint(0, 4)}.{RNG.randint(1, 254)}" for u in USERS}
HOME_LOCATION = {u: RNG.choice(LOCATIONS[:-1]) for u in USERS}
HOST_TTL = {}  # ip -> stable TTL, established lazily
KNOWN_DOMAINS = ["intranet.corp.local", "mail.corp.local", "vpn.corp.local", "billing.corp.local"]


def _host_ttl(ip):
    HOST_TTL.setdefault(ip, int(RNG.choice([64, 128])))
    return HOST_TTL[ip] - int(RNG.randint(0, 2))


def _rand_ip(internal=True):
    if internal:
        return f"10.0.{RNG.randint(0, 4)}.{RNG.randint(1, 254)}"
    return f"{RNG.randint(1, 223)}.{RNG.randint(0, 255)}.{RNG.randint(0, 255)}.{RNG.randint(1, 254)}"


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


DOMAIN_HOME_IP = {d: _rand_ip(True) for d in KNOWN_DOMAINS}


class LiveLogSource:
    """Async generator of raw log events at a configurable rate, with a
    background chance of an attack burst on every "tick"."""

    def __init__(self, events_per_second: float = 4.0, attack_probability: float = 0.02):
        self.events_per_second = max(0.2, events_per_second)
        self.attack_probability = attack_probability
        self._event_counter = 0
        # A short random prefix unique to this process run, so restarting
        # the server doesn't regenerate the exact same sequential event_ids
        # as a previous run still sitting in the database (which would
        # fail on the event_id UNIQUE constraint and silently drop events).
        import uuid
        self._run_id = uuid.uuid4().hex[:6]
        self._stop = False

    def set_rate(self, events_per_second: float):
        self.events_per_second = max(0.2, events_per_second)

    def stop(self):
        self._stop = True

    def _next_id(self):
        self._event_counter += 1
        return f"EVT-{self._run_id}-{self._event_counter:07d}"

    # ---------------------------------------------------------- normal
    def _normal_auth_event(self):
        user = RNG.choice(USERS)
        return dict(
            event_id=self._next_id(), timestamp=_now(), log_source="auth",
            user=user, source_ip=HOME_IP[user], device=DEVICES[user][0],
            location=HOME_LOCATION[user], event_type="login", status="SUCCESS",
        )

    def _normal_network_event(self):
        src_ip = _rand_ip(True)
        return dict(
            event_id=self._next_id(), timestamp=_now(), log_source="network",
            source_ip=src_ip, destination_ip=_rand_ip(True),
            destination_port=RNG.choice(COMMON_PORTS), protocol=RNG.choice(PROTOCOLS),
            packet_count=RNG.randint(5, 200), traffic_volume_kb=RNG.uniform(1, 500),
            ttl=_host_ttl(src_ip),
        )

    def _normal_session_event(self):
        user = RNG.choice(USERS)
        return dict(
            event_id=self._next_id(), timestamp=_now(), log_source="session",
            session_id=f"SESS-{RNG.randint(100000, 999999)}", user=user,
            source_ip=HOME_IP[user], action="page_view",
        )

    def _normal_dns_event(self):
        domain = RNG.choice(KNOWN_DOMAINS)
        return dict(
            event_id=self._next_id(), timestamp=_now(), log_source="dns",
            query_domain=domain, resolved_ip=DOMAIN_HOME_IP[domain], resolver="10.0.0.2",
        )

    def _normal_arp_event(self):
        ip = _rand_ip(True)
        HOST_TTL.setdefault(ip, 64)  # ensure host exists in some tracking dict
        return dict(
            event_id=self._next_id(), timestamp=_now(), log_source="arp",
            ip=ip, mac_address=f"{RNG.randint(0,255):02x}:aa:bb:cc:dd:{RNG.randint(0,255):02x}",
        )

    def _normal_app_event(self):
        user = RNG.choice(USERS)
        return dict(
            event_id=self._next_id(), timestamp=_now(), log_source="application",
            user=user, resource=RNG.choice(RESOURCES), event_type="read",
            files_accessed=RNG.randint(1, 10), privilege_level="user",
        )

    def _normal_event(self):
        r = RNG.random()
        if r < 0.30:
            return self._normal_auth_event()
        elif r < 0.60:
            return self._normal_network_event()
        elif r < 0.75:
            return self._normal_app_event()
        elif r < 0.85:
            return self._normal_session_event()
        elif r < 0.93:
            return self._normal_dns_event()
        return self._normal_arp_event()

    # ---------------------------------------------------------- attacks
    def _brute_force_burst(self):
        user = RNG.choice(USERS)
        attacker_ip = _rand_ip(False)
        events = []
        n_fail = RNG.randint(6, 18)
        for _ in range(n_fail):
            events.append(dict(
                event_id=self._next_id(), timestamp=_now(), log_source="auth",
                user=user, source_ip=attacker_ip, device="unknown_device",
                location="Unknown", event_type="login", status="FAILED",
            ))
        events.append(dict(
            event_id=self._next_id(), timestamp=_now(), log_source="auth",
            user=user, source_ip=attacker_ip, device="unknown_device",
            location="Unknown", event_type="login", status="SUCCESS",
        ))
        # follow-up: escalation + exfiltration to sell the "compromised account" story
        events.append(dict(
            event_id=self._next_id(), timestamp=_now(), log_source="application",
            user=user, resource="admin_console", event_type="privilege_escalation",
            files_accessed=0, privilege_level="admin",
        ))
        events.append(dict(
            event_id=self._next_id(), timestamp=_now(), log_source="application",
            user=user, resource=RNG.choice(list(SENSITIVE_RESOURCES)), event_type="download",
            files_accessed=RNG.randint(200, 800), privilege_level="admin",
        ))
        return events

    def _port_scan_burst(self):
        attacker_ip = _rand_ip(False)
        target_ip = _rand_ip(True)
        ports = RNG.sample(SCAN_PORTS, RNG.randint(40, 120))
        return [dict(
            event_id=self._next_id(), timestamp=_now(), log_source="network",
            source_ip=attacker_ip, destination_ip=target_ip, destination_port=p,
            protocol="TCP", packet_count=RNG.randint(1, 3), traffic_volume_kb=RNG.uniform(0.1, 2),
        ) for p in ports]

    def _dos_burst(self):
        attacker_ip = _rand_ip(False)
        target_ip = _rand_ip(True)
        n = RNG.randint(60, 150)
        return [dict(
            event_id=self._next_id(), timestamp=_now(), log_source="network",
            source_ip=attacker_ip, destination_ip=target_ip, destination_port=80,
            protocol="TCP", packet_count=RNG.randint(500, 3000), traffic_volume_kb=RNG.uniform(500, 5000),
        ) for _ in range(n)]

    def _insider_burst(self):
        user = RNG.choice(USERS)
        return [dict(
            event_id=self._next_id(), timestamp=_now(), log_source="auth",
            user=user, source_ip=HOME_IP[user], device=DEVICES[user][0],
            location=HOME_LOCATION[user], event_type="login", status="SUCCESS",
        ), dict(
            event_id=self._next_id(), timestamp=_now(), log_source="application",
            user=user, resource=RNG.choice(list(SENSITIVE_RESOURCES)), event_type="download",
            files_accessed=RNG.randint(150, 400), privilege_level="user",
        )]

    # -------------------------------------------------- Part B: 5 new attacks
    def _ip_spoofing_burst(self):
        """Forge a trusted internal IP's address, but the real hop
        distance shows up as a very different TTL than that host's
        established baseline."""
        victim_ip = RNG.choice(list(HOST_TTL.keys())) if HOST_TTL else _rand_ip(True)
        real_ttl = HOST_TTL.get(victim_ip, 64)
        spoofed_ttl = max(real_ttl - int(RNG.randint(20, 39)), 1)
        return [dict(
            event_id=self._next_id(), timestamp=_now(), log_source="network",
            source_ip=victim_ip, destination_ip=_rand_ip(True),
            destination_port=RNG.choice(COMMON_PORTS), protocol="TCP",
            packet_count=RNG.randint(5, 50), traffic_volume_kb=RNG.uniform(1, 100),
            ttl=spoofed_ttl,
        ) for _ in range(RNG.randint(3, 7))]

    def _session_hijack_burst(self):
        """A legitimate session, then the SAME session_id replayed from a
        completely different (attacker) IP minutes later."""
        user = RNG.choice(USERS)
        session_id = f"SESS-{RNG.randint(100000, 999999)}"
        legit_ip = HOME_IP[user]
        attacker_ip = _rand_ip(False)
        return [
            dict(event_id=self._next_id(), timestamp=_now(), log_source="session",
                 session_id=session_id, user=user, source_ip=legit_ip, action="login"),
            dict(event_id=self._next_id(), timestamp=_now(), log_source="session",
                 session_id=session_id, user=user, source_ip=attacker_ip, action="download"),
        ]

    def _dns_spoofing_burst(self):
        """A known internal domain suddenly resolves to a rogue,
        attacker-controlled IP outside its established range."""
        domain = RNG.choice(KNOWN_DOMAINS)
        rogue_ip = _rand_ip(False)
        return [dict(
            event_id=self._next_id(), timestamp=_now(), log_source="dns",
            query_domain=domain, resolved_ip=rogue_ip, resolver="10.0.0.2",
        ) for _ in range(RNG.randint(2, 4))]

    def _arp_spoofing_burst(self):
        """A new MAC address suddenly claims an IP that already has an
        established MAC — classic ARP cache poisoning."""
        victim_ip = _rand_ip(True)
        rogue_mac = f"{RNG.randint(0,255):02x}:ff:ff:ff:ff:{RNG.randint(0,255):02x}"
        return [dict(
            event_id=self._next_id(), timestamp=_now(), log_source="arp",
            ip=victim_ip, mac_address=rogue_mac,
        ) for _ in range(RNG.randint(3, 6))]

    def _mitm_burst(self):
        """The compound scenario: session hijacking and ARP spoofing
        happening close together in time for the correlator to catch."""
        return self._session_hijack_burst() + self._arp_spoofing_burst()

    async def stream(self):
        """Async generator yielding one raw event dict at a time forever
        (until .stop() is called)."""
        while not self._stop:
            delay = 1.0 / self.events_per_second
            if RNG.random() < self.attack_probability:
                burst_type = RNG.choice([
                    "brute_force", "port_scan", "dos", "insider",
                    "ip_spoofing", "session_hijacking", "dns_spoofing", "arp_spoofing", "mitm",
                ])
                burst = {
                    "brute_force": self._brute_force_burst,
                    "port_scan": self._port_scan_burst,
                    "dos": self._dos_burst,
                    "insider": self._insider_burst,
                    "ip_spoofing": self._ip_spoofing_burst,
                    "session_hijacking": self._session_hijack_burst,
                    "dns_spoofing": self._dns_spoofing_burst,
                    "arp_spoofing": self._arp_spoofing_burst,
                    "mitm": self._mitm_burst,
                }[burst_type]()
                for ev in burst:
                    yield ev
                    await asyncio.sleep(delay / 4)  # bursts arrive faster than normal traffic
            else:
                yield self._normal_event()
                await asyncio.sleep(delay)
