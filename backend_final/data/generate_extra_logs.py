"""
data/generate_extra_logs.py — Part B: log sources for the 5 rule-based
detectors (IP spoofing, session hijacking, DNS spoofing, ARP spoofing as
a sniffing proxy, and MITM as a compound of the last two).

These attacks are NOT well represented in any public flow-based dataset
(NSL-KDD, CICIDS2017, UNSW-NB15) — they need session/DNS/ARP-level data
that simply doesn't exist in network-flow captures. This generator
produces the same kind of realistic-but-synthetic logs as the original
data/generate_dataset.py, clearly labeled as such, specifically for the
5 attacks that have no real public dataset equivalent.
"""

import numpy as np
import pandas as pd
from datetime import datetime, timedelta
import os

RNG = np.random.default_rng(11)
OUT_DIR = os.path.dirname(os.path.abspath(__file__))
START = datetime(2026, 8, 1, 0, 0, 0)
N_USERS = 40
USERS = [f"user_{i:03d}" for i in range(1, N_USERS + 1)]
KNOWN_DOMAINS = ["intranet.corp.local", "mail.corp.local", "vpn.corp.local",
                  "billing.corp.local", "hr.corp.local"]


def _rand_ip(internal=True):
    if internal:
        return f"10.0.{RNG.integers(0, 5)}.{RNG.integers(1, 254)}"
    return f"{RNG.integers(1, 223)}.{RNG.integers(0, 255)}.{RNG.integers(0, 255)}.{RNG.integers(1, 254)}"


def _rand_mac():
    return ":".join(f"{RNG.integers(0, 256):02x}" for _ in range(6))


# --------------------------------------------------------------------
# 1. NETWORK LOGS WITH TTL (for IP spoofing detection)
# --------------------------------------------------------------------
def generate_network_ttl_logs():
    """Extends plain network flow logs with a TTL field. Genuine hosts on
    the same subnet have a stable, narrow TTL range; a spoofed packet
    forging a trusted internal IP typically arrives with a TTL that
    doesn't match that host's real hop distance."""
    rows = []
    host_normal_ttl = {}

    for _ in range(6000):
        day = int(RNG.integers(0, 14))
        ts = START + timedelta(days=day, seconds=int(RNG.integers(0, 86400)))
        src_ip = _rand_ip(True)
        host_normal_ttl.setdefault(src_ip, int(RNG.choice([64, 128])))
        ttl = host_normal_ttl[src_ip] - int(RNG.integers(0, 3))  # small natural jitter
        rows.append(dict(
            timestamp=ts, source_ip=src_ip, destination_ip=_rand_ip(True),
            ttl=ttl, is_attack=0, attack_type="none",
        ))

    # Inject IP spoofing: attacker forges a trusted internal IP's address,
    # but the packet's actual TTL reveals a different real hop distance.
    for _ in range(10):
        day = int(RNG.integers(0, 14))
        base_ts = START + timedelta(days=day, seconds=int(RNG.integers(0, 86400)))
        victim_ip = RNG.choice(list(host_normal_ttl.keys())) if host_normal_ttl else _rand_ip(True)
        real_ttl = host_normal_ttl.get(victim_ip, 64)
        spoofed_ttl = real_ttl - int(RNG.integers(20, 40))  # arrives from much farther away
        for i in range(RNG.integers(5, 15)):
            rows.append(dict(
                timestamp=base_ts + timedelta(seconds=int(i)), source_ip=victim_ip,
                destination_ip=_rand_ip(True), ttl=max(spoofed_ttl, 1),
                is_attack=1, attack_type="ip_spoofing",
            ))

    return pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)


# --------------------------------------------------------------------
# 2. SESSION LOGS (for session hijacking detection)
# --------------------------------------------------------------------
def generate_session_logs():
    rows = []
    session_counter = 0

    for user in USERS:
        for day in range(14):
            if RNG.random() > 0.6:
                continue
            session_counter += 1
            session_id = f"SESS-{session_counter:06d}"
            ip = _rand_ip(True)
            n_actions = int(RNG.integers(2, 8))
            for a in range(n_actions):
                ts = START + timedelta(days=day, hours=int(RNG.integers(9, 18)), minutes=a * 3)
                rows.append(dict(
                    timestamp=ts, session_id=session_id, user=user, source_ip=ip,
                    action="page_view", is_attack=0, attack_type="none",
                ))

    # Inject session hijacking: the SAME session_id observed from a
    # second, different IP shortly after the legitimate one — a stolen
    # cookie/session token being replayed by an attacker.
    for _ in range(8):
        user = RNG.choice(USERS)
        session_counter += 1
        session_id = f"SESS-{session_counter:06d}"
        day = int(RNG.integers(2, 13))
        legit_ip = _rand_ip(True)
        attacker_ip = _rand_ip(False)
        base_ts = START + timedelta(days=day, hours=int(RNG.integers(9, 18)))
        rows.append(dict(timestamp=base_ts, session_id=session_id, user=user,
                          source_ip=legit_ip, action="login", is_attack=0, attack_type="none"))
        rows.append(dict(timestamp=base_ts + timedelta(minutes=2), session_id=session_id, user=user,
                          source_ip=legit_ip, action="page_view", is_attack=0, attack_type="none"))
        # hijacked replay from a different IP just minutes later
        rows.append(dict(timestamp=base_ts + timedelta(minutes=4), session_id=session_id, user=user,
                          source_ip=attacker_ip, action="page_view",
                          is_attack=1, attack_type="session_hijacking"))
        rows.append(dict(timestamp=base_ts + timedelta(minutes=5), session_id=session_id, user=user,
                          source_ip=attacker_ip, action="download",
                          is_attack=1, attack_type="session_hijacking"))

    return pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)


# --------------------------------------------------------------------
# 3. DNS LOGS (for DNS spoofing / cache poisoning detection)
# --------------------------------------------------------------------
def generate_dns_logs():
    rows = []
    domain_home_ip = {d: _rand_ip(True) for d in KNOWN_DOMAINS}

    for _ in range(8000):
        day = int(RNG.integers(0, 14))
        ts = START + timedelta(days=day, seconds=int(RNG.integers(0, 86400)))
        domain = RNG.choice(KNOWN_DOMAINS)
        rows.append(dict(
            timestamp=ts, query_domain=domain, resolved_ip=domain_home_ip[domain],
            resolver="10.0.0.2", is_attack=0, attack_type="none",
        ))

    # Inject DNS spoofing / cache poisoning: a well-known internal domain
    # suddenly resolves to a completely different (attacker-controlled)
    # IP outside its established range.
    for _ in range(8):
        day = int(RNG.integers(2, 13))
        base_ts = START + timedelta(days=day, seconds=int(RNG.integers(0, 86400)))
        domain = RNG.choice(KNOWN_DOMAINS)
        rogue_ip = _rand_ip(False)
        for i in range(RNG.integers(3, 8)):
            rows.append(dict(
                timestamp=base_ts + timedelta(seconds=i * 5), query_domain=domain,
                resolved_ip=rogue_ip, resolver="10.0.0.2",
                is_attack=1, attack_type="dns_spoofing",
            ))

    return pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)


# --------------------------------------------------------------------
# 4. ARP LOGS (proxy signal for network sniffing via ARP cache poisoning)
# --------------------------------------------------------------------
def generate_arp_logs():
    """ARP spoofing is the standard real-world *precursor* to sniffing on
    a switched network — sniffing itself is passive and leaves no log
    trace, so this is the honest, detectable proxy signal, documented as
    such rather than oversold as 'sniffing detected'."""
    rows = []
    ip_mac = {}

    for _ in range(6000):
        day = int(RNG.integers(0, 14))
        ts = START + timedelta(days=day, seconds=int(RNG.integers(0, 86400)))
        ip = _rand_ip(True)
        ip_mac.setdefault(ip, _rand_mac())
        rows.append(dict(timestamp=ts, ip=ip, mac_address=ip_mac[ip],
                          is_attack=0, attack_type="none"))

    # Inject ARP spoofing: the attacker's MAC suddenly claims an IP
    # (often the gateway) that already has a different, established MAC —
    # classic ARP cache poisoning to intercept traffic.
    for _ in range(8):
        day = int(RNG.integers(2, 13))
        base_ts = START + timedelta(days=day, seconds=int(RNG.integers(0, 86400)))
        victim_ip = RNG.choice(list(ip_mac.keys()))
        attacker_mac = _rand_mac()
        for i in range(RNG.integers(4, 10)):
            rows.append(dict(
                timestamp=base_ts + timedelta(seconds=i * 2), ip=victim_ip,
                mac_address=attacker_mac, is_attack=1, attack_type="arp_spoofing",
            ))

    return pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)


def main():
    net_ttl = generate_network_ttl_logs()
    session = generate_session_logs()
    dns = generate_dns_logs()
    arp = generate_arp_logs()

    # Explicit MITM demonstration scenarios: deliberately co-locate a
    # session-hijacking event and an ARP-spoofing event in time for the
    # same attacker, so rules.mitm's compound detector (which looks for
    # temporal overlap between the two) has real cases to catch. Without
    # this, two independently-random attack injections would only
    # co-occur by chance.
    mitm_rows_session, mitm_rows_arp = [], []
    for _ in range(3):
        user = RNG.choice(USERS)
        day = int(RNG.integers(2, 13))
        base_ts = START + timedelta(days=day, hours=int(RNG.integers(9, 18)))
        session_id = f"SESS-MITM-{RNG.integers(10000, 99999)}"
        legit_ip = _rand_ip(True)
        attacker_ip = _rand_ip(False)
        attacker_mac = _rand_mac()
        victim_gateway_ip = _rand_ip(True)

        mitm_rows_session.append(dict(timestamp=base_ts, session_id=session_id, user=user,
                                       source_ip=legit_ip, action="login", is_attack=0, attack_type="none"))
        mitm_rows_arp.append(dict(timestamp=base_ts + timedelta(minutes=1), ip=victim_gateway_ip,
                                   mac_address=attacker_mac, is_attack=1, attack_type="arp_spoofing"))
        mitm_rows_session.append(dict(timestamp=base_ts + timedelta(minutes=3), session_id=session_id,
                                       user=user, source_ip=attacker_ip, action="download",
                                       is_attack=1, attack_type="session_hijacking"))

    session = pd.concat([session, pd.DataFrame(mitm_rows_session)], ignore_index=True).sort_values("timestamp")
    arp = pd.concat([arp, pd.DataFrame(mitm_rows_arp)], ignore_index=True).sort_values("timestamp")

    net_ttl.to_csv(os.path.join(OUT_DIR, "network_ttl_logs.csv"), index=False)
    session.to_csv(os.path.join(OUT_DIR, "session_logs.csv"), index=False)
    dns.to_csv(os.path.join(OUT_DIR, "dns_logs.csv"), index=False)
    arp.to_csv(os.path.join(OUT_DIR, "arp_logs.csv"), index=False)

    print(f"network_ttl_logs.csv : {len(net_ttl):,} rows ({net_ttl.is_attack.sum()} ip_spoofing events)")
    print(f"session_logs.csv     : {len(session):,} rows ({session.is_attack.sum()} session_hijacking events)")
    print(f"dns_logs.csv         : {len(dns):,} rows ({dns.is_attack.sum()} dns_spoofing events)")
    print(f"arp_logs.csv         : {len(arp):,} rows ({arp.is_attack.sum()} arp_spoofing events, "
          f"3 of which are explicit MITM demonstration scenarios)")


if __name__ == "__main__":
    main()
