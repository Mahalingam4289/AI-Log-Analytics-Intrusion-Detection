"""
generate_dataset.py
--------------------
Generates synthetic (but realistic-structured) security logs for the
AI-Driven Multi-Surface Log Analytics & Behavioral Intrusion Detection
prototype.

Three log sources are produced, matching Stage 1 of the architecture:
    1. auth_logs.csv       -> authentication events (login/logout, success/fail)
    2. network_logs.csv    -> network flow events (ports, protocols, traffic volume)
    3. application_logs.csv-> application/system events (resource access, errors)

A mix of NORMAL behavior and INJECTED ATTACKS is generated so that both the
supervised attack classifier and the unsupervised anomaly detector have
signal to learn from:

    - Brute force login attacks (many failed logins -> 1 success)
    - Port scanning / probing
    - DoS (denial of service) traffic bursts
    - Privilege escalation + sensitive resource access
    - Data exfiltration (large downloads)
    - Insider-style abnormal-hour access

Every event carries an `is_attack` ground-truth label and an `attack_type`
label so Phase 16 (evaluation) can compute precision/recall/F1/ROC-AUC.
Ground truth is used ONLY for training/evaluation -- the detection engine
itself does not see these columns at inference time.
"""

import numpy as np
import pandas as pd
from datetime import datetime, timedelta
import os

RNG = np.random.default_rng(42)

N_USERS = 40
N_DEVICES_PER_USER = 2
SIM_DAYS = 14
OUT_DIR = os.path.dirname(os.path.abspath(__file__))

USERS = [f"user_{i:03d}" for i in range(1, N_USERS + 1)]
LOCATIONS = ["Chennai", "Vellore", "Bangalore", "Mumbai", "Delhi", "Unknown"]
DEVICES = {u: [f"device_{u[-3:]}_{d}" for d in range(N_DEVICES_PER_USER)] for u in USERS}
RESOURCES = ["reports_db", "hr_portal", "finance_db", "customer_data",
             "source_code_repo", "email_server", "billing_system", "admin_console"]
SENSITIVE_RESOURCES = {"finance_db", "customer_data", "source_code_repo", "admin_console"}
PROTOCOLS = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS"]
COMMON_PORTS = [80, 443, 22, 3389, 53, 8080]
SCAN_PORTS = list(range(1, 1025))

START = datetime(2026, 8, 1, 0, 0, 0)


def rand_ip(internal=True):
    if internal:
        return f"10.0.{RNG.integers(0, 5)}.{RNG.integers(1, 254)}"
    return f"{RNG.integers(1, 223)}.{RNG.integers(0, 255)}.{RNG.integers(0, 255)}.{RNG.integers(1, 254)}"


# --------------------------------------------------------------------------
# 1. AUTHENTICATION LOGS
# --------------------------------------------------------------------------
def generate_auth_logs():
    rows = []
    for user in USERS:
        home_ip = rand_ip(internal=True)
        home_device = DEVICES[user][0]
        home_location = RNG.choice(LOCATIONS[:-1])
        for day in range(SIM_DAYS):
            # normal daily login pattern (working hours, own device/ip)
            n_logins = RNG.integers(1, 4)
            for _ in range(n_logins):
                hour = RNG.integers(9, 18)
                minute = RNG.integers(0, 59)
                ts = START + timedelta(days=day, hours=int(hour), minutes=int(minute))
                rows.append(dict(
                    timestamp=ts, user=user, source_ip=home_ip,
                    device=home_device, location=home_location,
                    event_type="login", auth_method="password",
                    status="SUCCESS", is_attack=0, attack_type="none"
                ))

    # ---- Inject brute force + account compromise scenarios ----
    n_bruteforce = 10
    victims = RNG.choice(USERS, size=n_bruteforce, replace=False)
    for user in victims:
        day = int(RNG.integers(2, SIM_DAYS - 1))
        hour = int(RNG.integers(0, 4))  # unusual hour
        ts = START + timedelta(days=day, hours=hour, minutes=int(RNG.integers(0, 59)))
        attacker_ip = rand_ip(internal=False)
        n_fail = int(RNG.integers(6, 25))
        for i in range(n_fail):
            rows.append(dict(
                timestamp=ts + timedelta(seconds=i * 3), user=user, source_ip=attacker_ip,
                device="unknown_device", location="Unknown",
                event_type="login", auth_method="password",
                status="FAILED", is_attack=1, attack_type="brute_force"
            ))
        # eventual successful breach
        rows.append(dict(
            timestamp=ts + timedelta(seconds=n_fail * 3 + 5), user=user, source_ip=attacker_ip,
            device="unknown_device", location="Unknown",
            event_type="login", auth_method="password",
            status="SUCCESS", is_attack=1, attack_type="account_compromise"
        ))

    # ---- Insider-style abnormal access (legit device, odd hour, many resources) ----
    n_insider = 5
    insiders = RNG.choice(USERS, size=n_insider, replace=False)
    for user in insiders:
        day = int(RNG.integers(2, SIM_DAYS - 1))
        hour = int(RNG.integers(1, 5))
        ts = START + timedelta(days=day, hours=hour)
        rows.append(dict(
            timestamp=ts, user=user, source_ip=rand_ip(internal=True),
            device=DEVICES[user][0], location=RNG.choice(LOCATIONS[:-1]),
            event_type="login", auth_method="password",
            status="SUCCESS", is_attack=1, attack_type="insider_threat"
        ))

    df = pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)
    return df


# --------------------------------------------------------------------------
# 2. NETWORK LOGS
# --------------------------------------------------------------------------
def generate_network_logs():
    rows = []
    # normal background traffic
    for _ in range(4000):
        day = int(RNG.integers(0, SIM_DAYS))
        ts = START + timedelta(days=day, seconds=int(RNG.integers(0, 86400)))
        rows.append(dict(
            timestamp=ts,
            source_ip=rand_ip(internal=True),
            destination_ip=rand_ip(internal=True),
            destination_port=int(RNG.choice(COMMON_PORTS)),
            protocol=RNG.choice(PROTOCOLS, p=[0.35, 0.15, 0.1, 0.25, 0.15]),
            packet_count=int(RNG.integers(5, 200)),
            traffic_volume_kb=float(RNG.uniform(1, 500)),
            is_attack=0, attack_type="none"
        ))

    # ---- Port scan / probe injection ----
    for _ in range(6):
        day = int(RNG.integers(0, SIM_DAYS))
        base_ts = START + timedelta(days=day, seconds=int(RNG.integers(0, 86400)))
        attacker_ip = rand_ip(internal=False)
        target_ip = rand_ip(internal=True)
        ports = RNG.choice(SCAN_PORTS, size=int(RNG.integers(80, 300)), replace=False)
        for i, p in enumerate(ports):
            rows.append(dict(
                timestamp=base_ts + timedelta(milliseconds=i * 50),
                source_ip=attacker_ip, destination_ip=target_ip,
                destination_port=int(p), protocol="TCP",
                packet_count=int(RNG.integers(1, 3)),
                traffic_volume_kb=float(RNG.uniform(0.1, 2)),
                is_attack=1, attack_type="probe"
            ))

    # ---- DoS burst injection ----
    for _ in range(4):
        day = int(RNG.integers(0, SIM_DAYS))
        base_ts = START + timedelta(days=day, seconds=int(RNG.integers(0, 86400)))
        attacker_ip = rand_ip(internal=False)
        target_ip = rand_ip(internal=True)
        n_pkts = int(RNG.integers(300, 800))
        for i in range(n_pkts):
            rows.append(dict(
                timestamp=base_ts + timedelta(milliseconds=i * 5),
                source_ip=attacker_ip, destination_ip=target_ip,
                destination_port=80, protocol="TCP",
                packet_count=int(RNG.integers(500, 3000)),
                traffic_volume_kb=float(RNG.uniform(500, 5000)),
                is_attack=1, attack_type="dos"
            ))

    df = pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)
    return df


# --------------------------------------------------------------------------
# 3. APPLICATION / SYSTEM LOGS
# --------------------------------------------------------------------------
def generate_application_logs():
    rows = []
    for user in USERS:
        for day in range(SIM_DAYS):
            n_events = int(RNG.integers(3, 12))
            for _ in range(n_events):
                hour = RNG.integers(9, 18)
                ts = START + timedelta(days=day, hours=int(hour), minutes=int(RNG.integers(0, 59)))
                rows.append(dict(
                    timestamp=ts, user=user, resource=RNG.choice(RESOURCES),
                    action="read", files_accessed=int(RNG.integers(1, 10)),
                    privilege_level="user",
                    is_attack=0, attack_type="none"
                ))

    # ---- Privilege escalation + sensitive data access / exfiltration, tied to compromise ----
    n_events = 8
    users_hit = RNG.choice(USERS, size=n_events, replace=False)
    for user in users_hit:
        day = int(RNG.integers(2, SIM_DAYS - 1))
        hour = int(RNG.integers(1, 5))
        ts = START + timedelta(days=day, hours=hour, minutes=int(RNG.integers(0, 30)))
        rows.append(dict(
            timestamp=ts, user=user, resource="admin_console",
            action="privilege_escalation", files_accessed=0,
            privilege_level="admin",
            is_attack=1, attack_type="privilege_escalation"
        ))
        rows.append(dict(
            timestamp=ts + timedelta(minutes=1), user=user,
            resource=RNG.choice(list(SENSITIVE_RESOURCES)),
            action="download", files_accessed=int(RNG.integers(200, 800)),
            privilege_level="admin",
            is_attack=1, attack_type="data_exfiltration"
        ))

    df = pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)
    return df


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    auth_df = generate_auth_logs()
    net_df = generate_network_logs()
    app_df = generate_application_logs()

    auth_df.to_csv(os.path.join(OUT_DIR, "auth_logs.csv"), index=False)
    net_df.to_csv(os.path.join(OUT_DIR, "network_logs.csv"), index=False)
    app_df.to_csv(os.path.join(OUT_DIR, "application_logs.csv"), index=False)

    print(f"auth_logs.csv        : {len(auth_df):,} rows  ({auth_df.is_attack.sum()} attack events)")
    print(f"network_logs.csv     : {len(net_df):,} rows  ({net_df.is_attack.sum()} attack events)")
    print(f"application_logs.csv : {len(app_df):,} rows  ({app_df.is_attack.sum()} attack events)")


if __name__ == "__main__":
    main()
