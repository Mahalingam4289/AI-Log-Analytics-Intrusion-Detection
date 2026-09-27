"""
data/load_real_dataset.py — Part A: Real dataset integration.

Downloads NSL-KDD (real captured/simulated network attack traffic, not
synthetic) and maps its 41 features + label onto this project's existing
auth_logs.csv / network_logs.csv / application_logs.csv schema, so the
rest of the pipeline (preprocessing, features, models, risk engine) is
completely unchanged.

Source: https://raw.githubusercontent.com/defcom17/NSL_KDD
NSL-KDD label -> this project's attack_type:
    dos                 -> dos
    portsweep, ipsweep,
    nmap, satan          -> probe
    guess_passwd,
    ftp_write, ...(r2l)   -> brute_force
    buffer_overflow,
    rootkit, ... (u2r)     -> privilege_escalation
    normal                 -> none
"""

import os
import sys
import urllib.request
import pandas as pd
import numpy as np

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RAW_DIR = os.path.join(BASE_DIR, "real_dataset")
TRAIN_URL = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B.csv"
TEST_URL = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest%2B.csv"

COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty",
]

DOS = {"back", "land", "neptune", "pod", "smurf", "teardrop", "apache2", "udpstorm",
       "processtable", "mailbomb"}
PROBE = {"ipsweep", "nmap", "portsweep", "satan", "mscan", "saint"}
R2L = {"ftp_write", "guess_passwd", "imap", "multihop", "phf", "spy", "warezclient",
       "warezmaster", "xlock", "xsnoop", "snmpguess", "snmpgetattack", "httptunnel",
       "sendmail", "named", "worm"}
U2R = {"buffer_overflow", "loadmodule", "perl", "rootkit", "ps", "sqlattack",
       "xterm"}


def map_label(label: str) -> str:
    if label in DOS:
        return "dos"
    if label in PROBE:
        return "probe"
    if label in R2L:
        return "brute_force"
    if label in U2R:
        return "privilege_escalation"
    return "none"


def download_if_missing():
    os.makedirs(RAW_DIR, exist_ok=True)
    train_path = os.path.join(RAW_DIR, "KDDTrain+.csv")
    test_path = os.path.join(RAW_DIR, "KDDTest+.csv")
    if not os.path.exists(train_path):
        print("[real_dataset] downloading NSL-KDD train set...")
        urllib.request.urlretrieve(TRAIN_URL, train_path)
    if not os.path.exists(test_path):
        print("[real_dataset] downloading NSL-KDD test set...")
        urllib.request.urlretrieve(TEST_URL, test_path)
    return train_path, test_path


def load_raw():
    train_path, test_path = download_if_missing()
    train = pd.read_csv(train_path, header=None, names=COLUMNS)
    test = pd.read_csv(test_path, header=None, names=COLUMNS)
    df = pd.concat([train, test], ignore_index=True)
    df["attack_type"] = df["label"].apply(map_label)
    df["is_attack"] = (df["attack_type"] != "none").astype(int)
    return df


def build_auth_logs(df: pd.DataFrame, start_time) -> pd.DataFrame:
    """Auth-relevant rows: anything with a login attempt signal."""
    rows = []
    n_users = 60
    users = [f"user_{i:03d}" for i in range(1, n_users + 1)]
    rng = np.random.default_rng(7)

    subset = df.sample(n=min(20000, len(df)), random_state=42)
    for i, (_, row) in enumerate(subset.iterrows()):
        user = users[i % n_users]
        ts = start_time + pd.Timedelta(seconds=i * 3)
        failed = int(row["num_failed_logins"]) > 0 or row["attack_type"] == "brute_force"
        rows.append(dict(
            timestamp=ts, user=user,
            source_ip=f"10.0.{i % 5}.{(i * 7) % 254 + 1}" if row["attack_type"] != "brute_force"
                       else f"{(i % 200) + 1}.{(i * 3) % 255}.{(i * 5) % 255}.{(i * 9) % 254 + 1}",
            device=f"device_{user[-3:]}_0" if row["attack_type"] != "brute_force" else "unknown_device",
            location="Chennai" if row["attack_type"] != "brute_force" else "Unknown",
            event_type="login",
            auth_method="password",
            status="FAILED" if failed else "SUCCESS",
            is_attack=int(row["is_attack"]), attack_type=row["attack_type"],
        ))
    return pd.DataFrame(rows)


def build_network_logs(df: pd.DataFrame, start_time) -> pd.DataFrame:
    """Every NSL-KDD row is fundamentally a network flow record — this is
    the dataset's native strength (DoS + Probe detection)."""
    rows = []
    subset = df.sample(n=min(60000, len(df)), random_state=43)
    proto_map = {"tcp": "TCP", "udp": "UDP", "icmp": "ICMP"}
    for i, (_, row) in enumerate(subset.iterrows()):
        ts = start_time + pd.Timedelta(seconds=i * 2)
        is_attack_row = row["attack_type"] in ("dos", "probe")
        src_ip = (f"{(i % 200) + 1}.{(i * 3) % 255}.{(i * 5) % 255}.{(i * 9) % 254 + 1}"
                   if is_attack_row else f"10.0.{i % 5}.{(i * 7) % 254 + 1}")
        rows.append(dict(
            timestamp=ts,
            source_ip=src_ip,
            destination_ip=f"10.0.{(i + 1) % 5}.{(i * 11) % 254 + 1}",
            destination_port=int(80 if row["service"] == "http" else
                                  (443 if row["service"] == "http_443" else
                                   (22 if row["service"] == "ssh" else
                                    (21 if row["service"] == "ftp" else 8080)))),
            protocol=proto_map.get(row["protocol_type"], "TCP"),
            packet_count=int(max(1, row["count"])),
            traffic_volume_kb=float((row["src_bytes"] + row["dst_bytes"]) / 1024.0),
            is_attack=int(row["is_attack"]),
            attack_type=row["attack_type"] if row["attack_type"] in ("dos", "probe", "none") else "none",
        ))
    return pd.DataFrame(rows)


def build_application_logs(df: pd.DataFrame, start_time) -> pd.DataFrame:
    """U2R (privilege escalation) rows map naturally onto application/
    system-level events."""
    rows = []
    n_users = 60
    users = [f"user_{i:03d}" for i in range(1, n_users + 1)]
    resources = ["reports_db", "hr_portal", "finance_db", "customer_data",
                 "source_code_repo", "email_server", "billing_system", "admin_console"]
    subset = df.sample(n=min(15000, len(df)), random_state=44)
    for i, (_, row) in enumerate(subset.iterrows()):
        user = users[i % n_users]
        ts = start_time + pd.Timedelta(seconds=i * 4)
        is_priv = row["attack_type"] == "privilege_escalation"
        rows.append(dict(
            timestamp=ts, user=user,
            resource="admin_console" if is_priv else resources[i % len(resources)],
            action="privilege_escalation" if is_priv else "read",
            files_accessed=int(row["num_file_creations"]) + int(row["num_access_files"]) + (1 if not is_priv else 0),
            privilege_level="admin" if is_priv else "user",
            is_attack=int(row["is_attack"]), attack_type=row["attack_type"],
        ))
    return pd.DataFrame(rows)


def main():
    print("[real_dataset] loading NSL-KDD (real network intrusion data)...")
    df = load_raw()
    print(f"[real_dataset] total records: {len(df):,}  "
          f"(attacks: {df['is_attack'].sum():,}, benign: {(df['is_attack']==0).sum():,})")

    start_time = pd.Timestamp("2026-08-01 00:00:00")
    auth_df = build_auth_logs(df, start_time)
    net_df = build_network_logs(df, start_time)
    app_df = build_application_logs(df, start_time)

    auth_df.to_csv(os.path.join(BASE_DIR, "auth_logs.csv"), index=False)
    net_df.to_csv(os.path.join(BASE_DIR, "network_logs.csv"), index=False)
    app_df.to_csv(os.path.join(BASE_DIR, "application_logs.csv"), index=False)

    print(f"auth_logs.csv        : {len(auth_df):,} rows  ({auth_df.is_attack.sum()} attack events)")
    print(f"network_logs.csv     : {len(net_df):,} rows  ({net_df.is_attack.sum()} attack events)")
    print(f"application_logs.csv : {len(app_df):,} rows  ({app_df.is_attack.sum()} attack events)")
    print("[real_dataset] done — these files match the schema generate_dataset.py "
          "would have produced, so main.py and the backend work unchanged.")


if __name__ == "__main__":
    main()
