"""
auth_features.py — Stage 4: Authentication feature engineering.

For every auth event, compute rolling behavioral signals:
    failed_login_count_10min : failed logins by same user in prior 10 min
    login_hour               : hour of day (0-23)
    is_off_hours             : 1 if login_hour outside 6-22
    new_device               : 1 if device not previously seen for user
    new_location             : 1 if location not previously seen for user
    ip_deviation              : 1 if source_ip not previously seen for user
"""

import pandas as pd


def compute_auth_features(unified: pd.DataFrame) -> pd.DataFrame:
    auth = unified[unified["log_source"] == "auth"].copy()
    auth = auth.sort_values("timestamp").reset_index(drop=True)

    auth["login_hour"] = auth["timestamp"].dt.hour
    auth["is_off_hours"] = ((auth["login_hour"] < 6) | (auth["login_hour"] > 22)).astype(int)

    seen_devices, seen_locations, seen_ips = {}, {}, {}
    new_device, new_location, ip_deviation = [], [], []

    for _, row in auth.iterrows():
        u = row["user"]
        d, l, ip = row["device"], row["location"], row["source_ip"]
        seen_devices.setdefault(u, set())
        seen_locations.setdefault(u, set())
        seen_ips.setdefault(u, set())

        new_device.append(int(d not in seen_devices[u]))
        new_location.append(int(l not in seen_locations[u]))
        ip_deviation.append(int(ip not in seen_ips[u]))

        seen_devices[u].add(d)
        seen_locations[u].add(l)
        seen_ips[u].add(ip)

    auth["new_device"] = new_device
    auth["new_location"] = new_location
    auth["ip_deviation"] = ip_deviation

    # failed_login_count in prior 10 minutes, per user
    auth["_orig_order"] = range(len(auth))
    auth_ts = auth.set_index("timestamp")
    failed_counts = []
    for u, grp in auth_ts.groupby("user"):
        is_failed = (grp["status"] == "FAILED").astype(int)
        rolled = is_failed.rolling("10min").sum()
        failed_counts.append(pd.DataFrame({"_orig_order": grp["_orig_order"].values,
                                            "failed_login_count_10min": rolled.values}))
    failed_df = pd.concat(failed_counts).set_index("_orig_order")
    auth = auth.set_index("_orig_order")
    auth["failed_login_count_10min"] = failed_df["failed_login_count_10min"]
    auth = auth.reset_index(drop=True)

    # login frequency: logins by user in past 1 hour
    auth["_orig_order"] = range(len(auth))
    auth_ts = auth.set_index("timestamp")
    freq = []
    for u, grp in auth_ts.groupby("user"):
        rolled = grp["event_id"].rolling("60min").count()
        freq.append(pd.DataFrame({"_orig_order": grp["_orig_order"].values,
                                   "login_frequency_1h": rolled.values}))
    freq_df = pd.concat(freq).set_index("_orig_order")
    auth = auth.set_index("_orig_order")
    auth["login_frequency_1h"] = freq_df["login_frequency_1h"]
    auth = auth.reset_index(drop=True)

    return auth
