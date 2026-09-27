"""
network_features.py — Stage 4: Network feature engineering.

    connection_count_1min : connections from same source_ip in prior 1 min
                             (captures port-scan / DoS bursts)
    unique_ports_1min      : distinct destination ports contacted by the
                              source_ip in the prior 1 min (port-scan signal)
    traffic_volume_zscore  : how unusual this flow's traffic volume is
                              relative to the source_ip's own recent history
"""

import pandas as pd
import numpy as np


def compute_network_features(unified: pd.DataFrame) -> pd.DataFrame:
    net = unified[unified["log_source"] == "network"].copy()
    net = net.sort_values("timestamp").reset_index(drop=True)
    net["_orig_order"] = range(len(net))
    net_ts = net.set_index("timestamp")

    rows = []
    for ip, grp in net_ts.groupby("source_ip"):
        conn = grp["event_id"].rolling("1min").count()
        uniq = grp["destination_port"].rolling(50, min_periods=1).apply(
            lambda x: pd.Series(x).nunique())
        mean = grp["traffic_volume_kb"].rolling(50, min_periods=1).mean()
        std = grp["traffic_volume_kb"].rolling(50, min_periods=1).std()
        std = std.fillna(60.0).replace(0, 60.0)
        z = (grp["traffic_volume_kb"] - mean) / std
        rows.append(pd.DataFrame({
            "_orig_order": grp["_orig_order"].values,
            "connection_count_1min": conn.values,
            "unique_ports_recent": uniq.values,
            "traffic_volume_zscore": z.values,
        }))

    feat_df = pd.concat(rows).set_index("_orig_order")
    net = net.set_index("_orig_order")
    net["connection_count_1min"] = feat_df["connection_count_1min"]
    net["unique_ports_recent"] = feat_df["unique_ports_recent"]
    net["traffic_volume_zscore"] = feat_df["traffic_volume_zscore"].fillna(0)
    net = net.reset_index(drop=True)
    return net
