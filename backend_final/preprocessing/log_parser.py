"""
log_parser.py — Stage 2: Log Ingestion
Loads heterogeneous raw logs (auth / network / application) from CSV.
In a real deployment this module would also support JSON and syslog,
this hook is left as an extension point (`parse_json`, `parse_syslog`).
"""

import pandas as pd


def parse_csv(path: str) -> pd.DataFrame:
    df = pd.read_csv(path, parse_dates=["timestamp"])
    return df


def load_all_logs(auth_path, network_path, app_path):
    auth_df = parse_csv(auth_path)
    net_df = parse_csv(network_path)
    app_df = parse_csv(app_path)
    return auth_df, net_df, app_df


# Extension points for real-world ingestion (not used by the prototype
# pipeline, kept to document how the system would be extended):
def parse_json(path: str) -> pd.DataFrame:
    return pd.read_json(path, lines=True)


def parse_syslog(path: str) -> pd.DataFrame:
    raise NotImplementedError("Syslog ingestion is an extensibility hook for future work.")
