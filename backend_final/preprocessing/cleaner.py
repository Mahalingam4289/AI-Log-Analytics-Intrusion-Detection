"""
cleaner.py — Stage 3 (part 1): Cleaning
Handles missing values, duplicate rows and obviously malformed entries
before normalization.
"""

import pandas as pd


def clean_dataframe(df: pd.DataFrame, required_cols=None) -> pd.DataFrame:
    df = df.copy()
    df = df.drop_duplicates()

    if required_cols:
        df = df.dropna(subset=[c for c in required_cols if c in df.columns])

    # Fill non-critical missing values sensibly
    for col in df.columns:
        if df[col].dtype == object:
            df[col] = df[col].fillna("unknown")
        else:
            df[col] = df[col].fillna(0)

    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df = df.sort_values("timestamp").reset_index(drop=True)

    return df
