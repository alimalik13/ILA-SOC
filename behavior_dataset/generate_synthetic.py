# -*- coding: utf-8 -*-
import sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

"""
Synthetic Behavioral Dataset Generator
========================================
Generates 2000 realistic synthetic user behavior records for a
cybersecurity nudging / user-profiling research system.

Grounding theories
------------------
- Cautious   : Protection Motivation Theory
- Impulsive  : Theory of Planned Behavior
- Negligent  : Prospect Theory

Run standalone:
    python behavior_dataset/generate_synthetic.py
"""

import os
import uuid
from datetime import datetime

import numpy as np
import pandas as pd

np.random.seed(42)  # reproducibility


# ── Helper ────────────────────────────────────────────────────────────────────

def _noise(n: int) -> np.ndarray:
    """Small Gaussian noise for realism."""
    return np.random.normal(0, 0.03, n)


def _add_noise(arr: np.ndarray) -> np.ndarray:
    """Add noise then re-clip to [0, 1]."""
    return np.clip(arr + _noise(len(arr)), 0.0, 1.0)


# ── Group generators ──────────────────────────────────────────────────────────

def _build_cautious() -> pd.DataFrame:
    n = 800
    wdr  = _add_noise(np.random.beta(1, 9, n))
    rur  = _add_noise(np.random.beta(1, 9, n))
    arb  = _add_noise(np.random.beta(1, 9, n))
    rtv  = np.random.gamma(2, 50, n)                          # no clip
    hr   = _add_noise(np.random.beta(9, 1, n))
    dar  = _add_noise(np.random.beta(1, 9, n))
    te   = np.random.randint(10, 80, n).astype(float)

    sc   = np.random.randint(1, 10, n)
    asd  = np.random.normal(25, 8, n).clip(5, 90)
    drs  = np.clip(np.random.beta(1, 8, n), 0.0, 1.0)
    pha  = np.random.randint(8, 18, n)

    return pd.DataFrame({
        "user_id":                    [str(uuid.uuid4()) for _ in range(n)],
        "label":                      "cautious",
        "warning_dismissal_rate":     wdr,
        "risky_url_ratio":            rur,
        "avg_risk_score_on_bypass":   arb,
        "response_time_variance":     rtv,
        "heeded_rate":                hr,
        "download_attempt_rate":      dar,
        "total_events":               te,
        "session_count":              sc,
        "avg_session_duration_mins":  asd,
        "device_risk_score":          drs,
        "peak_hour_activity":         pha,
    })


def _build_impulsive() -> pd.DataFrame:
    n = 700
    wdr  = _add_noise(np.clip(np.random.beta(6, 3, n), 0.35, 1.0))
    rur  = _add_noise(np.clip(np.random.beta(2, 6, n), 0.0,  0.49))
    arb  = _add_noise(np.clip(np.random.beta(5, 3, n), 0.45, 1.0))
    rtv  = np.random.gamma(8, 20, n)                          # no clip
    hr   = _add_noise(np.clip(np.random.beta(2, 7, n), 0.0,  0.45))
    dar  = _add_noise(np.random.beta(3, 6, n))
    te   = np.random.randint(15, 120, n).astype(float)

    sc   = np.random.randint(3, 20, n)
    asd  = np.random.normal(12, 5, n).clip(2, 45)
    drs  = np.clip(np.random.beta(3, 5, n), 0.0, 1.0)
    pha  = np.random.randint(0, 24, n)

    return pd.DataFrame({
        "user_id":                    [str(uuid.uuid4()) for _ in range(n)],
        "label":                      "impulsive",
        "warning_dismissal_rate":     wdr,
        "risky_url_ratio":            rur,
        "avg_risk_score_on_bypass":   arb,
        "response_time_variance":     rtv,
        "heeded_rate":                hr,
        "download_attempt_rate":      dar,
        "total_events":               te,
        "session_count":              sc,
        "avg_session_duration_mins":  asd,
        "device_risk_score":          drs,
        "peak_hour_activity":         pha,
    })


def _build_negligent() -> pd.DataFrame:
    n = 500
    wdr  = _add_noise(np.clip(np.random.beta(9, 1, n), 0.70, 1.0))
    rur  = _add_noise(np.clip(np.random.beta(7, 2, n), 0.50, 1.0))
    arb  = _add_noise(np.clip(np.random.beta(8, 2, n), 0.60, 1.0))
    rtv  = np.random.gamma(3, 80, n)                          # no clip
    hr   = _add_noise(np.clip(np.random.beta(1, 9, n), 0.0,  0.30))
    dar  = _add_noise(np.random.beta(5, 4, n))
    te   = np.random.randint(20, 200, n).astype(float)

    sc   = np.random.randint(5, 30, n)
    asd  = np.random.normal(35, 12, n).clip(5, 120)
    drs  = np.clip(np.random.beta(7, 2, n), 0.0, 1.0)
    pha  = np.random.randint(20, 24, n)

    return pd.DataFrame({
        "user_id":                    [str(uuid.uuid4()) for _ in range(n)],
        "label":                      "negligent",
        "warning_dismissal_rate":     wdr,
        "risky_url_ratio":            rur,
        "avg_risk_score_on_bypass":   arb,
        "response_time_variance":     rtv,
        "heeded_rate":                hr,
        "download_attempt_rate":      dar,
        "total_events":               te,
        "session_count":              sc,
        "avg_session_duration_mins":  asd,
        "device_risk_score":          drs,
        "peak_hour_activity":         pha,
    })


# ── Main ──────────────────────────────────────────────────────────────────────

def generate() -> pd.DataFrame:
    cautious_df  = _build_cautious()
    impulsive_df = _build_impulsive()
    negligent_df = _build_negligent()

    df = pd.concat(
        [cautious_df, impulsive_df, negligent_df],
        ignore_index=True
    )
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    return df


def save(df: pd.DataFrame) -> None:
    os.makedirs("behavior_dataset", exist_ok=True)

    full_path = "behavior_dataset/synthetic_behavior_dataset.csv"
    df.to_csv(full_path, index=False)

    df[df["label"] == "cautious"].to_csv(
        "behavior_dataset/synthetic_cautious.csv",  index=False)
    df[df["label"] == "impulsive"].to_csv(
        "behavior_dataset/synthetic_impulsive.csv", index=False)
    df[df["label"] == "negligent"].to_csv(
        "behavior_dataset/synthetic_negligent.csv", index=False)


def print_report(df: pd.DataFrame) -> None:
    features = [
        "warning_dismissal_rate", "risky_url_ratio",
        "avg_risk_score_on_bypass", "heeded_rate",
        "download_attempt_rate", "device_risk_score",
    ]

    print("=" * 55)
    print("   SYNTHETIC BEHAVIORAL DATASET — GENERATION REPORT")
    print("=" * 55)
    print(f"Total users generated : {len(df)}")
    print(f"Total features        : {len(df.columns) - 2}")
    print()
    print("Label Distribution:")
    for label, count in df["label"].value_counts().items():
        pct = count / len(df) * 100
        bar = "#" * int(pct / 2)
        print(f"  {label:<12} {count:>5} users  {bar} {pct:.1f}%")
    print()
    print("Feature Statistics per Label:")
    stats = df.groupby("label")[features].mean().round(3)
    print(stats.to_string())
    print()
    print("Files saved:")
    print("  behavior_dataset/synthetic_behavior_dataset.csv  ← full dataset")
    print("  behavior_dataset/synthetic_cautious.csv")
    print("  behavior_dataset/synthetic_impulsive.csv")
    print("  behavior_dataset/synthetic_negligent.csv")
    print("=" * 55)


if __name__ == "__main__":
    df = generate()
    save(df)
    print_report(df)
