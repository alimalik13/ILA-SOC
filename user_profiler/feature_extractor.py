"""
User Profiler – Feature Extractor
==================================
Derives behavioural feature signals from a list of raw BehaviorEvent dicts.

All values are returned as plain Python floats.  The function never raises;
any computation error yields an all-zero feature dict.
"""

from __future__ import annotations

from datetime import datetime
from typing import List

import numpy as np
import pandas as pd


# ── Zero-feature sentinel ────────────────────────────────────────────────────
_ZERO_FEATURES: dict = {
    "warning_dismissal_rate": 0.0,
    "risky_url_ratio": 0.0,
    "avg_risk_score_on_bypass": 0.0,
    "response_time_variance": 0.0,
    "heeded_rate": 0.0,
    "download_attempt_rate": 0.0,
    "total_events": 0.0,
}


def _parse_timestamp(ts) -> datetime:
    """Coerce a timestamp to a datetime object, regardless of input type."""
    if isinstance(ts, datetime):
        return ts
    return datetime.fromisoformat(str(ts))


def extract_features(events: List[dict]) -> dict:
    """Compute behavioural feature signals from a list of event dicts.

    Parameters
    ----------
    events : list[dict]
        Each dict must contain at least the keys produced by
        ``BehaviorStore.get_user_events()``.

    Returns
    -------
    dict
        Seven float-valued features (see module docstring).
        Returns all-zero dict on any error.
    """
    try:
        total = len(events)

        # ── total_events ─────────────────────────────────────────────────────
        total_events = float(total)

        if total == 0:
            return dict(_ZERO_FEATURES)

        # Build a DataFrame for vectorised ops
        df = pd.DataFrame(events)

        # ── warning_dismissal_rate & heeded_rate ─────────────────────────────
        warning_mask = df["event_type"].isin(["warning_dismissed", "warning_heeded"])
        warning_total = int(warning_mask.sum())

        dismissed_count = int((df["event_type"] == "warning_dismissed").sum())
        heeded_count = int((df["event_type"] == "warning_heeded").sum())

        warning_dismissal_rate = (
            float(dismissed_count / warning_total) if warning_total > 0 else 0.0
        )
        heeded_rate = (
            float(heeded_count / warning_total) if warning_total > 0 else 0.0
        )

        # ── risky_url_ratio ───────────────────────────────────────────────────
        risky_count = int((df["event_type"] == "risky_url_visited").sum())
        risky_url_ratio = float(risky_count / total)

        # ── avg_risk_score_on_bypass ─────────────────────────────────────────
        bypass_df = df[df["event_type"] == "blocked_action_bypassed"]
        if bypass_df.empty:
            avg_risk_score_on_bypass = 0.0
        else:
            avg_risk_score_on_bypass = float(
                np.mean(bypass_df["risk_score"].astype(float).to_numpy())
            )

        # ── response_time_variance ────────────────────────────────────────────
        if total < 2:
            response_time_variance = 0.0
        else:
            # Parse and sort timestamps
            timestamps = sorted(
                _parse_timestamp(ts) for ts in df["timestamp"].tolist()
            )
            # Compute inter-event gaps in seconds
            gaps = np.array(
                [
                    (timestamps[i + 1] - timestamps[i]).total_seconds()
                    for i in range(len(timestamps) - 1)
                ],
                dtype=float,
            )
            response_time_variance = (
                float(np.var(gaps)) if gaps.size > 0 else 0.0
            )

        # ── download_attempt_rate ─────────────────────────────────────────────
        download_count = int((df["event_type"] == "download_attempted").sum())
        download_attempt_rate = float(download_count / total)

        return {
            "warning_dismissal_rate": warning_dismissal_rate,
            "risky_url_ratio": risky_url_ratio,
            "avg_risk_score_on_bypass": avg_risk_score_on_bypass,
            "response_time_variance": response_time_variance,
            "heeded_rate": heeded_rate,
            "download_attempt_rate": download_attempt_rate,
            "total_events": total_events,
        }

    except Exception:  # noqa: BLE001
        return dict(_ZERO_FEATURES)
