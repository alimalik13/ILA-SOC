"""
Behavior Dataset – Dataset Builder
====================================
Aggregates per-user behavioural events from the BehaviorStore into a
labelled feature DataFrame suitable for training or analysis.
"""

from __future__ import annotations

import os

import pandas as pd

from user_profiler.feature_extractor import extract_features
from user_profiler.profiler import UserProfiler


class DatasetBuilder:
    """Builds a labelled dataset from raw BehaviorStore events.

    Each row in the resulting DataFrame represents one user and contains
    the seven behavioural features produced by ``extract_features()`` plus
    the rule-based archetype label assigned by ``UserProfiler``.
    """

    def __init__(self) -> None:
        self.profiler = UserProfiler()

    # ── Public API ───────────────────────────────────────────────────────────

    def build_dataset(self, behavior_store) -> pd.DataFrame:
        """Build a per-user labelled feature DataFrame.

        Parameters
        ----------
        behavior_store : BehaviorStore
            An initialised store exposing ``get_all_events() → pd.DataFrame``.

        Returns
        -------
        pd.DataFrame
            One row per unique user.  Columns are the seven feature keys
            plus ``user_id`` and ``label``.  Returns an empty DataFrame if
            the store contains no events.
        """
        df = behavior_store.get_all_events()

        if df is None or df.empty:
            return pd.DataFrame()

        rows = []
        for user_id in df["user_id"].unique():
            user_events = df[df["user_id"] == user_id].to_dict("records")
            features    = extract_features(user_events)
            label       = self.profiler.classify_rule_based(features)["user_type"]
            row         = {"user_id": user_id, **features, "label": label}
            rows.append(row)

        return pd.DataFrame(rows)

    def export_csv(
        self,
        df: pd.DataFrame,
        path: str = "behavior_dataset/behavior_dataset.csv",
    ) -> str:
        """Persist the dataset to a CSV file.

        Parameters
        ----------
        df : pd.DataFrame
            The DataFrame returned by :meth:`build_dataset`.
        path : str, optional
            Destination file path.  Parent directories are created
            automatically.

        Returns
        -------
        str
            The path the file was written to.
        """
        os.makedirs(os.path.dirname(path), exist_ok=True)
        df.to_csv(path, index=False)
        return path

    def get_statistics(self, df: pd.DataFrame) -> dict:
        """Compute summary statistics over the labelled dataset.

        Parameters
        ----------
        df : pd.DataFrame
            The DataFrame returned by :meth:`build_dataset`.

        Returns
        -------
        dict
            ``total_users``, ``label_distribution``,
            ``avg_warning_dismissal_rate``, and ``avg_risky_url_ratio``
            broken down by label.
        """
        if df is None or df.empty:
            return {
                "total_users":                0,
                "label_distribution":         {},
                "avg_warning_dismissal_rate": {},
                "avg_risky_url_ratio":        {},
            }

        label_dist = {
            k: int(v)
            for k, v in df["label"].value_counts().to_dict().items()
        }

        avg_wdr = {
            k: float(v)
            for k, v in df.groupby("label")["warning_dismissal_rate"]
            .mean()
            .to_dict()
            .items()
        }

        avg_rur = {
            k: float(v)
            for k, v in df.groupby("label")["risky_url_ratio"]
            .mean()
            .to_dict()
            .items()
        }

        return {
            "total_users":                int(len(df)),
            "label_distribution":         label_dist,
            "avg_warning_dismissal_rate": avg_wdr,
            "avg_risky_url_ratio":        avg_rur,
        }
