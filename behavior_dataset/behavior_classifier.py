"""
Behavior Dataset – ML Classifier
==================================
Trains a Random-Forest classifier on the labelled behavioural feature
dataset and exposes inference + effectiveness-evaluation utilities.

Saved artefact: behavior_dataset/behavior_model.pkl
"""

from __future__ import annotations

import os

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split


# ── Constants ────────────────────────────────────────────────────────────────

LABEL_MAP: dict[str, int] = {
    "cautious":  0,
    "impulsive": 1,
    "negligent": 2,
}

REVERSE_MAP: dict[int, str] = {v: k for k, v in LABEL_MAP.items()}

MODEL_PATH = "behavior_dataset/behavior_model.pkl"

FEATURE_COLS: list[str] = [
    "warning_dismissal_rate",
    "risky_url_ratio",
    "avg_risk_score_on_bypass",
    "response_time_variance",
    "heeded_rate",
    "download_attempt_rate",
    "total_events",
]


# ── Classifier ───────────────────────────────────────────────────────────────

class BehaviorClassifier:
    """Random-Forest classifier for user behaviour archetypes.

    Lifecycle
    ---------
    1. ``train(df)``     — fit on a labelled dataset, persist model to disk.
    2. ``load_model()``  — reload a previously saved model.
    3. ``predict(features)`` — infer archetype from a feature dict.
    4. ``evaluate_nudge_effectiveness(behavior_store)`` — compare pre/post
       nudge risky-URL rates using a temporal split.
    """

    def __init__(self) -> None:
        self.model:        RandomForestClassifier | None = None
        self.feature_cols: list[str]                     = FEATURE_COLS

    # ── Training ─────────────────────────────────────────────────────────────

    def train(self, df: pd.DataFrame) -> dict:
        """Fit a Random-Forest model on the labelled feature DataFrame.

        Parameters
        ----------
        df : pd.DataFrame
            Must contain all columns in ``FEATURE_COLS`` plus ``"label"``.

        Returns
        -------
        dict
            ``accuracy``, ``report`` (sklearn dict), and
            ``feature_importances``.  Returns ``{"error": ...}`` when there
            is insufficient data.
        """
        df = df.dropna(subset=["label"])

        if len(df) < 10:
            return {"error": "insufficient data for training"}

        y = df["label"].map(LABEL_MAP)
        X = df[FEATURE_COLS].fillna(0.0)

        # Prefer stratified split; fall back when any class has < 2 samples
        try:
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
        except ValueError:
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42
            )

        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.model.fit(X_train, y_train)

        y_pred   = self.model.predict(X_test)
        accuracy = float(accuracy_score(y_test, y_pred))
        report   = classification_report(y_test, y_pred, output_dict=True)

        importances = {
            col: float(imp)
            for col, imp in zip(FEATURE_COLS, self.model.feature_importances_)
        }

        # Persist to disk
        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        joblib.dump(
            {"model": self.model, "feature_cols": FEATURE_COLS},
            MODEL_PATH,
        )

        return {
            "accuracy":             accuracy,
            "report":               report,
            "feature_importances":  importances,
        }

    # ── Persistence ──────────────────────────────────────────────────────────

    def load_model(self) -> bool:
        """Load a previously saved model from ``MODEL_PATH``.

        Returns
        -------
        bool
            ``True`` on success, ``False`` if the file does not exist.
        """
        try:
            payload           = joblib.load(MODEL_PATH)
            self.model        = payload["model"]
            self.feature_cols = payload["feature_cols"]
            return True
        except FileNotFoundError:
            return False

    # ── Inference ─────────────────────────────────────────────────────────────

    def predict(self, features: dict) -> str:
        """Predict the user archetype from a feature dict."""
        label, _ = self.predict_with_confidence(features)
        return label

    def predict_with_confidence(self, features: dict) -> tuple[str, float]:
        """Predict the user archetype and return its confidence score.

        Attempts to load the saved model if none is in memory.
        Falls back to ``("cautious", 0.0)`` if no model is available.

        Parameters
        ----------
        features : dict
            Output of ``extract_features()``; missing keys default to 0.0.

        Returns
        -------
        tuple[str, float]
            (Archetype label, Confidence score)
        """
        if self.model is None:
            self.load_model()

        if self.model is None:
            return ("cautious", 0.0)

        X = [[features.get(col, 0.0) for col in self.feature_cols]]
        probs = self.model.predict_proba(X)[0]
        class_idx = int(np.argmax(probs))
        confidence = float(probs[class_idx])
        return (REVERSE_MAP[class_idx], confidence)

    # ── Effectiveness evaluation ──────────────────────────────────────────────

    def evaluate_nudge_effectiveness(self, behavior_store) -> dict:
        """Estimate nudge effectiveness via a temporal pre/post split.

        Divides the full event log in half (chronological order) and
        compares the risky-URL visit rate in each window.  A negative
        ``delta`` indicates the nudge reduced risky behaviour.

        Parameters
        ----------
        behavior_store : BehaviorStore
            Live store exposing ``get_all_events() → pd.DataFrame``.

        Returns
        -------
        dict
            ``{"overall": {"pre_rate": float, "post_rate": float,
            "delta": float}}``  or ``{}`` on error / empty store.
        """
        df = behavior_store.get_all_events()

        if df is None or df.empty:
            return {}

        try:
            df  = df.sort_values("timestamp")
            mid = len(df) // 2
            pre  = df.iloc[:mid]
            post = df.iloc[mid:]

            def risky_rate(window: pd.DataFrame) -> float:
                if len(window) == 0:
                    return 0.0
                return float(
                    (window["event_type"] == "risky_url_visited").sum()
                    / len(window)
                )

            pre_r  = risky_rate(pre)
            post_r = risky_rate(post)

            return {
                "overall": {
                    "pre_rate":  pre_r,
                    "post_rate": post_r,
                    "delta":     round(post_r - pre_r, 4),
                }
            }

        except Exception:  # noqa: BLE001
            return {}
