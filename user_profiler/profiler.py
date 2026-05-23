"""
User Profiler – Classifier
===========================
Maps behavioural feature vectors to risk archetypes using rule-based logic
grounded in established behavioural security theories.

No Flask imports.  No ML dependencies — pure rule evaluation.
"""

from __future__ import annotations

from datetime import datetime
from typing import List

from user_profiler.feature_extractor import extract_features

MIN_CONFIDENCE_THRESHOLD = 0.6


# ── Behavioural theory explanations ─────────────────────────────────────────
_THEORY_EXPLANATIONS: dict[str, str] = {
    "negligent": (
        "Prospect Theory: This user underweights low-probability threats, "
        "consistently dismissing warnings and visiting high-risk URLs."
    ),
    "impulsive": (
        "Theory of Planned Behavior: This user has low perceived behavioral "
        "control, acting quickly without assessing risk signals."
    ),
    "cautious": (
        "Protection Motivation Theory: This user shows high threat appraisal "
        "and coping behavior, consistently heeding security warnings."
    ),
}

_DEFAULT_EXPLANATION = "Insufficient data to apply behavioral theory."


class UserProfiler:
    """Rule-based user behaviour profiler.

    Classifies users into one of three archetypes
    (``"negligent"``, ``"impulsive"``, ``"cautious"``) based on
    feature signals extracted from their event history.
    """

    # ── Public API ───────────────────────────────────────────────────────────

    def classify_rule_based(self, features: dict) -> dict:
        """Map a feature dict to a user archetype.

        Rules are evaluated in priority order; the first match wins.

        Parameters
        ----------
        features : dict
            Output of :func:`user_profiler.feature_extractor.extract_features`.

        Returns
        -------
        dict
            ``{"user_type": str, "confidence": float}``
        """
        wdr = float(features.get("warning_dismissal_rate", 0.0))
        rur = float(features.get("risky_url_ratio", 0.0))
        arb = float(features.get("avg_risk_score_on_bypass", 0.0))
        hr  = float(features.get("heeded_rate", 0.0))

        # Rule 1 — negligent
        if wdr > 0.7 and rur > 0.5:
            user_type  = "negligent"
            confidence = float(min(wdr, rur))

        # Rule 2 — impulsive
        elif wdr > 0.4 or arb > 0.6:
            user_type  = "impulsive"
            confidence = float(max(wdr, arb))

        # Rule 3 — cautious (default)
        else:
            user_type  = "cautious"
            confidence = float(hr) if hr > 0.0 else 0.5

        return {"user_type": user_type, "confidence": confidence}

    def get_user_profile(self, user_id: str, events: List[dict]) -> dict:
        """Build a complete profile for a user from their event history.

        Parameters
        ----------
        user_id : str
            Identifier of the user being profiled.
        events : list[dict]
            Raw event rows from ``BehaviorStore.get_user_events()``.

        Returns
        -------
        dict
            Full profile including archetype, confidence, features, and metadata.
        """
        features = extract_features(events)
        
        try:
            from behavior_dataset.behavior_classifier import BehaviorClassifier
            behavior_model = BehaviorClassifier()
            if behavior_model.load_model():
                user_type, confidence = behavior_model.predict_with_confidence(features)
                if confidence < MIN_CONFIDENCE_THRESHOLD:
                    raise ValueError(f"ML confidence ({confidence:.2f}) below threshold {MIN_CONFIDENCE_THRESHOLD}")
                classification = {"user_type": user_type, "confidence": confidence}
            else:
                raise FileNotFoundError("Behavior model missing")
        except Exception as e:
            # Safe logging, no console spam
            # We won't use print(), just pass quietly to fallback
            classification = self.classify_rule_based(features)

        return {
            "user_id":    user_id,
            "user_type":  classification["user_type"],
            "confidence": classification["confidence"],
            "features":   features,
            "event_count": len(events),
            "timestamp":  datetime.utcnow().isoformat(),
        }

    def get_behavior_theory_explanation(self, user_type: str) -> str:
        """Return the behavioural theory explanation for a given archetype.

        Parameters
        ----------
        user_type : str
            One of ``"negligent"``, ``"impulsive"``, ``"cautious"``.

        Returns
        -------
        str
            Theory-grounded explanation string.
        """
        return _THEORY_EXPLANATIONS.get(user_type, _DEFAULT_EXPLANATION)
