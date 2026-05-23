"""
Nudge Engine
============
Maps a (user_type, verdict) pair to a personalised nudge payload.

Relies only on the Python standard library — no Flask, no third-party imports.
"""

from __future__ import annotations

from typing import Optional


class NudgeEngine:
    """Determines the appropriate nudge type and builds the full nudge payload
    for a given user archetype, URL verdict, and behavioural feature set.
    """

    # ── Nudge matrix ─────────────────────────────────────────────────────────
    # Maps (user_type, verdict) → nudge_type | None
    # None means no nudge should be shown (safe site, cautious user).
    NUDGE_MATRIX: dict[tuple[str, str], Optional[str]] = {
        ("negligent", "Malicious"):  "firm",
        ("negligent", "Suspicious"): "firm",
        ("negligent", "Safe"):       "gentle",
        ("impulsive", "Malicious"):  "firm",
        ("impulsive", "Suspicious"): "guided",
        ("impulsive", "Safe"):       "gentle",
        ("cautious",  "Malicious"):  "guided",
        ("cautious",  "Suspicious"): "gentle",
        ("cautious",  "Safe"):       None,
    }

    # ── Nudge templates ───────────────────────────────────────────────────────
    NUDGE_TEMPLATES: dict[str, dict] = {
        "firm": {
            "title":              "⛔ Action Blocked",
            "color":              "#FF0000",
            "block_page":         True,
            "action_required":    True,
            "highlight_elements": False,
        },
        "guided": {
            "title":              "⚠️ Risky Elements Detected",
            "color":              "#FF8C00",
            "block_page":         False,
            "action_required":    False,
            "highlight_elements": True,
        },
        "gentle": {
            "title":              "ℹ️ Risk Information",
            "color":              "#FFC107",
            "block_page":         False,
            "action_required":    False,
            "highlight_elements": False,
        },
    }

    # ── Private helpers ───────────────────────────────────────────────────────

    def _build_personalized_reason(
        self,
        user_type: str,
        verdict: str,
        features: dict,
    ) -> str:
        """Construct a human-readable, profile-aware reason string.

        Parameters
        ----------
        user_type : str
            One of ``"negligent"``, ``"impulsive"``, ``"cautious"``.
        verdict : str
            One of ``"Malicious"``, ``"Suspicious"``, ``"Safe"``.
        features : dict
            Feature dict from ``extract_features()``; accessed via
            ``.get()`` to prevent ``KeyError`` on missing keys.

        Returns
        -------
        str
            Personalised explanation for the nudge.
        """
        key = (user_type, verdict)

        if key == ("negligent", "Malicious"):
            dismissal_pct = int(features.get("warning_dismissal_rate", 0.0) * 100)
            return (
                f"You have dismissed {dismissal_pct}% of past warnings. "
                "This site is confirmed malicious."
            )

        if key == ("negligent", "Suspicious"):
            return (
                "You frequently visit risky URLs. "
                "This site shows suspicious signals — treat with caution."
            )

        if key == ("negligent", "Safe"):
            return (
                "No threats detected, but your browsing history includes "
                "many high-risk sites."
            )

        if key == ("impulsive", "Malicious"):
            return (
                "You tend to act quickly — pause before proceeding. "
                "This site is confirmed malicious."
            )

        if key == ("impulsive", "Suspicious"):
            return (
                "Risky elements detected. Your pattern suggests acting fast; "
                "take a moment to review."
            )

        if key == ("impulsive", "Safe"):
            return "No threats detected. Continue, but stay alert."

        if key == ("cautious", "Malicious"):
            return (
                "Unusual for your profile — this site is flagged as malicious. "
                "Trust your instincts."
            )

        if key == ("cautious", "Suspicious"):
            return (
                "Low risk for your profile, but some suspicious signals "
                "were detected."
            )

        if key == ("cautious", "Safe"):
            return "No threats detected. Safe to proceed."

        # Default fallback for unknown / future archetypes
        return "Proceed with caution."

    # ── Public API ────────────────────────────────────────────────────────────

    def get_nudge(
        self,
        user_type: str,
        verdict: str,
        risk_score: float,
        url: str,
        features: dict,
    ) -> dict:
        """Build the full nudge payload for the given context.

        Parameters
        ----------
        user_type : str
            User archetype from ``UserProfiler``.
        verdict : str
            URL verdict from the risk engine (``"Malicious"`` / ``"Suspicious"``
            / ``"Safe"``).
        risk_score : float
            Numeric risk score in ``[0.0, 1.0]``.
        url : str
            The URL being evaluated.
        features : dict
            Behavioural feature dict from ``extract_features()``.

        Returns
        -------
        dict
            Full nudge payload, or ``{"nudge_type": None}`` when no nudge is
            warranted (e.g. cautious user on a safe site).
        """
        key        = (user_type, verdict)
        nudge_type = self.NUDGE_MATRIX.get(key, "gentle")

        if nudge_type is None:
            return {"nudge_type": None}

        # .copy() prevents callers from mutating the class-level template
        template = self.NUDGE_TEMPLATES[nudge_type].copy()

        return {
            "nudge_type":          nudge_type,
            "title":               template["title"],
            "message":             template["title"],
            "action_required":     template["action_required"],
            "color_code":          template["color"],
            "block_page":          template["block_page"],
            "highlight_elements":  template["highlight_elements"],
            "risk_score":          float(risk_score),
            "verdict":             str(verdict),
            "personalized_reason": self._build_personalized_reason(
                user_type, verdict, features
            ),
            "url":                 str(url),
        }
