"""
Behavior Tracker Module
=======================
Tracks and stores user behavioral events (warning responses, URL visits,
download attempts, etc.) for the ILA-SOC nudging pipeline.

All data is persisted in a local SQLite database (behavior_data.db) and can
be retrieved as raw rows or as a pandas DataFrame for downstream analysis.
"""

from __future__ import annotations

import sqlite3
import os
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import List, Optional

import pandas as pd


# ── Valid event types ────────────────────────────────────────────────────────
VALID_EVENT_TYPES = frozenset(
    [
        "warning_dismissed",
        "warning_heeded",
        "risky_url_visited",
        "safe_url_visited",
        "download_attempted",
        "blocked_action_bypassed",
        "blocked_action_accepted",
    ]
)


# ── Data class ───────────────────────────────────────────────────────────────
@dataclass
class BehaviorEvent:
    """A single behavioural event recorded for a user session."""

    user_id: str
    event_type: str
    url: str
    risk_score: float
    verdict: str
    timestamp: datetime
    session_id: str

    def __post_init__(self) -> None:
        # Validate event_type
        if self.event_type not in VALID_EVENT_TYPES:
            raise ValueError(
                f"Invalid event_type '{self.event_type}'. "
                f"Must be one of {sorted(VALID_EVENT_TYPES)}"
            )

        # Coerce timestamp strings to datetime objects
        if isinstance(self.timestamp, str):
            self.timestamp = datetime.fromisoformat(self.timestamp)

        # Clamp risk_score to [0.0, 1.0]
        self.risk_score = max(0.0, min(1.0, float(self.risk_score)))


# ── Persistence layer ────────────────────────────────────────────────────────
_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS behavior_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     TEXT    NOT NULL,
    event_type  TEXT    NOT NULL,
    url         TEXT    NOT NULL,
    risk_score  REAL    NOT NULL,
    verdict     TEXT    NOT NULL,
    timestamp   TEXT    NOT NULL,
    session_id  TEXT    NOT NULL
);
"""

_INSERT_SQL = """
INSERT INTO behavior_events
    (user_id, event_type, url, risk_score, verdict, timestamp, session_id)
VALUES
    (?, ?, ?, ?, ?, ?, ?);
"""

_SELECT_USER_SQL = """
SELECT user_id, event_type, url, risk_score, verdict, timestamp, session_id
FROM behavior_events
WHERE user_id = ?
ORDER BY timestamp DESC
LIMIT ?;
"""

_SELECT_ALL_SQL = """
SELECT user_id, event_type, url, risk_score, verdict, timestamp, session_id
FROM behavior_events
ORDER BY timestamp DESC;
"""


class BehaviorStore:
    """SQLite-backed store for user behavior events.

    Parameters
    ----------
    db_path : str, optional
        Path to the SQLite database file.  Defaults to ``behavior_data.db``
        in the same directory as this module.
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = os.path.join(os.path.dirname(__file__), "behavior_data.db")
        self.db_path = db_path
        self._init_db()

    # ── Private helpers ──────────────────────────────────────────────────
    def _get_connection(self) -> sqlite3.Connection:
        """Return a new connection with WAL mode for better concurrency."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def _init_db(self) -> None:
        """Create the events table if it does not already exist."""
        with self._get_connection() as conn:
            conn.execute(_CREATE_TABLE_SQL)
            conn.commit()

    # ── Public API ───────────────────────────────────────────────────────
    def log_event(self, event: BehaviorEvent) -> None:
        """Persist a single :class:`BehaviorEvent` to the database.

        Parameters
        ----------
        event : BehaviorEvent
            The event to record.  ``event_type`` is validated on construction.
        """
        with self._get_connection() as conn:
            conn.execute(
                _INSERT_SQL,
                (
                    event.user_id,
                    event.event_type,
                    event.url,
                    event.risk_score,
                    event.verdict,
                    event.timestamp.isoformat(),
                    event.session_id,
                ),
            )
            conn.commit()

    def get_user_events(self, user_id: str, last_n: int = 100) -> List[dict]:
        """Return the most recent *last_n* events for a given user.

        Parameters
        ----------
        user_id : str
            The user whose events to retrieve.
        last_n : int, optional
            Maximum number of events to return (default ``100``).

        Returns
        -------
        list[dict]
            Each dict mirrors the :class:`BehaviorEvent` fields.
        """
        with self._get_connection() as conn:
            cursor = conn.execute(_SELECT_USER_SQL, (user_id, last_n))
            columns = [
                "user_id",
                "event_type",
                "url",
                "risk_score",
                "verdict",
                "timestamp",
                "session_id",
            ]
            return [dict(zip(columns, row)) for row in cursor.fetchall()]

    def get_all_events(self) -> pd.DataFrame:
        """Return every recorded event as a pandas DataFrame.

        Returns
        -------
        pd.DataFrame
            Columns match the :class:`BehaviorEvent` fields.  The
            ``timestamp`` column is parsed as ``datetime64``.
        """
        with self._get_connection() as conn:
            df = pd.read_sql_query(_SELECT_ALL_SQL, conn)

        if not df.empty:
            df["timestamp"] = pd.to_datetime(df["timestamp"])

        return df
