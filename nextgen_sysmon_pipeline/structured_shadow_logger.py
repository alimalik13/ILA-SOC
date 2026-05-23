import os
import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

class StructuredShadowLogger:
    """
    Independent storage layer for Shadow Mode telemetry collection.
    Safely logs structured features, legacy verdicts, and raw telemetry without blocking.
    """
    def __init__(self, db_path: str = None):
        if db_path is None:
            # Default to nextgen_sysmon_pipeline/structured_feature_logs/
            base_dir = Path(__file__).resolve().parent / "structured_feature_logs"
            os.makedirs(base_dir, exist_ok=True)
            self.db_path = str(base_dir / "structured_feature_vectors.db")
        else:
            self.db_path = db_path
            
        self._init_db()
        
    def _init_db(self):
        """Initialize the shadow mode database schemas."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Table to hold the parallel pipeline evaluation metrics
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS shadow_metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            event_id TEXT,
            process_guid TEXT,
            legacy_verdict TEXT,
            raw_telemetry JSON,
            feature_vector JSON
        )
        ''')
        
        conn.commit()
        conn.close()

    def log_shadow_event(self, event_id: str, process_guid: str, legacy_verdict: str, 
                         raw_json: Dict[str, Any], feature_vector: Dict[str, float]):
        """
        Silently log the event and parallel evaluation.
        Wrapped in a broad exception handler to guarantee zero production crashes.
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
            INSERT INTO shadow_metrics 
            (timestamp, event_id, process_guid, legacy_verdict, raw_telemetry, feature_vector)
            VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                datetime.utcnow().isoformat() + "Z",
                str(event_id),
                str(process_guid),
                str(legacy_verdict),
                json.dumps(raw_json),
                json.dumps(feature_vector)
            ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            # SHADOW MODE RULE: NEVER crash the production pipeline.
            # We silently swallow logging failures to preserve main server operations.
            print(f"[SHADOW_LOGGER_ERROR] Failed to write shadow event: {e}")
