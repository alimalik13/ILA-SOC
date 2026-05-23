# analyst_audit_logger.py
"""Simple audit logger for incident workflow actions.
Writes immutable JSON lines to a dedicated audit log file.
"""
import json
import os
from datetime import datetime

AUDIT_LOG_PATH = os.path.join(os.path.dirname(__file__), '..', 'audit_log.jsonl')

def log_audit_action(incident_id: int, action: str, details: dict | None = None):
    """Append an audit entry.
    :param incident_id: ID of the incident the action relates to.
    :param action: A short name of the action (e.g., "escalate_to_l2").
    :param details: Optional dict with extra context.
    """
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "incident_id": incident_id,
        "action": action,
        "details": details or {},
    }
    # Ensure directory exists
    os.makedirs(os.path.dirname(AUDIT_LOG_PATH), exist_ok=True)
    with open(AUDIT_LOG_PATH, 'a', encoding='utf-8') as f:
        f.write(json.dumps(entry) + "\n")
