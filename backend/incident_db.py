# incident_db.py
"""Utility helpers for incident related DB operations.
All functions use the same DB_FILE defined in backend/database.py.
"""
import sqlite3
from datetime import datetime
from backend import database

DB_FILE = database.DB_FILE

def get_connection():
    return sqlite3.connect(DB_FILE)

# ---------------------------------------------------------------------------
# Incident CRUD
# ---------------------------------------------------------------------------
def create_incident(log_id: int, incident_type: str, severity: str, title: str, description: str, owner: str = None) -> int:
    conn = get_connection()
    cur = conn.cursor()
    now = datetime.utcnow().isoformat()
    cur.execute(
        """INSERT INTO incidents (log_id, incident_type, severity, title, description, status, owner, tier, created_at, updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (log_id, incident_type, severity, title, description, 'Preparation', owner, 'L1', now, now),
    )
    incident_id = cur.lastrowid
    conn.commit()
    conn.close()
    return incident_id

def get_incident_by_id(incident_id: int):
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute('SELECT * FROM incidents WHERE id = ?', (incident_id,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None

def update_incident_owner(incident_id: int, owner: str):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute('UPDATE incidents SET owner = ?, updated_at = ? WHERE id = ?', (owner, datetime.utcnow().isoformat(), incident_id))
    conn.commit()
    conn.close()

def update_incident_tier(incident_id: int, tier: str):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute('UPDATE incidents SET tier = ?, updated_at = ? WHERE id = ?', (tier, datetime.utcnow().isoformat(), incident_id))
    conn.commit()
    conn.close()

def update_incident_status(incident_id: int, status: str):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute('UPDATE incidents SET status = ?, updated_at = ? WHERE id = ?', (status, datetime.utcnow().isoformat(), incident_id))
    conn.commit()
    conn.close()

# ---------------------------------------------------------------------------
# Notes, Recommendations, IOCs, Summaries
# ---------------------------------------------------------------------------
def add_incident_note(incident_id: int, author: str, note: str):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute('INSERT INTO incident_notes (incident_id, author, note, created_at) VALUES (?,?,?,?)',
                (incident_id, author, note, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

def add_incident_recommendation(incident_id: int, category: str, recommendation: str):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute('INSERT INTO incident_recommendations (incident_id, category, recommendation, created_at) VALUES (?,?,?,?)',
                (incident_id, category, recommendation, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

def add_incident_ioc(incident_id: int, ioc: str):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute('INSERT INTO incident_iocs (incident_id, ioc, requested_at) VALUES (?,?,?)',
                (incident_id, ioc, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

def add_incident_response_summary(incident_id: int, summary: str):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute('INSERT INTO incident_response_summaries (incident_id, summary, created_at) VALUES (?,?,?)',
                (incident_id, summary, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

# ---------------------------------------------------------------------------
# Phase tracking
# ---------------------------------------------------------------------------
def add_incident_phase(incident_id: int, phase_name: str, status: str, analyst: str = None, notes: str = None):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute('INSERT INTO incident_phases (incident_id, phase_name, status, analyst, notes, timestamp) VALUES (?,?,?,?,?,?)',
                (incident_id, phase_name, status, analyst, notes, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

def get_incident_phases(incident_id: int):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute('SELECT phase_name, status, analyst, notes, timestamp FROM incident_phases WHERE incident_id = ? ORDER BY id ASC', (incident_id,))
    rows = cur.fetchall()
    conn.close()
    return [{'phase_name': r[0], 'status': r[1], 'analyst': r[2], 'notes': r[3], 'timestamp': r[4]} for r in rows]

def get_incident_notes(incident_id: int):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute('SELECT author, note, created_at FROM incident_notes WHERE incident_id = ? ORDER BY created_at ASC', (incident_id,))
    rows = cur.fetchall()
    conn.close()
    return [{'author': r[0], 'note': r[1], 'created_at': r[2]} for r in rows]

def get_incident_recommendations(incident_id: int):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute('SELECT category, recommendation, created_at FROM incident_recommendations WHERE incident_id = ? ORDER BY created_at ASC', (incident_id,))
    rows = cur.fetchall()
    conn.close()
    return [{'category': r[0], 'recommendation': r[1], 'created_at': r[2]} for r in rows]

def get_incident_iocs(incident_id: int):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute('SELECT ioc, requested_at FROM incident_iocs WHERE incident_id = ? ORDER BY requested_at ASC', (incident_id,))
    rows = cur.fetchall()
    conn.close()
    return [{'ioc': r[0], 'requested_at': r[1]} for r in rows]

def get_incident_response_summary(incident_id: int):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute('SELECT summary, created_at FROM incident_response_summaries WHERE incident_id = ? ORDER BY created_at DESC LIMIT 1', (incident_id,))
    row = cur.fetchone()
    conn.close()
    return {'summary': row[0], 'created_at': row[1]} if row else None
