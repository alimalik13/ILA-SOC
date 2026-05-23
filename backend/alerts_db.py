import sqlite3
from datetime import datetime
from backend import database

DB_FILE = database.DB_FILE

def get_connection():
    return sqlite3.connect(DB_FILE)

def get_all_alerts():
    conn = get_connection()
    cur = conn.cursor()
    # alert_id, source_engine, severity, confidence, raw_log, host, user, timestamp, status, reviewed_by, suppression_flag, false_positive_flag, incident_id
    cur.execute('SELECT * FROM alerts WHERE suppression_flag = 0 AND false_positive_flag = 0 ORDER BY timestamp DESC')
    rows = cur.fetchall()
    conn.close()
    
    alerts = []
    for r in rows:
        alerts.append({
            'alert_id': r[0],
            'source_engine': r[1],
            'severity': r[2],
            'confidence': r[3],
            'raw_log': r[4],
            'host': r[5],
            'user': r[6],
            'timestamp': r[7],
            'status': r[8],
            'reviewed_by': r[9],
            'suppression_flag': r[10],
            'false_positive_flag': r[11],
            'incident_id': r[12],
            'log_id': r[13]
        })
    return alerts

def get_alert_by_id(alert_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM alerts WHERE alert_id = ?', (alert_id,))
    r = cur.fetchone()
    conn.close()
    
    if r:
        return {
            'alert_id': r[0],
            'source_engine': r[1],
            'severity': r[2],
            'confidence': r[3],
            'raw_log': r[4],
            'host': r[5],
            'user': r[6],
            'timestamp': r[7],
            'status': r[8],
            'reviewed_by': r[9],
            'suppression_flag': r[10],
            'false_positive_flag': r[11],
            'incident_id': r[12],
            'log_id': r[13]
        }
    return None

def assign_alert(alert_id, user):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute('UPDATE alerts SET reviewed_by = ?, status = "Investigating" WHERE alert_id = ?', (user, alert_id))
    conn.commit()
    conn.close()
    return True

def mark_false_positive(alert_id, user):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute('UPDATE alerts SET false_positive_flag = 1, reviewed_by = ?, status = "False Positive" WHERE alert_id = ?', (user, alert_id))
    conn.commit()
    conn.close()
    return True

def suppress_alert(alert_id, user):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute('UPDATE alerts SET suppression_flag = 1, reviewed_by = ?, status = "Suppressed" WHERE alert_id = ?', (user, alert_id))
    conn.commit()
    conn.close()
    return True

def create_alert(source_engine, severity, confidence, raw_log, host, user, log_id=None):
    conn = get_connection()
    cur = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cur.execute('''
        INSERT INTO alerts (source_engine, severity, confidence, raw_log, host, user, timestamp, status, log_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, "New", ?)
    ''', (source_engine, severity, confidence, raw_log, host, user, now, log_id))
    alert_id = cur.lastrowid
    conn.commit()
    conn.close()
    return alert_id

def mark_benign(alert_id, user):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute('UPDATE alerts SET suppression_flag = 1, reviewed_by = ?, status = "Benign" WHERE alert_id = ?', (user, alert_id))
    conn.commit()
    conn.close()
    return True

def link_alert_to_incident(alert_id, incident_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute('UPDATE alerts SET incident_id = ?, status = "Promoted" WHERE alert_id = ?', (incident_id, alert_id))
    conn.commit()
    conn.close()
    return True
