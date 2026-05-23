import sqlite3
import json
from datetime import datetime, timedelta

DB_FILE = 'ila_soc.db'

def get_db_connection():
    """Get a direct database connection"""
    conn = sqlite3.connect(DB_FILE, timeout=20)
    conn.row_factory = sqlite3.Row
    return conn

def init_database():
    conn = sqlite3.connect(DB_FILE, timeout=20)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            message TEXT NOT NULL,
            status TEXT NOT NULL,
            actions_taken TEXT,
            blocked_ip TEXT,
            vt_status TEXT
        )
    ''')
    
    try:
        cursor.execute('ALTER TABLE logs ADD COLUMN vt_status TEXT')
        print("[OK] Added vt_status column to logs table")
    except sqlite3.OperationalError:
        pass
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS threat_cache (
            ip TEXT PRIMARY KEY,
            vt_status TEXT NOT NULL,
            last_checked TEXT NOT NULL
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vt_cache_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            event_type TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    ''')
    
    try:
        cursor.execute('ALTER TABLE logs ADD COLUMN sent_to_analytics INTEGER DEFAULT 0')
        print("[OK] Added sent_to_analytics column to logs table")
    except sqlite3.OperationalError:
        pass
    
    try:
        cursor.execute('ALTER TABLE logs ADD COLUMN analyst_status TEXT')
        print("[OK] Added analyst_status column to logs table")
    except sqlite3.OperationalError:
        pass
    
    # Upgrade users table schema to support new authentication requirements
    cursor.execute("PRAGMA table_info(users)")
    columns = [col[1] for col in cursor.fetchall()]
    
    if not columns:
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                email TEXT UNIQUE NOT NULL,
                full_name TEXT,
                password_hash TEXT,
                auth_provider TEXT DEFAULT 'local',
                organization TEXT,
                role TEXT DEFAULT 'SOC_ANALYST',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_login TEXT,
                profile_picture TEXT,
                is_active INTEGER DEFAULT 1
            )
        ''')
    elif 'email' not in columns:
        print("[INFO] Upgrading users table schema...")
        cursor.execute("ALTER TABLE users RENAME TO users_old")
        cursor.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                email TEXT UNIQUE NOT NULL,
                full_name TEXT,
                password_hash TEXT,
                auth_provider TEXT DEFAULT 'local',
                organization TEXT,
                role TEXT DEFAULT 'SOC_ANALYST',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_login TEXT,
                profile_picture TEXT,
                is_active INTEGER DEFAULT 1
            )
        ''')
        cursor.execute('''
            INSERT INTO users (id, username, email, full_name, password_hash, role, created_at, updated_at, last_login)
            SELECT id, username, username, username, password_hash, role, created_at, created_at, last_login FROM users_old
        ''')
        cursor.execute("DROP TABLE users_old")
        print("[OK] Users table upgraded successfully")
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            session_token TEXT UNIQUE NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS agents (
            agent_id TEXT PRIMARY KEY,
            hostname TEXT NOT NULL,
            ip_address TEXT,
            os_type TEXT,
            registered_at TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            logs_sent INTEGER DEFAULT 0,
            status TEXT DEFAULT 'active'
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_engine TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence REAL NOT NULL,
            raw_log TEXT NOT NULL,
            host TEXT,
            user TEXT,
            timestamp TEXT NOT NULL,
            status TEXT DEFAULT "New",
            reviewed_by TEXT,
            suppression_flag INTEGER DEFAULT 0,
            false_positive_flag INTEGER DEFAULT 0,
            incident_id INTEGER,
            log_id INTEGER,
            FOREIGN KEY (incident_id) REFERENCES incidents(id),
            FOREIGN KEY (log_id) REFERENCES logs(id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS url_checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            domain TEXT,
            risk_score REAL NOT NULL,
            verdict TEXT NOT NULL,
            reason TEXT,
            nudge_level TEXT,
            features_json TEXT,
            checked_at TEXT NOT NULL,
            response_time_ms REAL
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS url_feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            risk_score REAL,
            verdict TEXT,
            action TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    ''')
    
    # Incident management tables
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_id INTEGER,
            incident_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT,
            description TEXT,
            status TEXT NOT NULL,
            owner TEXT,
            tier TEXT DEFAULT "L1",
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    ''')

    # Migration for incidents table - adding missing columns safely
    cursor.execute("PRAGMA table_info(incidents)")
    columns = [col[1] for col in cursor.fetchall()]
    
    if 'title' not in columns:
        cursor.execute('ALTER TABLE incidents ADD COLUMN title TEXT')
    if 'owner' not in columns:
        cursor.execute('ALTER TABLE incidents ADD COLUMN owner TEXT')
    if 'tier' not in columns:
        cursor.execute('ALTER TABLE incidents ADD COLUMN tier TEXT DEFAULT "L1"')
    if 'summary' not in columns:
        cursor.execute('ALTER TABLE incidents ADD COLUMN summary TEXT')
    if 'confidence' not in columns:
        cursor.execute('ALTER TABLE incidents ADD COLUMN confidence REAL DEFAULT 0')
    if 'mitre_mappings' not in columns:
        cursor.execute('ALTER TABLE incidents ADD COLUMN mitre_mappings TEXT')
    if 'timeline' not in columns:
        cursor.execute('ALTER TABLE incidents ADD COLUMN timeline TEXT')
    if 'process_tree' not in columns:
        cursor.execute('ALTER TABLE incidents ADD COLUMN process_tree TEXT')
    if 'iocs' not in columns:
        cursor.execute('ALTER TABLE incidents ADD COLUMN iocs TEXT')
    if 'evidence' not in columns:
        cursor.execute('ALTER TABLE incidents ADD COLUMN evidence TEXT')
    if 'audit_history' not in columns:
        cursor.execute('ALTER TABLE incidents ADD COLUMN audit_history TEXT')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS incident_phases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            phase_name TEXT NOT NULL,
            status TEXT NOT NULL,
            analyst TEXT,
            notes TEXT,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (incident_id) REFERENCES incidents(id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS incident_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            author TEXT NOT NULL,
            note TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (incident_id) REFERENCES incidents(id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS incident_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER,
            action_type TEXT NOT NULL,
            action_details TEXT,
            performed_by TEXT DEFAULT 'system',
            performed_at TEXT NOT NULL,
            result TEXT,
            FOREIGN KEY (incident_id) REFERENCES incidents(id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS incident_recommendations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            category TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (incident_id) REFERENCES incidents(id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS incident_iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            ioc TEXT NOT NULL,
            requested_at TEXT NOT NULL,
            FOREIGN KEY (incident_id) REFERENCES incidents(id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS incident_response_summaries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            summary TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (incident_id) REFERENCES incidents(id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS incident_escalations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            from_tier TEXT NOT NULL,
            to_tier TEXT NOT NULL,
            reason TEXT,
            analyst TEXT,
            escalated_at TEXT NOT NULL,
            notify INTEGER DEFAULT 0,
            FOREIGN KEY (incident_id) REFERENCES incidents(id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sla_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            phase_name TEXT NOT NULL,
            deadline TEXT NOT NULL,
            overdue INTEGER DEFAULT 0,
            FOREIGN KEY (incident_id) REFERENCES incidents(id)
        )
    ''')
    
    # Add Performance Indexes
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_status ON logs(status)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_fp ON alerts(false_positive_flag)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_at)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_log_id ON alerts(log_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_incidents_log_id ON incidents(log_id)')
    
    conn.commit()
    conn.close()
    print("[OK] Database initialized successfully with optimization indexes")

def save_log(timestamp, message, status, actions_taken=None, blocked_ip=None, vt_status=None):
    conn = sqlite3.connect(DB_FILE, timeout=20)
    cursor = conn.cursor()
    
    actions_json = json.dumps(actions_taken) if actions_taken else None
    message_json = json.dumps(message)
    
    cursor.execute('''
        INSERT INTO logs (timestamp, message, status, actions_taken, blocked_ip, vt_status)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (timestamp, message_json, status, actions_json, blocked_ip, vt_status))
    
    log_id = cursor.lastrowid
    
    # NEW: Automatically promote Suspicious/Malicious logs to the Alert Triage Queue
    if status in ['Malicious', 'Suspicious']:
        severity = 'CRITICAL' if status == 'Malicious' else 'MEDIUM'
        confidence = 0.85 # Default confidence for automated detections
        
        # Extract host/user if possible from message
        host = 'Unknown'
        user = 'Unknown'
        if isinstance(message, dict):
            host = message.get('hostname') or message.get('host') or 'Unknown'
            user = message.get('user') or message.get('username') or 'Unknown'
        elif isinstance(message, str):
            try:
                msg_obj = json.loads(message)
                host = msg_obj.get('hostname') or msg_obj.get('host') or 'Unknown'
                user = msg_obj.get('user') or msg_obj.get('username') or 'Unknown'
            except: pass

        cursor.execute('''
            INSERT INTO alerts (source_engine, severity, confidence, raw_log, host, user, timestamp, status, log_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', ('Auto-Detection', severity, confidence, message_json, host, user, timestamp, 'New', log_id))

    conn.commit()
    conn.close()

def get_logs_paginated(page=1, per_page=50, status_filter=None):
    """Fetch a subset of logs for paginated views"""
    conn = sqlite3.connect(DB_FILE, timeout=20)
    cursor = conn.cursor()
    
    offset = (page - 1) * per_page
    query = 'SELECT id, timestamp, message, status, actions_taken, blocked_ip, vt_status, sent_to_analytics, analyst_status FROM logs'
    params = []
    
    if status_filter and status_filter.lower() != 'all':
        query += ' WHERE status = ?'
        params.append(status_filter.capitalize())
        
    query += ' ORDER BY id DESC LIMIT ? OFFSET ?'
    params.extend([per_page, offset])
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    
    logs = []
    for row in rows:
        log_entry = {
            'id': row[0],
            'timestamp': row[1],
            'message': json.loads(row[2]) if row[2] else '',
            'status': row[3],
            'actions_taken': json.loads(row[4]) if row[4] else [],
            'blocked_ip': row[5],
            'vt_status': row[6],
            'sent_to_analytics': row[7],
            'analyst_status': row[8]
        }
        logs.append(log_entry)
    
    # Get total count for pagination UI
    count_query = 'SELECT COUNT(*) FROM logs'
    if status_filter and status_filter.lower() != 'all':
        count_query += ' WHERE status = ?'
        cursor.execute(count_query, [status_filter.capitalize()])
    else:
        cursor.execute(count_query)
    total_count = cursor.fetchone()[0]
    
    conn.close()
    return logs, total_count


def get_all_logs():
    return get_logs_paginated(page=1, per_page=1000)[0]

def update_log_status(log_id, new_status):
    """Update the analyst-assigned status of a log"""
    conn = sqlite3.connect(DB_FILE, timeout=20)
    cursor = conn.cursor()
    
    cursor.execute('UPDATE logs SET analyst_status = ? WHERE id = ?', (new_status, log_id))
    updated = cursor.rowcount > 0
    
    conn.commit()
    conn.close()
    return updated

def send_logs_to_analytics(log_ids):
    """Mark logs as sent to analytics for further analysis"""
    conn = sqlite3.connect(DB_FILE, timeout=20)
    cursor = conn.cursor()
    
    placeholders = ','.join('?' * len(log_ids))
    cursor.execute(f'UPDATE logs SET sent_to_analytics = 1 WHERE id IN ({placeholders})', log_ids)
    updated = cursor.rowcount
    
    conn.commit()
    conn.close()
    return updated

def get_analytics_logs():
    """Get logs that have been sent to analytics (Malicious or Suspicious)"""
    conn = sqlite3.connect(DB_FILE, timeout=20)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, timestamp, message, status, actions_taken, blocked_ip, vt_status, sent_to_analytics, analyst_status 
        FROM logs 
        WHERE sent_to_analytics = 1 
        ORDER BY id DESC
    ''')
    rows = cursor.fetchall()
    
    logs = []
    for row in rows:
        log_entry = {
            'id': row[0],
            'timestamp': row[1],
            'message': json.loads(row[2]) if row[2] else '',
            'status': row[3],
            'actions_taken': json.loads(row[4]) if row[4] else [],
            'blocked_ip': row[5],
            'vt_status': row[6] if len(row) > 6 else None,
            'sent_to_analytics': row[7] if len(row) > 7 else 0,
            'analyst_status': row[8] if len(row) > 8 else None
        }
        logs.append(log_entry)
    
    conn.close()
    return logs

def remove_from_analytics(log_id):
    """Remove a log from analytics queue"""
    conn = sqlite3.connect(DB_FILE, timeout=20)
    cursor = conn.cursor()
    
    cursor.execute('UPDATE logs SET sent_to_analytics = 0 WHERE id = ?', (log_id,))
    updated = cursor.rowcount > 0
    
    conn.commit()
    conn.close()
    return updated

def save_blocked_ip(ip):
    conn = sqlite3.connect(DB_FILE, timeout=20)
    cursor = conn.cursor()
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    try:
        cursor.execute('''
            INSERT OR IGNORE INTO blocked_ips (ip, timestamp)
            VALUES (?, ?)
        ''', (ip, timestamp))
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    
    conn.close()

def get_blocked_ips():
    conn = sqlite3.connect(DB_FILE, timeout=20)
    cursor = conn.cursor()
    
    cursor.execute('SELECT ip FROM blocked_ips')
    rows = cursor.fetchall()
    
    ips = [row[0] for row in rows]
    
    conn.close()
    return ips

def get_cached_vt_result(ip):
    """
    Retrieve cached VirusTotal result for an IP if it's fresh (< 24 hours old).
    
    Args:
        ip (str): IP address to check
        
    Returns:
        dict or None: Cached VT result if fresh, None otherwise
    """
    conn = sqlite3.connect(DB_FILE, timeout=20)
    cursor = conn.cursor()
    
    cursor.execute('SELECT vt_status, last_checked FROM threat_cache WHERE ip = ?', (ip,))
    row = cursor.fetchone()
    
    conn.close()
    
    if row:
        vt_status_json = row[0]
        last_checked_str = row[1]
        
        last_checked = datetime.strptime(last_checked_str, "%Y-%m-%d %H:%M:%S")
        cache_age = datetime.now() - last_checked
        
        if cache_age < timedelta(hours=24):
            log_cache_event(ip, 'cache_hit')
            return json.loads(vt_status_json)
    
    log_cache_event(ip, 'cache_miss')
    return None

def save_vt_cache(ip, vt_result, is_refresh=False):
    """
    Save VirusTotal result to cache for an IP.
    
    Args:
        ip (str): IP address
        vt_result (dict): VirusTotal result dictionary
        is_refresh (bool): Whether this is a cache refresh (True) or initial save (False)
    """
    conn = sqlite3.connect(DB_FILE, timeout=20)
    cursor = conn.cursor()
    
    vt_status_json = json.dumps(vt_result)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    cursor.execute('''
        INSERT OR REPLACE INTO threat_cache (ip, vt_status, last_checked)
        VALUES (?, ?, ?)
    ''', (ip, vt_status_json, timestamp))
    
    conn.commit()
    conn.close()
    
    event_type = 'cache_refresh' if is_refresh else 'cache_save'
    log_cache_event(ip, event_type)

def log_cache_event(ip, event_type):
    """
    Log a cache event (hit, miss, refresh, delete).
    
    Args:
        ip (str): IP address
        event_type (str): Type of event (cache_hit, cache_miss, cache_refresh, cache_delete)
    """
    conn = sqlite3.connect(DB_FILE, timeout=20)
    cursor = conn.cursor()
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    cursor.execute('''
        INSERT INTO vt_cache_events (ip, event_type, timestamp)
        VALUES (?, ?, ?)
    ''', (ip, event_type, timestamp))
    
    conn.commit()
    conn.close()

def get_all_cache_entries():
    """
    Retrieve all cached VirusTotal results.
    
    Returns:
        list: List of cache entries with IP, status, and last checked time
    """
    conn = sqlite3.connect(DB_FILE, timeout=20)
    cursor = conn.cursor()
    
    cursor.execute('SELECT ip, vt_status, last_checked FROM threat_cache ORDER BY last_checked DESC')
    rows = cursor.fetchall()
    
    cache_entries = []
    for row in rows:
        vt_result = json.loads(row[1])
        cache_entry = {
            'ip': row[0],
            'vt_status': vt_result.get('status', 'Unknown'),
            'last_checked': row[2],
            'raw_stats': {
                'malicious': vt_result.get('malicious', 0),
                'suspicious': vt_result.get('suspicious', 0),
                'harmless': vt_result.get('harmless', 0),
                'undetected': vt_result.get('undetected', 0)
            }
        }
        cache_entries.append(cache_entry)
    
    conn.close()
    return cache_entries

def delete_cache_entry(ip):
    """
    Delete a specific cache entry.
    
    Args:
        ip (str): IP address to delete from cache
        
    Returns:
        bool: True if deleted, False if not found
    """
    conn = sqlite3.connect(DB_FILE, timeout=20)
    cursor = conn.cursor()
    
    cursor.execute('DELETE FROM threat_cache WHERE ip = ?', (ip,))
    deleted = cursor.rowcount > 0
    
    conn.commit()
    conn.close()
    
    if deleted:
        log_cache_event(ip, 'cache_delete')
    
    return deleted

def clear_all_cache():
    """
    Clear all cache entries.
    
    Returns:
        int: Number of entries deleted
    """
    conn = sqlite3.connect(DB_FILE, timeout=20)
    cursor = conn.cursor()
    
    cursor.execute('SELECT COUNT(*) FROM threat_cache')
    count = cursor.fetchone()[0]
    
    cursor.execute('DELETE FROM threat_cache')
    
    conn.commit()
    conn.close()
    
    log_cache_event('ALL', 'cache_clear')
    
    return count

def clear_all_events():
    """
    Clear all logs, blocked IPs, incidents, and reset the dashboard.
    
    Returns:
        dict: Count of deleted entries from each table
    """
    conn = sqlite3.connect(DB_FILE, timeout=20)
    cursor = conn.cursor()
    
    cursor.execute('SELECT COUNT(*) FROM logs')
    logs_count = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM blocked_ips')
    blocked_ips_count = cursor.fetchone()[0]
    
    incidents_count = 0
    actions_count = 0
    try:
        cursor.execute('SELECT COUNT(*) FROM incidents')
        incidents_count = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM incident_actions')
        actions_count = cursor.fetchone()[0]
    except sqlite3.OperationalError:
        pass
    
    cursor.execute('DELETE FROM logs')
    cursor.execute('DELETE FROM blocked_ips')
    
    try:
        cursor.execute('DELETE FROM incidents')
        cursor.execute('DELETE FROM incident_actions')
    except sqlite3.OperationalError:
        pass
    
    conn.commit()
    conn.close()
    
    return {
        'logs_deleted': logs_count,
        'blocked_ips_deleted': blocked_ips_count,
        'incidents_deleted': incidents_count,
        'actions_deleted': actions_count
    }


def delete_all_logs():
    """
    Delete all logs from the database.
    
    Returns:
        int: Number of logs deleted
    """
    conn = sqlite3.connect(DB_FILE, timeout=20)
    cursor = conn.cursor()
    
    cursor.execute('SELECT COUNT(*) FROM logs')
    count = cursor.fetchone()[0]
    
    cursor.execute('DELETE FROM logs')
    conn.commit()
    conn.close()
    
    return count


def get_optimized_stats():
    """Get SOC metrics using a single efficient aggregation query"""
    conn = sqlite3.connect(DB_FILE, timeout=20)
    cursor = conn.cursor()
    
    # Combined query for all counts
    cursor.execute('''
        SELECT 
            (SELECT COUNT(*) FROM logs) as total_logs,
            (SELECT COUNT(*) FROM logs WHERE status = "Malicious") as malicious_logs,
            (SELECT COUNT(*) FROM logs WHERE status = "Suspicious") as suspicious_logs,
            (SELECT COUNT(*) FROM alerts WHERE status = "New") as active_alerts,
            (SELECT COUNT(*) FROM alerts WHERE false_positive_flag = 1) as false_positives,
            (SELECT COUNT(*) FROM incidents WHERE status != "Resolved") as open_incidents,
            (SELECT COUNT(*) FROM incidents WHERE status = "Resolved") as resolved_incidents,
            (SELECT COUNT(*) FROM blocked_ips) as blocked_ips_count
    ''')
    
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return {
            'total_logs': 0, 'malicious_logs': 0, 'suspicious_logs': 0, 'normal_logs': 0,
            'active_alerts': 0, 'false_positives': 0, 'open_incidents': 0, 
            'resolved_incidents': 0, 'blocked_ips_count': 0
        }
        
    res = {
        'total_logs': row[0],
        'malicious_logs': row[1],
        'suspicious_logs': row[2],
        'normal_logs': row[0] - row[1] - row[2],
        'active_alerts': row[3],
        'false_positives': row[4],
        'open_incidents': row[5],
        'resolved_incidents': row[6],
        'blocked_ips_count': row[7]
    }
    
    return res


    return res


def get_attack_distribution():
    """Get distribution of attack types using SQL aggregation for performance"""
    conn = sqlite3.connect(DB_FILE, timeout=20)
    cursor = conn.cursor()
    
    # These patterns match DataManager._detect_attack_type logic
    cursor.execute('''
        SELECT 
            CASE 
                WHEN (LOWER(message) LIKE '%failed login%' OR LOWER(message) LIKE '%authentication failure%' OR LOWER(message) LIKE '%invalid password%') THEN 'Brute Force'
                WHEN (LOWER(message) LIKE '%sql%' OR LOWER(message) LIKE '%select * from%' OR LOWER(message) LIKE '%union select%' OR LOWER(message) LIKE '%drop table%') THEN 'SQL Injection'
                WHEN (LOWER(message) LIKE '%<script%' OR LOWER(message) LIKE '%javascript:%' OR LOWER(message) LIKE '%onerror=%') THEN 'XSS'
                WHEN (LOWER(message) LIKE '%cmd.exe%' OR LOWER(message) LIKE '%/bin/sh%' OR LOWER(message) LIKE '%&&%' OR LOWER(message) LIKE '%||%' OR LOWER(message) LIKE '%;rm%') THEN 'Command Injection'
                WHEN (LOWER(message) LIKE '%../%' OR LOWER(message) LIKE '%..\\\\%' OR LOWER(message) LIKE '%/etc/passwd%') THEN 'Path Traversal'
                WHEN (LOWER(message) LIKE '%sudo %' OR LOWER(message) LIKE '%runas %' OR LOWER(message) LIKE '%privilege %') THEN 'Privilege Escalation'
                WHEN (LOWER(message) LIKE '%malware%' OR LOWER(message) LIKE '%virus%' OR LOWER(message) LIKE '%trojan%' OR LOWER(message) LIKE '%ransomware%') THEN 'Malware'
                WHEN (LOWER(message) LIKE '%exfiltrat%' OR LOWER(message) LIKE '%upload%' OR LOWER(message) LIKE '%transfer%') THEN 'Data Exfiltration'
                WHEN (LOWER(message) LIKE '%scan%' OR LOWER(message) LIKE '%nmap%' OR LOWER(message) LIKE '%port scan%') THEN 'Reconnaissance'
                WHEN (LOWER(message) LIKE '%credential%' OR LOWER(message) LIKE '%password%' OR LOWER(message) LIKE '%hash dump%') THEN 'Credential Theft'
                ELSE 'Other Malicious'
            END as attack_type,
            COUNT(*) as count
        FROM logs
        WHERE status = 'Malicious'
        GROUP BY attack_type
        ORDER BY count DESC
    ''')
    
    results = {row[0]: row[1] for row in cursor.fetchall()}
    conn.close()
    return results


def get_cache_stats():
    """
    Get cache statistics.
    
    Returns:
        dict: Cache stats including total entries, hit rate, last refresh
    """
    conn = sqlite3.connect(DB_FILE, timeout=20)
    cursor = conn.cursor()
    
    # Total cached IPs
    cursor.execute('SELECT COUNT(*) FROM threat_cache')
    total_cached = cursor.fetchone()[0]
    
    # Cache events count
    cursor.execute('SELECT COUNT(*) FROM vt_cache_events WHERE event_type = "cache_hit"')
    cache_hits = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM vt_cache_events WHERE event_type = "cache_miss"')
    cache_misses = cursor.fetchone()[0]
    
    total_checks = cache_hits + cache_misses
    cache_hit_rate = (cache_hits / total_checks * 100) if total_checks > 0 else 0
    
    # Last cache refresh
    cursor.execute('SELECT MAX(last_checked) FROM threat_cache')
    last_refresh = cursor.fetchone()[0]
    
    conn.close()
    
    return {
        'total_cached': total_cached,
        'cache_hits': cache_hits,
        'cache_misses': cache_misses,
        'cache_hit_rate': round(cache_hit_rate, 2),
        'last_refresh': last_refresh
    }


def init_incidents_table():
    """Initialize the incidents tracking table - delegates to main init_database"""
    init_database()


def get_logs_by_time_range(start_time=None, end_time=None, status_filter=None):
    """
    Get logs filtered by time range and optional status.
    
    Args:
        start_time (str): Start datetime in format 'YYYY-MM-DD HH:MM:SS'
        end_time (str): End datetime in format 'YYYY-MM-DD HH:MM:SS'
        status_filter (str): Optional status filter ('Malicious', 'Suspicious', 'Normal')
    
    Returns:
        list: Filtered log entries
    """
    conn = sqlite3.connect(DB_FILE, timeout=20)
    cursor = conn.cursor()
    
    query = 'SELECT id, timestamp, message, status, actions_taken, blocked_ip, vt_status FROM logs WHERE 1=1'
    params = []
    
    if start_time:
        query += ' AND timestamp >= ?'
        params.append(start_time)
    
    if end_time:
        query += ' AND timestamp <= ?'
        params.append(end_time)
    
    if status_filter and status_filter.lower() != 'all':
        if status_filter.lower() == 'normal':
            query += ' AND (status = ? OR status = ?)'
            params.extend(['Normal', 'OK'])
        else:
            query += ' AND status = ?'
            params.append(status_filter)
    
    query += ' ORDER BY id DESC'
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    
    logs = []
    for row in rows:
        log_entry = {
            'id': row[0],
            'timestamp': row[1],
            'message': json.loads(row[2]) if row[2] else '',
            'status': row[3],
            'actions_taken': json.loads(row[4]) if row[4] else [],
            'blocked_ip': row[5],
            'vt_status': row[6] if len(row) > 6 else None
        }
        logs.append(log_entry)
    
    conn.close()
    return logs


def create_incident(log_id, incident_type, severity, ip_address, description):
    """Create a new incident record"""
    conn = sqlite3.connect(DB_FILE, timeout=20)
    cursor = conn.cursor()
    
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    cursor.execute('''
        INSERT INTO incidents (log_id, incident_type, severity, status, ip_address, description, created_at, updated_at)
        VALUES (?, ?, ?, 'open', ?, ?, ?, ?)
    ''', (log_id, incident_type, severity, ip_address, description, now, now))
    
    incident_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return incident_id


def log_incident_action(incident_id, action_type, action_details, performed_by='system', result='success'):
    """Log an action taken on an incident"""
    conn = sqlite3.connect(DB_FILE, timeout=20)
    cursor = conn.cursor()
    
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    cursor.execute('''
        INSERT INTO incident_actions (incident_id, action_type, action_details, performed_by, performed_at, result)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (incident_id, action_type, action_details, performed_by, now, result))
    
    cursor.execute('''
        UPDATE incidents SET updated_at = ?, actions_taken = COALESCE(actions_taken || ', ', '') || ?
        WHERE id = ?
    ''', (now, action_type, incident_id))
    
    conn.commit()
    conn.close()


def update_incident_status(incident_id, new_status, notes=None):
    """Update incident status"""
    conn = sqlite3.connect(DB_FILE, timeout=20)
    cursor = conn.cursor()
    
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    if notes:
        cursor.execute('''
            UPDATE incidents SET status = ?, updated_at = ?, notes = COALESCE(notes || '\n', '') || ?
            WHERE id = ?
        ''', (new_status, now, notes, incident_id))
    else:
        cursor.execute('''
            UPDATE incidents SET status = ?, updated_at = ?
            WHERE id = ?
        ''', (new_status, now, incident_id))
    
    conn.commit()
    conn.close()


def get_incident_summaries():
    """Get only essential fields for the incident list to improve performance"""
    conn = sqlite3.connect(DB_FILE, timeout=20)
    cursor = conn.cursor()
    cursor.execute('SELECT id, incident_type, severity, status, title, owner, tier, created_at FROM incidents ORDER BY created_at DESC')
    rows = cursor.fetchall()
    
    summaries = []
    for row in rows:
        summaries.append({
            'id': row[0],
            'incident_type': row[1],
            'severity': row[2],
            'status': row[3],
            'title': row[4],
            'owner': row[5],
            'tier': row[6],
            'created_at': row[7]
        })
    conn.close()
    return summaries


def get_all_incidents(status_filter=None):
    """Get all incidents with optional status filter"""
    conn = sqlite3.connect(DB_FILE, timeout=20)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    query = 'SELECT * FROM incidents'
    params = []
    if status_filter:
        query += ' WHERE status = ?'
        params.append(status_filter)
    query += ' ORDER BY created_at DESC'
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_incident_by_id(incident_id):
    """Get a single incident by its ID as a dictionary"""
    conn = sqlite3.connect(DB_FILE, timeout=20)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM incidents WHERE id = ?', (incident_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_incident_actions(incident_id):
    """Get all actions for a specific incident"""
    conn = sqlite3.connect(DB_FILE, timeout=20)
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM incident_actions WHERE incident_id = ? ORDER BY performed_at DESC', (incident_id,))
    rows = cursor.fetchall()
    
    actions = []
    for row in rows:
        actions.append({
            'id': row[0],
            'incident_id': row[1],
            'action_type': row[2],
            'action_details': row[3],
            'performed_by': row[4],
            'performed_at': row[5],
            'result': row[6]
        })
    
    conn.close()
    return actions


def get_log_by_id(log_id):
    """Get a specific log entry by ID"""
    conn = sqlite3.connect(DB_FILE, timeout=20)
    cursor = conn.cursor()
    
    cursor.execute('SELECT id, timestamp, message, status, actions_taken, blocked_ip, vt_status FROM logs WHERE id = ?', (log_id,))
    row = cursor.fetchone()
    
    conn.close()
    
    if row:
        return {
            'id': row[0],
            'timestamp': row[1],
            'message': json.loads(row[2]) if row[2] else '',
            'status': row[3],
            'actions_taken': json.loads(row[4]) if row[4] else [],
            'blocked_ip': row[5],
            'vt_status': row[6] if len(row) > 6 else None
        }
    return None


def create_user(email, password_hash, full_name='', username=None, auth_provider='local', organization='', role='SOC_ANALYST', profile_picture=None):
    """Create a new user"""
    conn = sqlite3.connect(DB_FILE, timeout=20)
    cursor = conn.cursor()
    
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    try:
        cursor.execute('''
            INSERT INTO users (username, email, full_name, password_hash, auth_provider, organization, role, created_at, updated_at, profile_picture)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (username or email, email, full_name, password_hash, auth_provider, organization, role, now, now, profile_picture))
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        return user_id
    except sqlite3.IntegrityError:
        conn.close()
        return None


def get_user_by_username(username):
    """Get user by username (or email)"""
    conn = sqlite3.connect(DB_FILE, timeout=20)
    cursor = conn.cursor()
    
    cursor.execute('SELECT id, username, email, full_name, password_hash, auth_provider, organization, role, created_at, updated_at, last_login, profile_picture, is_active FROM users WHERE username = ? OR email = ?', (username, username))
    row = cursor.fetchone()
    conn.close()
    
    if row:
        return {
            'id': row[0],
            'username': row[1],
            'email': row[2],
            'full_name': row[3],
            'password_hash': row[4],
            'auth_provider': row[5],
            'organization': row[6],
            'role': row[7],
            'created_at': row[8],
            'updated_at': row[9],
            'last_login': row[10],
            'profile_picture': row[11],
            'is_active': row[12]
        }
    return None


def get_user_by_email(email):
    """Get user by email"""
    return get_user_by_username(email)


def update_user_password(user_id, new_password_hash):
    """Update user password"""
    conn = sqlite3.connect(DB_FILE, timeout=20)
    cursor = conn.cursor()
    
    cursor.execute('UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?', (new_password_hash, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), user_id))
    conn.commit()
    conn.close()
    return cursor.rowcount > 0


def update_user_last_login(user_id):
    """Update user's last login timestamp"""
    conn = sqlite3.connect(DB_FILE, timeout=20)
    cursor = conn.cursor()
    
    cursor.execute('UPDATE users SET last_login = ? WHERE id = ?', 
                   (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), user_id))
    conn.commit()
    conn.close()


def get_all_users():
    """Get all users"""
    conn = sqlite3.connect(DB_FILE, timeout=20)
    cursor = conn.cursor()
    
    cursor.execute('SELECT id, username, email, full_name, role, auth_provider, is_active, created_at, last_login FROM users ORDER BY id')
    rows = cursor.fetchall()
    conn.close()
    
    return [{
        'id': row[0],
        'username': row[1],
        'email': row[2],
        'full_name': row[3],
        'role': row[4],
        'auth_provider': row[5],
        'is_active': row[6],
        'created_at': row[7],
        'last_login': row[8]
    } for row in rows]


def get_setting(key, default=None):
    """Get a setting value"""
    conn = sqlite3.connect(DB_FILE, timeout=20)
    cursor = conn.cursor()
    
    cursor.execute('SELECT value FROM settings WHERE key = ?', (key,))
    row = cursor.fetchone()
    conn.close()
    
    return row[0] if row else default


def set_setting(key, value):
    """Set a setting value"""
    conn = sqlite3.connect(DB_FILE, timeout=20)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT OR REPLACE INTO settings (key, value, updated_at)
        VALUES (?, ?, ?)
    ''', (key, value, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    conn.commit()
    conn.close()


def get_all_settings():
    """Get all settings"""
    conn = sqlite3.connect(DB_FILE, timeout=20)
    cursor = conn.cursor()
    
    cursor.execute('SELECT key, value, updated_at FROM settings')
    rows = cursor.fetchall()
    conn.close()
    
    return {row[0]: {'value': row[1], 'updated_at': row[2]} for row in rows}


def ensure_default_admin():
    """Ensure default admin user exists"""
    from werkzeug.security import generate_password_hash
    
    admin = get_user_by_username('admin')
    if not admin:
        password_hash = generate_password_hash('admin')
        create_user('admin', password_hash, 'admin')
        print("Created default admin user (username: admin, password: admin)")


def register_agent(agent_id, hostname, ip_address, os_type):
    """Register or update an agent in the database"""
    conn = sqlite3.connect(DB_FILE, timeout=20)
    cursor = conn.cursor()
    
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    cursor.execute('SELECT agent_id FROM agents WHERE agent_id = ?', (agent_id,))
    existing = cursor.fetchone()
    
    if existing:
        cursor.execute('''
            UPDATE agents SET hostname = ?, ip_address = ?, os_type = ?, last_seen = ?, status = 'active'
            WHERE agent_id = ?
        ''', (hostname, ip_address, os_type, now, agent_id))
    else:
        cursor.execute('''
            INSERT INTO agents (agent_id, hostname, ip_address, os_type, registered_at, last_seen, logs_sent, status)
            VALUES (?, ?, ?, ?, ?, ?, 0, 'active')
        ''', (agent_id, hostname, ip_address, os_type, now, now))
    
    conn.commit()
    conn.close()
    return True


def update_agent_heartbeat(agent_id):
    """Update agent's last_seen timestamp"""
    conn = sqlite3.connect(DB_FILE, timeout=20)
    cursor = conn.cursor()
    
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    cursor.execute('''
        UPDATE agents SET last_seen = ?, status = 'active'
        WHERE agent_id = ?
    ''', (now, agent_id))
    
    affected = cursor.rowcount
    conn.commit()
    conn.close()
    
    return affected > 0


def increment_agent_logs(agent_id, count=1):
    """Increment the logs_sent counter for an agent"""
    conn = sqlite3.connect(DB_FILE, timeout=20)
    cursor = conn.cursor()
    
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    cursor.execute('''
        UPDATE agents SET logs_sent = logs_sent + ?, last_seen = ?
        WHERE agent_id = ?
    ''', (count, now, agent_id))
    
    conn.commit()
    conn.close()


def get_all_agents():
    """Get all registered agents with their status"""
    conn = sqlite3.connect(DB_FILE, timeout=20)
    cursor = conn.cursor()
    
    cursor.execute('SELECT agent_id, hostname, ip_address, os_type, registered_at, last_seen, logs_sent, status FROM agents ORDER BY last_seen DESC')
    rows = cursor.fetchall()
    conn.close()
    
    agents = []
    now = datetime.now()
    
    for row in rows:
        last_seen_str = row[5]
        try:
            last_seen_dt = datetime.strptime(last_seen_str, "%Y-%m-%d %H:%M:%S")
            time_diff = (now - last_seen_dt).total_seconds()
            if time_diff > 60:
                status = 'offline'
            elif time_diff > 30:
                status = 'idle'
            else:
                status = 'active'
        except:
            status = row[7]
        
        agents.append({
            'agent_id': row[0],
            'hostname': row[1],
            'ip_address': row[2],
            'os_type': row[3],
            'registered_at': row[4],
            'last_seen': row[5],
            'logs_sent': row[6],
            'status': status
        })
    
    return agents


def get_agent_by_id(agent_id):
    """Get a specific agent by ID"""
    conn = sqlite3.connect(DB_FILE, timeout=20)
    cursor = conn.cursor()
    
    cursor.execute('SELECT agent_id, hostname, ip_address, os_type, registered_at, last_seen, logs_sent, status FROM agents WHERE agent_id = ?', (agent_id,))
    row = cursor.fetchone()
    conn.close()
    
    if row:
        return {
            'agent_id': row[0],
            'hostname': row[1],
            'ip_address': row[2],
            'os_type': row[3],
            'registered_at': row[4],
            'last_seen': row[5],
            'logs_sent': row[6],
            'status': row[7]
        }
    return None


def delete_agent(agent_id):
    """Delete an agent from the database"""
    conn = sqlite3.connect(DB_FILE, timeout=20)
    cursor = conn.cursor()
    
    cursor.execute('DELETE FROM agents WHERE agent_id = ?', (agent_id,))
    affected = cursor.rowcount
    conn.commit()
    conn.close()
    
    return affected > 0


def save_url_check(url, domain, risk_score, verdict, reason, nudge_level, features_json, response_time_ms):
    """Save a URL check result"""
    conn = sqlite3.connect(DB_FILE, timeout=20)
    cursor = conn.cursor()
    
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    cursor.execute('''
        INSERT INTO url_checks (url, domain, risk_score, verdict, reason, nudge_level, features_json, checked_at, response_time_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (url, domain, risk_score, verdict, reason, nudge_level, features_json, now, response_time_ms))
    
    check_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return check_id


def save_url_feedback(url, risk_score, verdict, action, timestamp):
    """Save user feedback on a URL check"""
    conn = sqlite3.connect(DB_FILE, timeout=20)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO url_feedback (url, risk_score, verdict, action, timestamp)
        VALUES (?, ?, ?, ?, ?)
    ''', (url, risk_score, verdict, action, timestamp))
    
    conn.commit()
    conn.close()


def get_url_check_stats():
    """Get URL check statistics"""
    conn = sqlite3.connect(DB_FILE, timeout=20)
    cursor = conn.cursor()
    
    cursor.execute('SELECT COUNT(*) FROM url_checks')
    total = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM url_checks WHERE verdict = 'Phishing'")
    phishing = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM url_checks WHERE verdict = 'Suspicious'")
    suspicious = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM url_checks WHERE verdict = 'Safe'")
    safe = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM url_feedback WHERE action = 'proceed'")
    proceeded = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM url_feedback WHERE action = 'cancel'")
    cancelled = cursor.fetchone()[0]
    
    conn.close()
    
    return {
        'total_checks': total,
        'phishing': phishing,
        'suspicious': suspicious,
        'safe': safe,
        'user_proceeded': proceeded,
        'user_cancelled': cancelled
    }


def get_recent_url_checks(limit=50):
    """Get recent URL checks"""
    conn = sqlite3.connect(DB_FILE, timeout=20)
    cursor = conn.cursor()
    
    cursor.execute('SELECT id, url, domain, risk_score, verdict, reason, nudge_level, checked_at FROM url_checks ORDER BY id DESC LIMIT ?', (limit,))
    rows = cursor.fetchall()
    conn.close()
    
    return [{
        'id': row[0],
        'url': row[1],
        'domain': row[2],
        'risk_score': row[3],
        'verdict': row[4],
        'reason': row[5],
        'nudge_level': row[6],
        'checked_at': row[7]
    } for row in rows]


def get_url_logs_paginated(page=1, per_page=25, risk_level=None, domain_search=None, date_from=None, date_to=None, sort_by='newest'):
    conn = sqlite3.connect(DB_FILE, timeout=20)
    cursor = conn.cursor()

    where_clauses = []
    params = []

    if risk_level and risk_level != 'all':
        where_clauses.append('verdict = ?')
        params.append(risk_level)

    if domain_search:
        where_clauses.append('(domain LIKE ? OR url LIKE ?)')
        params.extend([f'%{domain_search}%', f'%{domain_search}%'])

    if date_from:
        where_clauses.append('checked_at >= ?')
        params.append(date_from)

    if date_to:
        where_clauses.append('checked_at <= ?')
        params.append(date_to + ' 23:59:59')

    where_sql = ''
    if where_clauses:
        where_sql = 'WHERE ' + ' AND '.join(where_clauses)

    cursor.execute(f'SELECT COUNT(*) FROM url_checks {where_sql}', params)
    total = cursor.fetchone()[0]

    order = 'DESC' if sort_by == 'newest' else 'ASC'
    if sort_by == 'risk_high':
        order_sql = 'ORDER BY risk_score DESC'
    elif sort_by == 'risk_low':
        order_sql = 'ORDER BY risk_score ASC'
    else:
        order_sql = f'ORDER BY id {order}'

    offset = (page - 1) * per_page
    cursor.execute(f'''
        SELECT id, url, domain, risk_score, verdict, reason, nudge_level, features_json, checked_at, response_time_ms
        FROM url_checks {where_sql} {order_sql} LIMIT ? OFFSET ?
    ''', params + [per_page, offset])
    rows = cursor.fetchall()

    cursor.execute(f'SELECT COUNT(*) FROM url_checks {where_sql} AND verdict = "Phishing"' if where_sql else 'SELECT COUNT(*) FROM url_checks WHERE verdict = "Phishing"', params)
    count_phishing = cursor.fetchone()[0]
    cursor.execute(f'SELECT COUNT(*) FROM url_checks {where_sql} AND verdict = "Suspicious"' if where_sql else 'SELECT COUNT(*) FROM url_checks WHERE verdict = "Suspicious"', params)
    count_suspicious = cursor.fetchone()[0]
    cursor.execute(f'SELECT COUNT(*) FROM url_checks {where_sql} AND verdict = "Safe"' if where_sql else 'SELECT COUNT(*) FROM url_checks WHERE verdict = "Safe"', params)
    count_safe = cursor.fetchone()[0]

    conn.close()

    logs = []
    for row in rows:
        logs.append({
            'id': row[0],
            'url': row[1],
            'domain': row[2],
            'risk_score': row[3],
            'verdict': row[4],
            'reason': row[5],
            'nudge_level': row[6],
            'features_json': row[7],
            'checked_at': row[8],
            'response_time_ms': row[9]
        })

    return {
        'logs': logs,
        'total': total,
        'page': page,
        'per_page': per_page,
        'total_pages': max(1, (total + per_page - 1) // per_page),
        'counts': {
            'phishing': count_phishing,
            'suspicious': count_suspicious,
            'safe': count_safe
        }
    }


def get_url_feedback_stats():
    conn = sqlite3.connect(DB_FILE, timeout=20)
    cursor = conn.cursor()
    cursor.execute("SELECT action, COUNT(*) FROM url_feedback GROUP BY action")
    rows = cursor.fetchall()
    conn.close()
    return {row[0]: row[1] for row in rows}


def get_url_scans_over_time(days=30):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT DATE(checked_at) as scan_date, COUNT(*) as count
        FROM url_checks
        WHERE checked_at >= date('now', ?)
        GROUP BY DATE(checked_at)
        ORDER BY scan_date ASC
    ''', (f'-{days} days',))
    rows = cursor.fetchall()
    conn.close()
    return [{'date': row[0], 'count': row[1]} for row in rows]
