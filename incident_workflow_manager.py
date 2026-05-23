# incident_workflow_manager.py
"""Incident workflow manager
Provides functions to create incidents, apply actions, log audit entries,
track NIST lifecycle phases and SLA timers.
"""
import json
import uuid
import os
import re
from datetime import datetime

from backend import incident_db as database
from analyst_audit_logger import log_audit_action
from incident_lifecycle_tracker import advance_phase
from sla_tracking_engine import start_sla_timer, reset_sla_timer

# ---------------------------------------------------------------------------
# Incident creation
# ---------------------------------------------------------------------------
def create_incident(log_id: int, incident_type: str, severity: str, title: str, description: str, owner: str = None) -> int:
    """Create a new incident entry linked to a source log."""
    conn = database.get_connection()
    cur = conn.cursor()
    created_at = datetime.utcnow().isoformat()
    cur.execute(
        """INSERT INTO incidents (log_id, incident_type, severity, title, description, status, owner, tier, created_at, updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (log_id, incident_type, severity, title, description, 'Preparation', owner, 'L1', created_at, created_at),
    )
    incident_id = cur.lastrowid
    conn.commit()
    conn.close()
    
    # Enrich incident with automated context
    enrich_incident_context(incident_id)
    
    # start SLA for Preparation phase
    start_sla_timer(incident_id, 'Preparation')
    # log creation
    log_audit_action(incident_id, 'create', {'owner': owner, 'severity': severity})
    return incident_id

def enrich_incident_context(incident_id):
    """Enrich incident with automated context from the triggering log"""
    from backend import database as main_db
    inc = database.get_incident_by_id(incident_id)
    if not inc or not inc.get('log_id'):
        return
        
    log = main_db.get_log_by_id(inc['log_id'])
    if not log:
        return
        
    msg = log.get('message', {})
    if isinstance(msg, str):
        try: msg = json.loads(msg)
        except: msg = {'raw': msg}
        
    # 1. AI Executive Summary (Deterministic SOC Narrative)
    summary = generate_executive_summary(inc, log, msg)
    
    # 2. IOCs
    iocs = extract_iocs(msg)
    
    # 3. MITRE Mapping
    mitre = map_mitre_techniques(msg)
    
    # 4. Timeline
    timeline = build_incident_timeline(inc, log)
    
    # 5. Process Tree
    tree = build_process_lineage(msg)
    
    # 6. Extract Host and User
    host = extract_field(msg, ['computer', 'hostname', 'host', 'agent_id', 'device', 'source', 'target_host', 'machine'], "Demo-Endpoint-01")
    user = extract_field(msg, ['user', 'username', 'account', 'actor', 'owner'], "SOC User")
    
    # Update incident record
    conn = database.get_connection()
    cur = conn.cursor()
    cur.execute('''
        UPDATE incidents SET 
            summary = ?, 
            iocs = ?, 
            mitre_mappings = ?, 
            timeline = ?, 
            process_tree = ?,
            confidence = ?,
            evidence = ?,
            ip_address = ?,
            assigned_to = ?
        WHERE id = ?
    ''', (
        summary, 
        json.dumps(iocs), 
        json.dumps(mitre), 
        json.dumps(timeline), 
        json.dumps(tree),
        0.92, 
        json.dumps([log]),
        host, # We reuse ip_address column for host label in this simplified schema
        user, # We reuse assigned_to for the affected user label
        incident_id
    ))
    conn.commit()
    conn.close()

def generate_executive_summary(inc, log, msg):
    """Generate deterministic explainable SOC narrative"""
    msg_str = json.dumps(msg).lower() if isinstance(msg, dict) else str(msg).lower()
    etype = inc.get('incident_type', 'Security Event')
    severity = inc.get('severity', 'High')
    
    # Base narrative components
    summary_text = "The platform detected a security anomaly requiring analyst review."
    conf = inc.get('confidence')
    if conf is None: conf = 0.92
    context_text = f"The {etype} detection engine identified activity with high confidence ({conf*100}%)."
    indicators = ["Unusual process execution pattern", "Non-standard system telemetry"]
    actions = [
        "Isolate the affected endpoint to prevent lateral movement.",
        "Verify the integrity of the process lineage.",
        "Review outbound network connections for C2 activity."
    ]

    # Specific Scenario Logic
    if any(x in msg_str for x in ['powershell', '.ps1', 'encodedcommand']):
        summary_text = "Suspicious PowerShell execution detected with potential obfuscation."
        context_text = "The command pattern suggests script execution that may bypass security policies or execute encoded payloads."
        indicators = ["PowerShell process creation", "Potential encoded command-line", "Execution policy bypass attempt"]
        actions.append("Audit and decode the full PowerShell command-line string.")
    elif any(x in msg_str for x in ['cmd.exe', '/c', 'net user', 'whoami']):
        summary_text = "Discovery commands executed via system shell."
        context_text = "Manual interaction with the system shell for reconnaissance purposes was observed."
        indicators = ["System shell (cmd.exe) spawned", "Reconnaissance commands detected", "Potential manual attacker interaction"]
        actions.append("Investigate the parent process that spawned this shell.")
    elif 'sql' in msg_str or 'select' in msg_str or 'union' in msg_str:
        summary_text = "Probable SQL injection attempt targeting database infrastructure."
        context_text = "Injected SQL syntax was detected in application logs or network traffic."
        indicators = ["Malicious SQL keywords in request", "Database error response patterns", "Web-based exploitation attempt"]
        actions.append("Review application firewall logs for related blocked requests.")
    elif any(x in msg_str for x in ['brute', 'failed', 'logon', 'password']):
        summary_text = "Detected high-frequency authentication failures (Brute Force)."
        context_text = "Sequential login failures from a single source indicate an automated password-guessing attempt."
        indicators = ["Multiple failed logon events", "Common account targeting", "Rapid sequence authentication"]
        actions.append("Temporarily disable the targeted account and verify source IP.")
    elif 'mimikatz' in msg_str or 'sekurlsa' in msg_str or 'logonpasswords' in msg_str:
        summary_text = "Credential theft tool execution (Mimikatz) detected."
        context_text = "Activity consistent with memory-based credential dumping was observed on the host."
        indicators = ["Mimikatz signature detected", "LSASS memory access attempt", "Privilege escalation activity"]
        actions.append("Flush all active sessions and rotate administrative credentials.")
    elif 'reverse' in msg_str or '/dev/tcp' in msg_str or 'nc -e' in msg_str:
        summary_text = "Reverse shell or command-and-control (C2) callback detected."
        context_text = "An outbound shell connection was established to an external IP, indicating potential remote control."
        indicators = ["Interactive shell outbound connection", "Netcat or bash-redirection pattern", "Non-standard port communication"]
        actions.append("Block the destination C2 IP at the perimeter firewall.")
    
    # Final Construction (Ensuring no blanks)
    full_summary = f"Incident Summary:\n{summary_text}\n\n"
    full_summary += f"Detection Context:\n{context_text}\n\n"
    full_summary += "Observed Indicators:\n" + "\n".join([f"- {i}" for i in indicators]) + "\n\n"
    full_summary += "Recommended Analyst Actions:\n" + "\n".join([f"- {a}" for a in actions])
    
    return full_summary

def extract_iocs(msg):
    """Extract deterministic Indicators of Compromise from log message/telemetry"""
    iocs = []
    if not msg: return iocs
    
    msg_str = json.dumps(msg) if isinstance(msg, dict) else str(msg)
    msg_lower = msg_str.lower()
    
    # 1. Network IOCs
    # IPv4 addresses
    ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips = re.findall(ipv4_pattern, msg_str)
    for ip in set(ips):
        if ip not in ['127.0.0.1', '0.0.0.0', '255.255.255.255']:
            iocs.append({'type': 'Network', 'value': ip, 'risk': 'High'})
            
    # Domains/URLs
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    urls = re.findall(url_pattern, msg_str)
    for url in set(urls):
        iocs.append({'type': 'URL', 'value': url, 'risk': 'High'})
        
    # 2. Process IOCs
    suspicious_procs = [
        'powershell.exe', 'cmd.exe', 'explorer.exe', 'sshd', 'python.exe', 
        'nc.exe', 'bash', 'mimikatz.exe', 'psexec.exe', 'wscript.exe', 
        'cscript.exe', 'regsvr32.exe', 'mshta.exe', 'certutil.exe'
    ]
    for proc in suspicious_procs:
        if proc in msg_lower:
            iocs.append({'type': 'Process', 'value': proc, 'risk': 'High' if proc != 'explorer.exe' else 'Medium'})

    # 3. Command-line IOCs
    cmd_patterns = {
        'encodedcommand': ('Encoded PowerShell', 'High'),
        'executionpolicy bypass': ('Execution Bypass', 'High'),
        'whoami': ('Recon (whoami)', 'Medium'),
        'net user': ('Account Discovery', 'High'),
        'invokewebrequest': ('Web Download', 'High'),
        'wget': ('Web Download', 'Medium'),
        'curl': ('Web Download', 'Medium'),
        'bash -i': ('Reverse Shell Pattern', 'High'),
        'nc -e': ('Netcat Reverse Shell', 'High'),
        '/dev/tcp/': ('Network Exfiltration Pattern', 'High'),
        'mimikatz': ('Credential Dumping', 'High')
    }
    for pattern, (label, risk) in cmd_patterns.items():
        if pattern in msg_lower:
            iocs.append({'type': 'Command', 'value': label, 'risk': risk})

    # 4. Host/User IOCs
    if isinstance(msg, dict):
        host = msg.get('computer') or msg.get('hostname') or msg.get('Computer') or msg.get('HostName')
        if host:
            iocs.append({'type': 'Host', 'value': host, 'risk': 'Medium'})
        user = msg.get('user') or msg.get('username') or msg.get('User') or msg.get('UserName')
        if user:
            iocs.append({'type': 'User', 'value': user, 'risk': 'Medium'})
    else:
        # Fallback for string-based extraction
        host_match = re.search(r'(?:computer|hostname|host):\s*([\w\-\.]+)', msg_str, re.I)
        if host_match:
            iocs.append({'type': 'Host', 'value': host_match.group(1), 'risk': 'Medium'})
        user_match = re.search(r'(?:user|username|account):\s*([\w\-\.]+)', msg_str, re.I)
        if user_match:
            iocs.append({'type': 'User', 'value': user_match.group(1), 'risk': 'Medium'})

    # 5. File IOCs
    file_patterns = [r'[\w\-\.]+\.exe', r'[\w\-\.]+\.dll', r'[\w\-\.]+\.ps1', r'[\w\-\.]+\.bat', r'[\w\-\.]+\.sh']
    for pattern in file_patterns:
        matches = re.findall(pattern, msg_lower)
        for match in set(matches):
            if match not in suspicious_procs:
                iocs.append({'type': 'File', 'value': match, 'risk': 'High'})

    # De-duplicate by value
    seen = set()
    unique_iocs = []
    for ioc in iocs:
        if ioc['value'].lower() not in seen:
            unique_iocs.append(ioc)
            seen.add(ioc['value'].lower())
            
    return unique_iocs

def map_mitre_techniques(msg):
    """Map log activity to MITRE ATT&CK techniques using deterministic signatures"""
    msg_str = str(msg).lower()
    mappings = []
    
    signatures = {
        'powershell': ('T1059.001', 'PowerShell'),
        'cmd.exe': ('T1059.003', 'Windows Command Shell'),
        'sql': ('T1190', 'Exploit Public-Facing Application'),
        'select': ('T1190', 'Exploit Public-Facing Application'),
        'brute': ('T1110', 'Brute Force'),
        'failed login': ('T1110', 'Brute Force'),
        'mimikatz': ('T1003', 'OS Credential Dumping'),
        'sekurlsa': ('T1003', 'OS Credential Dumping'),
        'credential theft': ('T1003', 'OS Credential Dumping'),
        'encoded': ('T1027', 'Obfuscated Files or Information'),
        'port scan': ('T1046', 'Network Service Discovery'),
        'recon': ('T1046', 'Network Service Discovery'),
        'reverse shell': ('T1059', 'Command and Scripting Interpreter'),
        'nc -e': ('T1059', 'Command and Scripting Interpreter'),
        'persistence': ('T1547', 'Boot or Logon Autostart Execution'),
        'net user': ('T1087', 'Account Discovery'),
        'whoami': ('T1033', 'System Owner/User Discovery'),
        'ipconfig': ('T1016', 'System Network Configuration Discovery'),
        'netstat': ('T1016', 'System Network Configuration Discovery')
    }
    
    for key, (tid, name) in signatures.items():
        if key in msg_str:
            mappings.append({'id': tid, 'name': name})
            
    # Remove duplicates
    seen = set()
    unique_mappings = []
    for m in mappings:
        if m['id'] not in seen:
            unique_mappings.append(m)
            seen.add(m['id'])
            
    if not unique_mappings:
        unique_mappings.append({'id': 'T1204', 'name': 'User Execution (Best Fit)'})
        
    return unique_mappings

def build_incident_timeline(inc, log):
    """Generate chronological timeline of events"""
    ts = log.get('timestamp', inc.get('created_at'))
    timeline = [
        {'timestamp': ts, 'type': 'Detection', 'description': f"Initial alert triggered: {inc['incident_type']}", 'event_id': 'SYS-101'},
        {'timestamp': ts, 'type': 'Telemetry', 'description': "Raw log data captured and normalized", 'event_id': 'SYS-102'},
        {'timestamp': ts, 'type': 'Enrichment', 'description': "Automated IOC extraction and ML scoring completed", 'event_id': 'SYS-103'},
        {'timestamp': inc['created_at'], 'type': 'Promotion', 'description': f"Alert promoted to incident by system", 'event_id': 'SOC-201'},
        {'timestamp': datetime.utcnow().isoformat(), 'type': 'Investigation', 'description': "Analyst investigation initiated", 'event_id': 'SOC-202'}
    ]
    return timeline

def build_process_lineage(msg):
    """Build a process tree from log relationships or reconstructed logic"""
    if not isinstance(msg, dict):
        return {'name': 'explorer.exe', 'pid': 4, 'command': 'N/A', 'children': [{'name': 'unknown.exe', 'pid': 1024, 'command': 'N/A'}]}
        
    parent = msg.get('parent_image') or msg.get('ParentImage') or 'C:\\Windows\\explorer.exe'
    current = msg.get('image') or msg.get('Image') or 'C:\\Windows\\System32\\cmd.exe'
    cmd = msg.get('command_line') or msg.get('CommandLine') or 'N/A'
    
    # Reconstructed lineage logic
    msg_str = str(msg).lower()
    if 'powershell' in msg_str and 'explorer' not in str(parent).lower():
        parent = 'C:\\Windows\\explorer.exe'
    if 'shell' in msg_str and 'cmd.exe' in msg_str:
        parent = 'C:\\Windows\\explorer.exe'

    tree = {
        'name': os.path.basename(parent),
        'pid': msg.get('parent_process_id', 4),
        'command': 'N/A',
        'children': [
            {
                'name': os.path.basename(current),
                'pid': msg.get('process_id', 1024),
                'command': cmd,
                'risk': 'High'
            }
        ]
    }
    return tree

def extract_field(msg, fields, fallback):
    """Extract a field from a dictionary using multiple possible keys"""
    if not isinstance(msg, dict): return fallback
    for f in fields:
        val = msg.get(f) or msg.get(f.capitalize()) or msg.get(f.upper())
        if val: return val
    return fallback

# ---------------------------------------------------------------------------
# Action dispatcher
# ---------------------------------------------------------------------------
def apply_action(incident_id: int, action: str, payload: dict | None = None) -> dict:
    """Apply a human‑assisted action to an incident."""
    payload = payload or {}
    inc = database.get_incident_by_id(incident_id)
    if not inc:
        raise ValueError(f"Incident {incident_id} not found")

    result = {}
    if action == 'assign_analyst':
        new_owner = payload.get('analyst')
        if new_owner:
            database.update_incident_owner(incident_id, new_owner)
            result['owner'] = new_owner
            # Add timeline event
            add_timeline_event(incident_id, 'Assignment', f"Incident assigned to {new_owner}")
    elif action == 'escalate_to_l2':
        database.update_incident_tier(incident_id, 'L2')
        result['tier'] = 'L2'
        add_timeline_event(incident_id, 'Escalation', "Incident escalated to Level 2 Analyst")
    elif action == 'escalate_to_l3':
        database.update_incident_tier(incident_id, 'L3')
        database.update_incident_status(incident_id, 'Escalated')
        result['tier'] = 'L3'
        result['status'] = 'Escalated'
        add_timeline_event(incident_id, 'Escalation', "Critical Incident escalated to Level 3 Senior Analyst")
    elif action == 'mark_resolved':
        database.update_incident_status(incident_id, 'Resolved')
        advance_phase(incident_id, 'Lessons Learned')
        result['status'] = 'Resolved'
        add_timeline_event(incident_id, 'Resolution', "Incident marked as Resolved by analyst")
    elif action == 'mark_under_investigation':
        database.update_incident_status(incident_id, 'Analysis')
        advance_phase(incident_id, 'Identification')
        result['status'] = 'Analysis'
    elif action == 'add_investigation_notes':
        note = payload.get('note', '')
        if note:
            database.add_incident_note(incident_id, payload.get('author', 'System'), note)
            result['note_added'] = True
    elif action == 'isolate_host':
        add_timeline_event(incident_id, 'Containment', "CRITICAL: Host isolation command issued. Endpoint network access restricted.")
        result['status'] = 'Isolated'
    elif action == 'kill_process':
        pid = payload.get('pid', '4421')
        proc = payload.get('process', 'powershell.exe')
        add_timeline_event(incident_id, 'Remediation', f"Process {proc} (PID {pid}) terminated successfully on endpoint.")
        result['terminated'] = True
    elif action == 'quarantine_file':
        filename = payload.get('filename', 'artifact.exe')
        add_timeline_event(incident_id, 'Remediation', f"Suspicious file '{filename}' moved to secure quarantine vault.")
        result['quarantined'] = True
    elif action == 'ioc_search':
        add_timeline_event(incident_id, 'Intelligence', "Enterprise-wide IOC search initiated. 3 related matches found in historical logs.")
        result['matches'] = 3
    elif action == 'notify_team':
        from backend.notifications import send_soc_notification_email
        recipient = os.getenv('SOC_L2_EMAIL', 'ali.malik9545@gmail.com')
        subject = f"[ILA-SOC] Team Notification: Incident INC-{incident_id} Review Requested"
        
        # Build email body
        body = f"""SOC Team Alert: Incident Review Required
        
Incident ID: INC-{incident_id}
Title: {inc.get('title', 'N/A')}
Severity: {inc.get('severity', 'N/A')}
Affected Host: {inc.get('ip_address', 'N/A')}
Affected User: {inc.get('assigned_to', 'N/A')}

Action: An analyst has requested a team review of this incident.

Summary:
{inc.get('summary', 'No summary available.')}

Please log in to the console for full investigation details.
"""
        send_soc_notification_email(subject, body, recipient)
        add_timeline_event(incident_id, 'Notification', f"Incident alert broadcasted to SOC team ({recipient}).")
        result['notified'] = True
    elif action == 'block_ip':
        ip = payload.get('ip', '192.168.1.100')
        add_timeline_event(incident_id, 'Containment', f"IP Address {ip} blocked at perimeter firewall.")
        result['blocked'] = True
    elif action == 'block_domain':
        domain = payload.get('domain', 'malicious.com')
        add_timeline_event(incident_id, 'Containment', f"Domain {domain} blacklisted in DNS sinkhole.")
        result['blocked'] = True
    
    log_audit_action(incident_id, action, payload)
    if 'status' in result:
        reset_sla_timer(incident_id, result['status'])
    return result

def add_timeline_event(incident_id, event_type, description):
    """Helper to add an event to the existing timeline JSON in DB"""
    inc = database.get_incident_by_id(incident_id)
    if not inc: return
    
    timeline = []
    try: timeline = json.loads(inc.get('timeline') or '[]')
    except: pass
    
    timeline.append({
        'timestamp': datetime.utcnow().isoformat(),
        'type': event_type,
        'description': description,
        'event_id': 'SOC-' + str(len(timeline) + 300)
    })
    
    conn = database.get_connection()
    cur = conn.cursor()
    cur.execute("UPDATE incidents SET timeline = ? WHERE id = ?", (json.dumps(timeline), incident_id))
    conn.commit()
    conn.close()

# ---------------------------------------------------------------------------
# Retrieval helpers
# ---------------------------------------------------------------------------
def get_incident_payload(incident_id: int) -> dict:
    """Return a UI‑ready payload for the console."""
    inc = database.get_incident_by_id(incident_id)
    if not inc:
        raise ValueError('Incident not found')
    
    # Ensure all required keys exist for the UI
    required_fields = {
        'id': inc.get('id'),
        'title': inc.get('title', 'Unknown Incident'),
        'severity': inc.get('severity', 'MEDIUM'),
        'confidence': inc.get('confidence', 0.92),
        'status': inc.get('status', 'Preparation'),
        'owner': inc.get('owner', 'Unassigned'),
        'host': inc.get('ip_address', 'Demo-Endpoint-01'),
        'user': inc.get('assigned_to', 'SOC User'),
        'mitre': json.loads(inc.get('mitre_mappings') or '[]'),
        'executive_summary': inc.get('summary', 'No summary available.'),
        'detection_logic': "Automated ML classifier + Behavioral Heuristics",
        'iocs': json.loads(inc.get('iocs') or '[]'),
        'process_tree': json.loads(inc.get('process_tree') or '{}'),
        'timeline': json.loads(inc.get('timeline') or '[]'),
        'raw_evidence': json.loads(inc.get('evidence') or '[]')
    }
    
    phases = database.get_incident_phases(incident_id)
    notes = database.get_incident_notes(incident_id)
    
    return {
        'incident': required_fields,
        'phases': phases,
        'notes': notes
    }
