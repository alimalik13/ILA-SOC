from flask import Flask, request, jsonify, render_template, send_file, redirect, url_for, session, flash, make_response
from flask_cors import CORS
from flask_socketio import SocketIO
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from functools import wraps
import jwt
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from dotenv import load_dotenv
from email_validator import validate_email, EmailNotValidError
import os
import json
import csv
import re
import traceback
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

load_dotenv()

from backend import database
from backend import vt_integration
from ml import ml_text_classifier
from ml import ml_flow_classifier
from backend.data_manager import data_manager, config_manager
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from url_intelligence.risk_engine import compute_risk_score
from url_intelligence.feature_extractor import extract_features
from url_intelligence.ml_model import classify_url_with_model
from behavior_tracker import BehaviorEvent, BehaviorStore
from user_profiler    import UserProfiler
from nudge_engine     import NudgeEngine
from behavior_dataset import DatasetBuilder, BehaviorClassifier
from backend import alerts_db, incident_db

# --- NEXTGEN SYSMON SHADOW MODE ---
try:
    from nextgen_sysmon_pipeline.shadow_mode_runner import dispatch_shadow_event
except ImportError:
    def dispatch_shadow_event(raw_json, legacy_verdict):
        pass

app = Flask(__name__)

# Configure CORS - allows all origins for Chrome Extension communication
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

@app.after_request
def add_pna_headers(response):
    """
    Handle Private Network Access (PNA) preflight requests.
    This is required when an HTTPS page (like a Chrome extension) 
    calls a localhost/private server.
    """
    if request.headers.get('Access-Control-Request-Private-Network') == 'true':
        response.headers['Access-Control-Allow-Private-Network'] = 'true'
    return response

app.config['SECRET_KEY'] = os.getenv('SESSION_SECRET', 'dev-secret-key-change-in-production')
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB max file size
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)

GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')

if not GOOGLE_CLIENT_ID or GOOGLE_CLIENT_ID == 'your_google_client_id.apps.googleusercontent.com' or GOOGLE_CLIENT_ID == 'YOUR_GOOGLE_CLIENT_ID':
    print("\n[WARNING] GOOGLE_CLIENT_ID is missing or not configured correctly in .env!")
    print("[WARNING] Google OAuth authentication will NOT work. Please configure the OAuth Client ID for a Web Application.")
    GOOGLE_CLIENT_ID = ""
else:
    print("\n[OK] Google auth configured: YES")

AUTH_SECRET = os.getenv('AUTH_SECRET', app.config['SECRET_KEY'])
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# ── Behavior / nudge module instances ────────────────────────────────────────
behavior_store    = BehaviorStore()
profiler          = UserProfiler()
nudge_engine_inst = NudgeEngine()
dataset_builder   = DatasetBuilder()
classifier        = BehaviorClassifier()
ADMIN_KEY         = "ila-soc-admin"

def get_agent_api_key():
    """Get current agent API key from config or environment"""
    return config_manager.get_agent_api_key()

def require_agent_api_key(f):
    """Decorator to require API key authentication for agent endpoints"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key') or request.json.get('api_key') if request.is_json else None
        current_key = get_agent_api_key()
        if not api_key or api_key != current_key:
            return jsonify({"status": "error", "message": "Invalid or missing API key"}), 401
        return f(*args, **kwargs)
    return decorated_function

from backend.notifications import send_soc_notification_email

# Upload configuration
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
RAW_FOLDER = os.path.join(UPLOAD_FOLDER, 'raw')
REPORTS_FOLDER = os.path.join(UPLOAD_FOLDER, 'reports')
ALLOWED_EXTENSIONS = {'txt', 'log', 'json', 'csv'}

# Create upload directories if they don't exist
os.makedirs(RAW_FOLDER, exist_ok=True)
os.makedirs(REPORTS_FOLDER, exist_ok=True)

# Store last analysis results in memory
app.last_results = None

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

database.init_database()
database.ensure_default_admin()

def login_required(f):
    """Decorator to require login for protected routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

if ml_flow_classifier.FLOW_READY:
    attack_count = len(ml_flow_classifier.FLOW_MODEL.classes_) if ml_flow_classifier.FLOW_MODEL else 0
else:
    pass


def rule_based_classify(log_data):
    """
    Rule-based classification fallback.
    Uses smart detection to avoid false positives on benign Windows events.
    """
    log_message_str = str(log_data).lower()
    
    BENIGN_WINDOWS_INDICATORS = [
        "microsoft-windows-security-auditing",
        "microsoft-windows-powershell",
        "successfully logged on",
        "logon type: 3",
        "logon type: 10",
        "special privileges assigned",
        "the time provider",
        "credential manager",
        "windows error reporting",
        "svchost.exe",
        "vmictimeprovider",
        "group policy",
        "scheduled task",
        "service control manager",
        "power event",
        "kernel-power",
        "system restore",
        "windows update",
        "eventid: 4624",
        "eventid: 4625",
        "eventid: 4688",
        "eventid: 7036",
        "eventid: 7045",
        "a logon was attempted",
        "account was successfully logged on"
    ]
    
    for pattern in BENIGN_WINDOWS_INDICATORS:
        if pattern in log_message_str:
            return "Normal"
    
    DEFINITE_MALICIOUS = [
        "mimikatz", "sekurlsa", "logonpasswords", "hashdump", "credential dump",
        "reverse shell", "/dev/tcp", "nc -e", "bash -i",
        "union select", "or 1=1", "'--", "xss", "<script>alert",
        "jndi:ldap", "${jndi:", "log4shell",
        "cobalt strike", "metasploit", "meterpreter",
        "ransomware", "encrypted your files", "ransom note"
    ]
    
    for keyword in DEFINITE_MALICIOUS:
        if keyword in log_message_str:
            return "Malicious"
    
    SUSPICIOUS_KEYWORDS = [
        "failed password", "authentication failure", "access denied",
        "brute force", "unauthorized access", "invalid credentials"
    ]
    
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in log_message_str:
            return "Suspicious"
    
    return "Normal"

def extract_ip(log_data):
    import re
    log_str = str(log_data)
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    match = re.search(ip_pattern, log_str)
    return match.group(0) if match else "Unknown"

def block_ip(ip):
    if ip != "Unknown":
        database.save_blocked_ip(ip)
        return True
    return False

def notify_admin(ip, log_message):
    # TODO: Implement admin notification (e.g., email, logging)
    pass

def isolate_endpoint(ip):
    if ip != "Unknown":
        return True
    return False

def trigger_response_actions(log_entry):
    ip = extract_ip(log_entry.get('message', {}))
    log_msg = str(log_entry.get('message', ''))
    
    
    block_ip(ip)
    notify_admin(ip, log_msg)
    isolate_endpoint(ip)
    
    
    blocked_ips_list = database.get_blocked_ips()
    
    return {
        "ip": ip,
        "blocked": ip in blocked_ips_list,
        "actions": ["IP Blocked", "Admin Notified", "Endpoint Isolated"]
    }

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('soc_dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET'])
def login():
    if 'user_id' in session:
        return redirect(url_for('soc_dashboard'))
    return render_template('login.html', google_client_id=GOOGLE_CLIENT_ID)

@app.route('/register', methods=['GET'])
def register():
    if 'user_id' in session:
        return redirect(url_for('soc_dashboard'))
    return render_template('register.html', google_client_id=GOOGLE_CLIENT_ID)


@app.route('/logout')
def logout():
    session.clear()
    resp = make_response(redirect(url_for('login')))
    resp.delete_cookie('access_token')
    return resp

# --- AUTHENTICATION APIs ---

def generate_jwt(user):
    payload = {
        'user_id': user['id'],
        'email': user['email'],
        'role': user['role'],
        'exp': datetime.utcnow() + timedelta(days=7)
    }
    return jwt.encode(payload, AUTH_SECRET, algorithm='HS256')


@app.route('/auth/register', methods=['POST'])
def auth_register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    full_name = data.get('full_name', '')
    organization = data.get('organization', '')
    
    if not email or not password:
        return jsonify({'status': 'error', 'message': 'Email and password are required'}), 400
        
    try:
        # Robust email validation
        valid = validate_email(email)
        email = valid.normalized
    except EmailNotValidError as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400
        
    if database.get_user_by_email(email):
        return jsonify({'status': 'error', 'message': 'Email is already registered'}), 409
        
    password_hash = generate_password_hash(password)
    user_id = database.create_user(email=email, password_hash=password_hash, full_name=full_name, organization=organization)
    
    if user_id:
        user = database.get_user_by_email(email)
        token = generate_jwt(user)
        session.permanent = True
        session['user_id'] = user['id']
        session['username'] = user['email']
        session['role'] = user['role']
        database.update_user_last_login(user['id'])
        
        resp = jsonify({'status': 'success', 'token': token, 'user': {'id': user['id'], 'email': user['email'], 'full_name': user['full_name'], 'role': user['role']}})
        resp.set_cookie('access_token', token, httponly=True, secure=True, samesite='None')
        return resp, 201
    else:
        return jsonify({'status': 'error', 'message': 'Registration failed'}), 500


@app.route('/auth/login', methods=['POST'])
def auth_login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({'status': 'error', 'message': 'Email and password are required'}), 400
        
    try:
        # Robust email validation
        valid = validate_email(email)
        email = valid.normalized
    except EmailNotValidError as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400
        
    user = database.get_user_by_email(email)
    if user and user['password_hash'] and check_password_hash(user['password_hash'], password):
        if not user['is_active']:
            return jsonify({'status': 'error', 'message': 'Account is disabled'}), 403
            
        token = generate_jwt(user)
        session.permanent = True
        session['user_id'] = user['id']
        session['username'] = user['email']
        session['role'] = user['role']
        database.update_user_last_login(user['id'])
        
        resp = jsonify({'status': 'success', 'token': token, 'user': {'id': user['id'], 'email': user['email'], 'full_name': user['full_name'], 'role': user['role']}})
        resp.set_cookie('access_token', token, httponly=True, secure=True, samesite='None')
        return resp, 200
    else:
        return jsonify({'status': 'error', 'message': 'Invalid email or password'}), 401


@app.route('/auth/google', methods=['POST'])
def auth_google():
    data = request.get_json()
    token = data.get('credential')
    
    if not token:
        return jsonify({'status': 'error', 'message': 'No credential provided'}), 400
        
    if not GOOGLE_CLIENT_ID:
        return jsonify({'status': 'error', 'message': 'Google authentication is not configured on the server'}), 500
        
    try:
        idinfo = id_token.verify_oauth2_token(token, google_requests.Request(), GOOGLE_CLIENT_ID)
        
        email = idinfo['email']
        full_name = idinfo.get('name', '')
        profile_picture = idinfo.get('picture', '')
        
        user = database.get_user_by_email(email)
        if not user:
            # Create user if it doesn't exist
            user_id = database.create_user(email=email, password_hash='', full_name=full_name, auth_provider='google', profile_picture=profile_picture)
            if not user_id:
                return jsonify({'status': 'error', 'message': 'Failed to create Google user'}), 500
            user = database.get_user_by_email(email)
        elif user['auth_provider'] != 'google':
            # Update to include google if they had a local account? Or just let them log in.
            pass
            
        if not user['is_active']:
            return jsonify({'status': 'error', 'message': 'Account is disabled'}), 403
            
        jwt_token = generate_jwt(user)
        session.permanent = True
        session['user_id'] = user['id']
        session['username'] = user['email']
        session['role'] = user['role']
        database.update_user_last_login(user['id'])
        
        resp = jsonify({'status': 'success', 'token': jwt_token, 'user': {'id': user['id'], 'email': user['email'], 'full_name': user['full_name'], 'role': user['role'], 'picture': user['profile_picture']}})
        resp.set_cookie('access_token', jwt_token, httponly=True, secure=True, samesite='None')
        return resp, 200
        
    except ValueError:
        return jsonify({'status': 'error', 'message': 'Invalid Google token'}), 401


@app.route('/auth/logout', methods=['POST'])
def auth_logout():
    session.clear()
    resp = jsonify({'status': 'success', 'message': 'Logged out successfully'})
    resp.delete_cookie('access_token')
    return resp, 200


@app.route('/auth/me', methods=['GET'])
def auth_me():
    user_id = session.get('user_id')
    auth_header = request.headers.get('Authorization')
    
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
        try:
            payload = jwt.decode(token, AUTH_SECRET, algorithms=['HS256'])
            user_id = payload.get('user_id')
        except:
            return jsonify({'status': 'error', 'message': 'Invalid or expired token'}), 401
            
    if not user_id:
        return jsonify({'status': 'error', 'message': 'Not authenticated'}), 401
        
    conn = sqlite3.connect(database.DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT id, email, full_name, role, organization, profile_picture FROM users WHERE id = ?', (user_id,))
    row = cursor.fetchone()
    conn.close()
    
    if row:
        return jsonify({
            'status': 'success',
            'user': {
                'id': row[0],
                'email': row[1],
                'full_name': row[2],
                'role': row[3],
                'organization': row[4],
                'picture': row[5]
            }
        }), 200
    return jsonify({'status': 'error', 'message': 'User not found'}), 404


@app.route('/auth/forgot-password', methods=['POST'])
def auth_forgot_password():
    data = request.get_json()
    email = data.get('email')
    
    if not email:
        return jsonify({'status': 'error', 'message': 'Email is required'}), 400
        
    # In a real system, send email here
    return jsonify({'status': 'success', 'message': 'If the email exists, a reset link has been sent.'}), 200


@app.route('/auth/reset-password', methods=['POST'])
def auth_reset_password():
    data = request.get_json()
    token = data.get('token')
    new_password = data.get('new_password')
    
    if not token or not new_password:
        return jsonify({'status': 'error', 'message': 'Token and new password required'}), 400
        
    # Mock implementation
    return jsonify({'status': 'success', 'message': 'Password has been reset'}), 200


@app.route('/api/incidents', methods=['GET'])
@login_required
def get_incidents():
    # Fetch incident summaries from database (optimized for list view)
    try:
        incidents = database.get_incident_summaries()
        return jsonify({'status': 'success', 'incidents': incidents})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/incidents/<int:incident_id>', methods=['GET'])
@login_required
def get_incident_details(incident_id):
    try:
        import incident_workflow_manager
        payload = incident_workflow_manager.get_incident_payload(incident_id)
        return jsonify({'status': 'success', 'data': payload})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 404

@app.route('/api/incidents/<int:incident_id>/timeline', methods=['GET'])
@login_required
def get_incident_timeline(incident_id):
    try:
        # Mock timeline generation based on log_id for the UI
        inc = database.get_incident_by_id(incident_id)
        if not inc:
            return jsonify({'status': 'error', 'message': 'Not found'}), 404
        
        # In a real setup, we query related logs using correlation engine
        # For now, return the trigger log
        log = database.get_log_by_id(inc['log_id']) if inc.get('log_id') else None
        
        timeline = []
        if log:
            timeline.append({
                'timestamp': log.get('timestamp', inc.get('created_at')),
                'type': 'Process Creation' if 'process' in str(log).lower() else 'Raw Telemetry',
                'event_id': log.get('id', 'Sysmon'),
                'description': log.get('message', 'Trigger Event'),
                'severity': inc.get('severity', 'MEDIUM'),
                'raw': log
            })
            
        return jsonify({'status': 'success', 'timeline': timeline})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/incidents/<int:incident_id>/process-tree', methods=['GET'])
@login_required
def get_incident_process_tree(incident_id):
    try:
        # Generate process tree based on incident
        return jsonify({'status': 'success', 'tree': {
            'name': 'cmd.exe',
            'pid': 1024,
            'command': 'cmd.exe /c start',
            'children': [
                {'name': 'powershell.exe', 'pid': 1120, 'command': 'powershell -enc SUVY...', 'risk': 'encoded command'}
            ]
        }})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/incidents/<int:incident_id>/related', methods=['GET'])
@login_required
def get_related_incidents(incident_id):
    return jsonify({'status': 'success', 'related': []})

@app.route('/api/incidents/<int:incident_id>/evidence', methods=['GET'])
@login_required
def get_incident_evidence(incident_id):
    try:
        inc = database.get_incident_by_id(incident_id)
        if not inc:
            return jsonify({'status': 'error', 'message': 'Not found'}), 404
        log = database.get_log_by_id(inc.get('log_id')) if inc.get('log_id') else {}
        return jsonify({'status': 'success', 'evidence': [log]})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/incidents/<int:incident_id>/assign', methods=['POST'])
@login_required
def assign_incident(incident_id):
    data = request.get_json()
    try:
        import incident_workflow_manager
        res = incident_workflow_manager.apply_action(incident_id, 'assign_analyst', {'analyst': data.get('analyst')})
        return jsonify({'status': 'success', 'result': res})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/incidents/<int:incident_id>/status', methods=['PUT'])
@login_required
def update_incident_status(incident_id):
    data = request.get_json()
    action_map = {
        'Analysis': 'mark_under_investigation',
        'Resolved': 'mark_resolved'
    }
    try:
        import incident_workflow_manager
        action = action_map.get(data.get('status'))
        if action:
            res = incident_workflow_manager.apply_action(incident_id, action)
            return jsonify({'status': 'success', 'result': res})
        return jsonify({'status': 'error', 'message': 'Invalid status'}), 400
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/incidents/<int:incident_id>/action', methods=['POST'])
@login_required
def perform_incident_action(incident_id):
    """Generic endpoint for incident response actions (Isolate, Kill, etc.)"""
    data = request.get_json() or {}
    action = data.get('action')
    params = data.get('params', {})
    
    if not action:
        return jsonify({'status': 'error', 'message': 'No action specified'}), 400
        
    try:
        import incident_workflow_manager
        res = incident_workflow_manager.apply_action(incident_id, action, params)
        return jsonify({'status': 'success', 'result': res})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/incidents/<int:incident_id>/escalate', methods=['POST'], endpoint='incident_escalate')
@login_required
def escalate_incident_api(incident_id):
    try:
        import incident_workflow_manager
        res = incident_workflow_manager.apply_action(incident_id, 'escalate_to_l3')
        
        # Email Notification (L2 -> L3)
        try:
            inc_payload = incident_workflow_manager.get_incident_payload(incident_id)
            inc_data = inc_payload['incident']
            recipient = os.getenv('SOC_L3_EMAIL', 'ali.malik9545@gmail.com')
            subject = f"[ILA-SOC] Critical Incident Escalated to L3 - INC-{incident_id}"
            
            body = f"""Incident ID: INC-{incident_id}
Severity: {inc_data.get('severity')}
Current Status: {inc_data.get('status')}
Affected Host: {inc_data.get('host')}
Affected User: {inc_data.get('user')}
Confidence Score: {inc_data.get('confidence')}
MITRE ATT&CK mapping: {json.dumps(inc_data.get('mitre', []))}
Escalation Timestamp: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
Analyst Notes: Level 2 Analyst escalated for Senior Tier review.

Executive Summary:
{inc_data.get('executive_summary')}

Message: This incident requires immediate Level 3 attention.
"""
            send_soc_notification_email(subject, body, recipient)
        except Exception as email_err:
            print(f"[ERROR] Email notification failed for escalation: {str(email_err)}")

        return jsonify({'status': 'success', 'result': res})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/incidents/<int:incident_id>/notes', methods=['POST'])
@login_required
def add_incident_notes(incident_id):
    data = request.get_json()
    try:
        import incident_workflow_manager
        res = incident_workflow_manager.apply_action(incident_id, 'add_investigation_notes', {'note': data.get('note'), 'author': session.get('username')})
        return jsonify({'status': 'success', 'result': res})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/alerts', methods=['GET'])
@login_required
def get_alerts():
    """Get all alerts in the triage queue"""
    try:
        alerts = alerts_db.get_all_alerts()
        return jsonify({'status': 'success', 'alerts': alerts})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/alerts/<int:alert_id>', methods=['GET'])
@login_required
def get_alert_detail(alert_id):
    """Get detailed information for a specific alert"""
    try:
        alert = alerts_db.get_alert_by_id(alert_id)
        if not alert:
            return jsonify({'status': 'error', 'message': 'Alert not found'}), 404
        return jsonify({'status': 'success', 'alert': alert})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/alerts/<int:alert_id>/assign', methods=['POST'])
@login_required
def assign_alert(alert_id):
    """Assign an alert to the current analyst"""
    try:
        user = session.get('username', 'analyst')
        alerts_db.assign_alert(alert_id, user)
        return jsonify({'status': 'success', 'message': f'Alert assigned to {user}'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/alerts/<int:alert_id>/false-positive', methods=['POST'])
@login_required
def mark_alert_false_positive(alert_id):
    """Mark an alert as a false positive"""
    try:
        user = session.get('username', 'analyst')
        alerts_db.mark_false_positive(alert_id, user)
        return jsonify({'status': 'success', 'message': 'Alert marked as false positive'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/alerts/<int:alert_id>/mark-benign', methods=['POST'])
@login_required
def mark_alert_benign(alert_id):
    """Mark an alert as benign"""
    try:
        user = session.get('username', 'analyst')
        alerts_db.mark_benign(alert_id, user)
        return jsonify({'status': 'success', 'message': 'Alert marked as benign'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/alerts/<int:alert_id>/block-ip', methods=['POST'])
@login_required
def alert_block_ip(alert_id):
    """Block IP associated with an alert"""
    try:
        alert = alerts_db.get_alert_by_id(alert_id)
        if not alert:
            return jsonify({'status': 'error', 'message': 'Alert not found'}), 404
        
        # Try to extract IP from raw log
        msg = alert.get('raw_log', '')
        if isinstance(msg, dict):
            msg = json.dumps(msg)
        
        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', str(msg))
        ip = ip_match.group(1) if ip_match else alert.get('host')
        
        if not ip or ip == 'Unknown':
            return jsonify({'status': 'error', 'message': 'No IP address found in alert'}), 400
        
        database.save_blocked_ip(ip)
        
        socketio.emit('ip_blocked', {
            'ip': ip,
            'alert_id': alert_id,
            'reason': 'Blocked from alert triage',
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
        
        return jsonify({
            'status': 'success',
            'message': f'IP {ip} has been blocked',
            'ip': ip
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/alerts/<int:alert_id>/suppress', methods=['POST'])
@login_required
def suppress_alert(alert_id):
    """Suppress similar alerts"""
    try:
        user = session.get('username', 'analyst')
        alerts_db.suppress_alert(alert_id, user)
        return jsonify({'status': 'success', 'message': 'Alert suppressed'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/alerts/<int:alert_id>/create-incident', methods=['POST'])
@login_required
def promote_to_incident(alert_id):
    """Promote an alert to a full incident"""
    try:
        alert = alerts_db.get_alert_by_id(alert_id)
        if not alert:
            return jsonify({'status': 'error', 'message': 'Alert not found'}), 404
            
        if alert.get('incident_id'):
            return jsonify({'status': 'error', 'message': 'Alert already promoted to incident'}), 400
            
        data = request.get_json() or {}
        user = session.get('username', 'analyst')
        
        import incident_workflow_manager
        # Create the incident
        incident_id = incident_workflow_manager.create_incident(
            log_id=alert.get('log_id'), 
            incident_type=alert['source_engine'],
            severity=alert['severity'],
            title=f"Incident: {alert['source_engine']} Alert",
            description=alert['raw_log'],
            owner=user
        )
        
        # Link alert to incident
        alerts_db.link_alert_to_incident(alert_id, incident_id)
        
        # CHANGE 2: Alert Promotion Email (L1 -> L2)
        try:
            inc_data = incident_workflow_manager.get_incident_payload(incident_id)['incident']
            recipient = os.getenv('SOC_L2_EMAIL', 'ali.malik9545@gmail.com')
            subject = f"[ILA-SOC] Incident Promotion Notification - INC-{incident_id}"
            
            body = f"""Incident ID: INC-{incident_id}
Severity: {inc_data.get('severity')}
Detection Type: {alert.get('source_engine', 'N/A')}
Affected Host: {inc_data.get('host')}
Affected User: {inc_data.get('user')}
Confidence Score: {inc_data.get('confidence')}
MITRE ATT&CK mapping: {json.dumps(inc_data.get('mitre', []))}
Timestamp: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
Analyst: {user}

Message: This incident requires Level 2 investigation.
"""
            send_soc_notification_email(subject, body, recipient)
        except Exception as email_err:
            print(f"[ERROR] Email notification failed for promotion: {str(email_err)}")

        return jsonify({
            'status': 'success', 
            'incident_id': incident_id,
            'message': 'Alert promoted to incident successfully'
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/alert-triage')
@login_required
def alert_triage_page():
    """Alert Triage Queue (formerly Analytics Queue)"""
    return render_template('analytics.html', user=session, page_title="Alert Triage Queue (Level 1)")

@app.route('/incident-investigation')
@login_required
def incident_investigation_page():
    """Incident Investigation (formerly Structured Incidents)"""
    return render_template('soc_dashboard.html', user=session, page_title="Incident Investigation L2")

@app.route('/upload')
@login_required
def upload_page():
    """Render the file upload page"""
    return render_template('upload.html', user=session)

def parse_log_file(filepath, filename):
    """Parse different log file formats and extract log lines"""
    logs = []
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            if ext == 'json':
                content = f.read().strip()
                if content.startswith('['):
                    data = json.loads(content)
                    for i, item in enumerate(data):
                        if isinstance(item, dict):
                            log_text = item.get('message', item.get('log', item.get('log_text', str(item))))
                        else:
                            log_text = str(item)
                        logs.append({'line_number': i + 1, 'log': log_text})
                else:
                    for i, line in enumerate(content.split('\n')):
                        line = line.strip()
                        if line:
                            try:
                                item = json.loads(line)
                                if isinstance(item, dict):
                                    log_text = item.get('message', item.get('log', item.get('log_text', str(item))))
                                else:
                                    log_text = str(item)
                            except:
                                log_text = line
                            logs.append({'line_number': i + 1, 'log': log_text})
            
            elif ext == 'csv':
                f.seek(0)
                reader = csv.DictReader(f)
                for i, row in enumerate(reader):
                    log_text = row.get('message', row.get('log', row.get('log_text', str(row))))
                    logs.append({'line_number': i + 1, 'log': log_text})
            
            else:
                for i, line in enumerate(f):
                    line = line.strip()
                    if line:
                        logs.append({'line_number': i + 1, 'log': line})
    
    except Exception as e:
        raise
    
    return logs

def analyze_logs_batch(logs):
    """Analyze a batch of logs using the hybrid detection pipeline"""
    results = []
    summary = {
        'total_logs': len(logs),
        'malicious_count': 0,
        'suspicious_count': 0,
        'normal_count': 0
    }
    signatures_triggered = {}
    attack_types = {}
    
    for log_entry in logs:
        log_text = log_entry['log']
        line_num = log_entry['line_number']
        
        status, confidence = ml_text_classifier.classify_text_log(log_text)
        
        if status is None:
            status = 'Normal'
            confidence = 50.0
        
        if status == 'Malicious':
            summary['malicious_count'] += 1
            triggered = extract_triggered_signatures(log_text)
            for sig in triggered:
                signatures_triggered[sig] = signatures_triggered.get(sig, 0) + 1
            attack_type = detect_attack_type(log_text)
            if attack_type:
                attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
        elif status == 'Suspicious':
            summary['suspicious_count'] += 1
        else:
            summary['normal_count'] += 1
        
        results.append({
            'line_number': line_num,
            'log': log_text[:500],
            'classification': status,
            'confidence': f"{confidence:.2f}%" if confidence else "N/A"
        })
    
    return results, summary, signatures_triggered, attack_types

def extract_triggered_signatures(log_text):
    """Extract which attack signatures were triggered"""
    triggered = []
    log_lower = log_text.lower()
    
    signature_keywords = {
        'mimikatz': 'mimikatz',
        'psexec': 'psexec',
        'powershell': 'powershell',
        'wmic': 'wmic',
        'schtasks': 'schtasks',
        'reg add': 'registry',
        'sql injection': 'sql injection',
        'xss': 'xss',
        '/dev/tcp': 'reverse shell',
        'netcat': 'netcat',
        'nmap': 'nmap',
        'port scan': 'port scan'
    }
    
    for keyword, sig_name in signature_keywords.items():
        if keyword in log_lower:
            triggered.append(sig_name)
    
    return triggered

def detect_attack_type(log_text):
    """Detect the type of attack from log text"""
    log_lower = log_text.lower()
    
    if any(k in log_lower for k in ['mimikatz', 'sekurlsa', 'lsass', 'ntlm', 'kerberos']):
        return 'Credential Theft'
    if any(k in log_lower for k in ['psexec', 'wmic', 'winrm', 'lateral']):
        return 'Lateral Movement'
    if any(k in log_lower for k in ['schtasks', 'reg add', 'persistence', 'backdoor']):
        return 'Persistence'
    if any(k in log_lower for k in ['sql', 'injection', 'xss', 'webshell', 'traversal']):
        return 'Web Attack'
    if any(k in log_lower for k in ['/dev/tcp', 'netcat', 'reverse', 'shell']):
        return 'Reverse Shell'
    if any(k in log_lower for k in ['nmap', 'scan', 'reconnaissance']):
        return 'Reconnaissance'
    if any(k in log_lower for k in ['privilege', 'escalation', 'setuid', 'getsystem']):
        return 'Privilege Escalation'
    
    return 'Other'

@app.route('/upload_logs', methods=['POST'])
@login_required
def upload_logs():
    """Handle log file upload and analysis"""
    try:
        if 'log_file' not in request.files:
            return jsonify({'status': 'error', 'message': 'No file provided'}), 400
        
        file = request.files['log_file']
        
        if file.filename == '':
            return jsonify({'status': 'error', 'message': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({
                'status': 'error', 
                'message': 'Invalid file type. Allowed: .txt, .log, .json, .csv'
            }), 400
        
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_filename = f"{timestamp}_{filename}"
        
        raw_path = os.path.join(RAW_FOLDER, safe_filename)
        file.save(raw_path)
        
        logs = parse_log_file(raw_path, filename)
        
        if len(logs) == 0:
            return jsonify({'status': 'error', 'message': 'No valid log entries found in file'}), 400
        
        results, summary, signatures_triggered, attack_types = analyze_logs_batch(logs)
        
        report = {
            'status': 'success',
            'filename': filename,
            'timestamp': datetime.now().isoformat(),
            'message': f'Successfully analyzed {len(logs)} logs from {filename}',
            'summary': summary,
            'stats': {
                'total': summary['total_logs'],
                'malicious': summary['malicious_count'],
                'suspicious': summary['suspicious_count'],
                'normal': summary['normal_count']
            },
            'top_signatures': dict(sorted(signatures_triggered.items(), key=lambda x: x[1], reverse=True)[:10]),
            'attack_types': attack_types,
            'detailed_results': results
        }
        
        report_filename = f"report_{timestamp}.json"
        report_path = os.path.join(REPORTS_FOLDER, report_filename)
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        saved_count = 0
        for result in results:
            log_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_message = {'log_text': result['log'], 'source': filename}
            status = result['classification']
            actions_taken = []
            blocked_ip = None
            vt_status = "-"
            
            if status == 'Malicious':
                ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', result['log'])
                if ip_match:
                    blocked_ip = ip_match.group()
                    vt_result = vt_integration.check_virus_total(blocked_ip)
                    vt_status = vt_result.get('status', 'Unknown')
                    actions_taken.append(f"VT: {vt_status}")
            
            database.save_log(log_timestamp, log_message, status, actions_taken, blocked_ip, vt_status)
            saved_count += 1
        
        
        app.last_results = report
        
        return jsonify(report), 200
    
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/report/download')
def download_report():
    """Download the last analysis report as JSON"""
    if app.last_results is None:
        reports = sorted(os.listdir(REPORTS_FOLDER), reverse=True)
        if reports:
            report_path = os.path.join(REPORTS_FOLDER, reports[0])
            return send_file(report_path, as_attachment=True, download_name=reports[0])
        return jsonify({'status': 'error', 'message': 'No reports available'}), 404
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    temp_path = os.path.join(REPORTS_FOLDER, f'download_{timestamp}.json')
    with open(temp_path, 'w') as f:
        json.dump(app.last_results, f, indent=2)
    
    return send_file(temp_path, as_attachment=True, download_name=f'ila_soc_report_{timestamp}.json')

@app.route('/ingest', methods=['POST'])
def ingest_log():
    try:
        log_data = request.get_json()
        if log_data:
            
            log_text = log_data.get('log_text', log_data)
            status, confidence = ml_text_classifier.classify_text_log(log_text)
            
            if status is None:
                status = rule_based_classify(log_data)
                confidence = None
            
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            actions_taken = []
            blocked_ip = None
            vt_status = "-"
            
            if status == "Malicious":
                log_entry = {
                    "timestamp": timestamp,
                    "message": log_data,
                    "status": status
                }
                response_result = trigger_response_actions(log_entry)
                actions_taken = response_result.get("actions", [])
                blocked_ip = response_result.get("ip", "Unknown")
                
                if blocked_ip and blocked_ip != "Unknown":
                    vt_result = vt_integration.check_virus_total(blocked_ip)
                    vt_status = vt_result.get('status', 'Unknown')
                    
                    vt_info = f"VT: {vt_status}"
                    if vt_result.get('malicious', 0) > 0:
                        vt_info += f" ({vt_result['malicious']} malicious)"
                    elif vt_result.get('suspicious', 0) > 0:
                        vt_info += f" ({vt_result['suspicious']} suspicious)"
                    
                    actions_taken.append(vt_info)
                else:
                    vt_status = "Unknown"
            
            database.save_log(timestamp, log_data, status, actions_taken, blocked_ip, vt_status)
            
            # --- NEXTGEN SYSMON SHADOW MODE PASSIVE HOOK ---
            # Dispatch to parallel pipeline if structured JSON. No blocking, no return value.
            if isinstance(log_data, dict) and ('event_id' in log_data or 'EventID' in log_data):
                dispatch_shadow_event(log_data, status)
            
            if status == "Malicious":
                alert_data = {
                    'timestamp': timestamp,
                    'ip': blocked_ip if blocked_ip else 'Unknown',
                    'message': str(log_data)[:100],
                    'vt_status': vt_status,
                    'confidence': f"{confidence:.2f}%" if confidence is not None else 'N/A'
                }
                socketio.emit('malicious_log_alert', alert_data, namespace='/')
            
            response = {
                "status": "success", 
                "message": "Log ingested successfully",
                "classification": status
            }
            if confidence is not None:
                response["confidence"] = f"{confidence:.2f}%"
            
            return jsonify(response), 200
        else:
            return jsonify({"status": "error", "message": "No JSON data provided"}), 400
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/agent/register', methods=['POST'])
@require_agent_api_key
def register_agent():
    """Register a new agent with the server"""
    try:
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"status": "error", "message": "No JSON data provided"}), 400
            
        agent_id = data.get('agent_id')
        hostname = data.get('hostname', 'Unknown')
        ip_address = request.remote_addr
        os_type = data.get('os_type', 'Unknown')
        
        if not agent_id:
            return jsonify({"status": "error", "message": "agent_id is required"}), 400
        
        database.register_agent(agent_id, hostname, ip_address, os_type)
        print(f"[AGENT] Registered: {agent_id} ({hostname} @ {ip_address})")
        
        socketio.emit('agent_registered', {
            'agent_id': agent_id,
            'hostname': hostname,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
        
        return jsonify({
            "status": "success",
            "message": f"Agent {agent_id} registered successfully",
            "server_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }), 200
        
    except Exception as e:
        print(f"[AGENT ERROR] Registration failed: {str(e)}")
        return jsonify({"status": "error", "message": "Internal server error during registration"}), 500

@app.route('/api/agent/heartbeat', methods=['POST'])
@require_agent_api_key
def agent_heartbeat():
    """Receive heartbeat from agent to maintain connection status"""
    try:
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"status": "error", "message": "No JSON data provided"}), 400
            
        agent_id = data.get('agent_id')
        if not agent_id:
            return jsonify({"status": "error", "message": "agent_id is required"}), 400
        
        if database.update_agent_heartbeat(agent_id):
            print(f"[AGENT] Heartbeat: {agent_id}")
            return jsonify({"status": "success", "message": "Heartbeat received"}), 200
        else:
            return jsonify({"status": "error", "message": "Agent not registered. Please register first."}), 404
            
    except Exception as e:
        print(f"[AGENT ERROR] Heartbeat failed: {str(e)}")
        return jsonify({"status": "error", "message": "Internal server error during heartbeat"}), 500

@app.route('/api/agent/ingest-batch', methods=['POST'])
@require_agent_api_key
def ingest_batch():
    """Ingest multiple logs in a single request for efficiency"""
    try:
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"status": "error", "message": "No JSON data provided"}), 400
            
        agent_id = data.get('agent_id')
        logs = data.get('logs', [])
        
        if not logs:
            return jsonify({"status": "error", "message": "No logs provided"}), 400
        
        print(f"[AGENT] Received batch: {len(logs)} events from {agent_id}")
        
        results = []
        malicious_count = 0
        suspicious_count = 0
        
        for log_entry in logs:
            try:
                log_text = log_entry.get('log_text', log_entry)
                source = log_entry.get('source', agent_id or 'unknown')
                
                status, confidence = ml_text_classifier.classify_text_log(log_text)
                
                if status is None:
                    status = rule_based_classify({'log_text': log_text})
                    confidence = None
                
                timestamp = log_entry.get('timestamp', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                actions_taken = []
                blocked_ip = None
                vt_status = "-"
                
                if status == "Malicious":
                    malicious_count += 1
                    log_data = {"log_text": log_text, "source": source}
                    response_result = trigger_response_actions({"timestamp": timestamp, "message": log_data, "status": status})
                    actions_taken = response_result.get("actions", [])
                    blocked_ip = response_result.get("ip", "Unknown")
                    
                    if blocked_ip and blocked_ip != "Unknown":
                        vt_result = vt_integration.check_virus_total(blocked_ip)
                        vt_status = vt_result.get('status', '-')
                elif status == "Suspicious":
                    suspicious_count += 1
                
                # Save to database
                database.save_log(timestamp, {"log_text": log_text, "source": source}, status, actions_taken, blocked_ip, vt_status)
                
                # --- NEXTGEN SYSMON SHADOW MODE PASSIVE HOOK ---
                if isinstance(log_entry, dict) and ('event_id' in log_entry or 'EventID' in log_entry):
                    try:
                        dispatch_shadow_event(log_entry, status)
                    except: pass

                results.append({
                    "log_text": log_text[:50] + "..." if len(log_text) > 50 else log_text,
                    "status": status,
                    "confidence": f"{confidence:.2f}%" if confidence else "N/A"
                })
            except Exception as inner_e:
                print(f"[AGENT ERROR] Error processing log entry: {str(inner_e)}")
                continue
        
        # Increment agent log counter
        if agent_id:
            database.increment_agent_logs(agent_id, len(logs))
            
        print(f"[AGENT] Processed batch successfully from {agent_id}")
        return jsonify({
            "status": "success",
            "message": f"Processed {len(logs)} logs",
            "total": len(logs),
            "malicious": malicious_count,
            "suspicious": suspicious_count,
            "results": results
        }), 200
        
    except Exception as e:
        print(f"[AGENT ERROR] Batch ingestion failed: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return jsonify({"status": "error", "message": "Internal server error during batch ingestion"}), 500

@app.route('/api/agents', methods=['GET'])
def get_agents():
    """Get list of all connected agents from database"""
    agents = database.get_all_agents()
    
    active_count = sum(1 for a in agents if a['status'] == 'active')
    offline_count = sum(1 for a in agents if a['status'] == 'offline')
    idle_count = sum(1 for a in agents if a['status'] == 'idle')
    
    agents_dict = {a['agent_id']: a for a in agents}
    
    return jsonify({
        "status": "success",
        "agents": agents_dict,
        "total": len(agents),
        "active": active_count,
        "inactive": offline_count + idle_count,
        "offline": offline_count
    }), 200


@app.route('/api/agent/<agent_id>', methods=['GET'])
def get_agent_details(agent_id):
    """Get details of a specific agent"""
    agent = database.get_agent_by_id(agent_id)
    if agent:
        return jsonify({"status": "success", "agent": agent}), 200
    return jsonify({"status": "error", "message": "Agent not found"}), 404


@app.route('/api/agent/<agent_id>', methods=['DELETE'])
@login_required
def remove_agent(agent_id):
    """Remove an agent from the database"""
    if database.delete_agent(agent_id):
        return jsonify({"status": "success", "message": f"Agent {agent_id} removed"}), 200
    return jsonify({"status": "error", "message": "Agent not found"}), 404

@app.route('/logs', methods=['GET'])
def get_logs():
    logs = database.get_all_logs()
    return jsonify({"logs": logs, "count": len(logs)}), 200

def summarize_log(log):
    """Normalize and humanize raw log data for the UI."""
    msg = log.get('message', {})
    if not isinstance(msg, dict):
        try:
            msg = json.loads(str(msg))
        except:
            msg = {'log_text': str(msg)}
            
    # Determine Source (Rule: Hostname / Provider or Channel)
    hostname = msg.get('hostname') or msg.get('agent_id') or ''
    channel = msg.get('channel') or ''
    provider = msg.get('provider') or msg.get('ProviderName') or ''
    
    display_source = "Unknown"
    if hostname:
        display_source = hostname
        if channel: display_source += f" / {channel}"
        elif provider: display_source += f" / {provider}"
    elif log.get('blocked_ip'):
        display_source = log.get('blocked_ip')
    
    # Determine Category & Summary (Rule 4: Semantic Parsing)
    status = log.get('status', 'Normal')
    log_text = msg.get('log_text', '')
    event_id = str(msg.get('event_id') or msg.get('EventID') or '')
    
    summary = log_text
    category = "Security Event"
    
    msg_str = str(msg).lower()
    if 'sysmon' in msg_str:
        category = "Sysmon"
        if event_id == '1': summary = f"Process Creation: {msg.get('Image', 'Unknown')}"
        elif event_id == '3': summary = f"Network Connection: {msg.get('DestinationIp', 'Unknown')}:{msg.get('DestinationPort', '')}"
        elif event_id == '10': summary = f"Process Access: {msg.get('TargetImage', 'Unknown')}"
        elif event_id: summary = f"Sysmon Event (ID {event_id})"
    elif channel == 'Security':
        category = "Windows Security"
        if event_id: summary = f"Windows Security (ID {event_id})"
    elif channel == 'System':
        category = "Windows System"
        if event_id: summary = f"Windows System (ID {event_id})"
    elif 'application' in channel.lower() or 'application' in provider.lower():
        category = "Application"
        if event_id: summary = f"App Event (ID {event_id})"
    elif status == 'Normal':
        category = "Normal Event"
        
    if not summary:
        summary = "Standard telemetry event detected"
        
    return {
        'display_source': display_source,
        'category': category,
        'summary': summary
    }

@app.route('/logs/view', methods=['GET'])
@login_required
def view_logs():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    status_filter = request.args.get('status', 'all')
    
    # Use optimized paginated query
    logs, total_count = database.get_logs_paginated(page, per_page, status_filter)
    
    # Get total counts for filters
    stats = database.get_optimized_stats()
    counts = {
        'total': stats['total_logs'],
        'malicious': stats['malicious_logs'],
        'suspicious': stats['suspicious_logs'],
        'normal': stats['normal_logs']
    }
    
    enriched_logs = []
    log_data = {}
    
    for log in logs:
        info = summarize_log(log)
        
        # Merge info into log object for template
        log['display_source'] = info['display_source']
        log['display_category'] = info['category']
        log['display_summary'] = info['summary']
        
        enriched_logs.append(log)
        
        # Prepare log_data for details modal (raw strings)
        msg = log.get('message', '')
        msg_text = json.dumps(msg, indent=2) if isinstance(msg, dict) else str(msg)
        
        log_data[log['id']] = {
            'id': log['id'],
            'timestamp': log.get('timestamp', ''),
            'status': log.get('status', ''),
            'source': info['display_source'],
            'category': info['category'],
            'message': msg_text
        }
        
    time_filter = request.args.get('time', 'all')
    sort_order = request.args.get('sort', 'newest')
    
    return render_template('logs.html', 
                           logs=enriched_logs, 
                           user=session, 
                           log_data=log_data, 
                           page_title="Log Analysis",
                           time_filter=time_filter,
                           sort_order=sort_order,
                           page=page,
                           per_page=per_page,
                           total_count=total_count,
                           status_filter=status_filter,
                           counts=counts)

@app.route('/respond/<int:log_id>', methods=['POST'])
def respond_to_threat(log_id):
    try:
        logs = database.get_all_logs()
        
        if log_id < 1 or log_id > len(logs):
            return jsonify({"status": "error", "message": "Invalid log ID"}), 404
        
        log_entry = logs[log_id - 1]
        
        if log_entry['status'] != 'Malicious':
            return jsonify({
                "status": "info", 
                "message": "Log is not classified as malicious. No response needed."
            }), 200
        
        response_result = trigger_response_actions(log_entry)
        
        return jsonify({
            "status": "success",
            "message": "Threat response actions executed",
            "log_id": log_id,
            "response": response_result
        }), 200
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/blocked-ips', methods=['GET'])
def get_blocked_ips_route():
    blocked_ips_list = database.get_blocked_ips()
    return jsonify({
        "blocked_ips": blocked_ips_list,
        "count": len(blocked_ips_list)
    }), 200

@app.route('/vt-cache', methods=['GET'])
def get_vt_cache():
    """Get all cached VirusTotal entries"""
    try:
        cache_entries = database.get_all_cache_entries()
        return jsonify({
            "status": "success",
            "cache_entries": cache_entries,
            "count": len(cache_entries)
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/vt-cache/refresh', methods=['POST'])
def refresh_vt_cache():
    """Force refresh VirusTotal check for a specific IP"""
    try:
        data = request.get_json()
        ip = data.get('ip')
        
        if not ip:
            return jsonify({"status": "error", "message": "IP address is required"}), 400
        
        
        # Force fresh VT check by bypassing cache
        vt_result = vt_integration.check_virus_total(ip, bypass_cache=True)
        
        return jsonify({
            "status": "success",
            "message": f"VirusTotal cache refreshed for {ip}",
            "ip": ip,
            "vt_result": {
                "status": vt_result.get('status'),
                "malicious": vt_result.get('malicious', 0),
                "suspicious": vt_result.get('suspicious', 0),
                "harmless": vt_result.get('harmless', 0)
            }
        }), 200
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/vt-cache/<ip>', methods=['DELETE'])
def delete_vt_cache_entry(ip):
    """Delete a specific cache entry"""
    try:
        deleted = database.delete_cache_entry(ip)
        
        if deleted:
            return jsonify({
                "status": "success",
                "message": f"Cache entry for {ip} deleted"
            }), 200
        else:
            return jsonify({
                "status": "error",
                "message": f"Cache entry for {ip} not found"
            }), 404
            
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/vt-cache', methods=['DELETE'])
def clear_vt_cache():
    """Clear all cache entries"""
    try:
        count = database.clear_all_cache()
        
        return jsonify({
            "status": "success",
            "message": f"Cache cleared. {count} entries deleted."
        }), 200
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

def compute_analytics():
    """Optimized analytics computation using SQL aggregations instead of Python loops"""
    conn = None
    try:
        # Use the optimized stats function for basic counts
        stats = database.get_optimized_stats()
        cache_stats = database.get_cache_stats()
        
        conn = database.get_db_connection()
        cursor = conn.cursor()
        
        # Optimized Logs Per Hour query using SQLite date/time functions
        cursor.execute('''
            SELECT strftime('%Y-%m-%d %H:00', replace(timestamp, 'T', ' ')) as hour, COUNT(*) as count
            FROM logs
            WHERE timestamp >= datetime('now', '-7 days')
            GROUP BY hour
            ORDER BY hour ASC
        ''')
        logs_per_hour = {row[0]: row[1] for row in cursor.fetchall()}
        
        # Optimized IP Frequency query
        cursor.execute('''
            SELECT blocked_ip, COUNT(*) as count
            FROM logs
            WHERE blocked_ip IS NOT NULL AND blocked_ip != 'Unknown'
            GROUP BY blocked_ip
            ORDER BY count DESC
            LIMIT 10
        ''')
        top_blocked_ips = cursor.fetchall()
        
        # Fetch recent malicious logs for the feed
        cursor.execute('''
            SELECT id, timestamp, message, status, blocked_ip
            FROM logs
            WHERE status = "Malicious"
            ORDER BY timestamp DESC
            LIMIT 20
        ''')
        recent_malicious_rows = cursor.fetchall()
        recent_malicious = []
        for row in recent_malicious_rows:
            try:
                msg_obj = json.loads(row[2])
                log_msg = msg_obj.get('log_text', str(msg_obj))
            except:
                log_msg = str(row[2])
                
            recent_malicious.append({
                'id': row[0],
                'timestamp': row[1],
                'message': str(log_msg)[:200] if log_msg else 'N/A',
                'status': row[3],
                'blocked_ip': row[4] or 'Unknown'
            })
            
        # Fetch all agents for stats
        # Assuming database.get_all_agents() might open its own connection, 
        # but if it uses a shared one it's fine. 
        # However, to be safe, let's assume it's independent.
        agents = database.get_all_agents()
        active_agents = sum(1 for a in agents if a['status'] == 'active')
        
        # Calculate heuristics for enterprise metrics
        total_alerts = stats['active_alerts'] + stats['false_positives']
        det_accuracy = round(((stats['active_alerts']) / total_alerts * 100), 1) if total_alerts > 0 else 98.5
        
        # Threat Score (0-100)
        threat_score = min(100, round((stats['malicious_logs'] * 5 + stats['suspicious_logs'] * 2) / (stats['total_logs'] / 100 + 1), 1))
        
        # MITRE ATT&CK Aggregation (Deduplicated across incidents and alerts)
        cursor.execute('SELECT mitre_mappings FROM incidents WHERE mitre_mappings IS NOT NULL')
        mitre_rows = cursor.fetchall()
        
        # Mapping Techniques to Tactics
        TECH_TO_TACTIC = {
            'T1059.001': 'Execution', 'T1059.003': 'Execution', 'T1190': 'Initial Access',
            'T1110': 'Credential Access', 'T1003': 'Credential Access', 'T1027': 'Defense Evasion',
            'T1046': 'Discovery', 'T1033': 'Discovery', 'T1016': 'Discovery', 'T1547': 'Persistence',
            'T1087': 'Discovery', 'T1105': 'Command and Control', 'T1204': 'Execution'
        }
        
        mitre_counts = {}
        for row in mitre_rows:
            try:
                mappings = json.loads(row[0])
                if isinstance(mappings, list):
                    for m in mappings:
                        tactic = m.get('tactic')
                        if not tactic:
                            tid = m.get('id', '')
                            tactic = TECH_TO_TACTIC.get(tid, 'Unknown')
                        mitre_counts[tactic] = mitre_counts.get(tactic, 0) + 1
            except: pass
            
        # Ensure common tactics exist for UI consistency
        for t in ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery"]:
            if t not in mitre_counts: mitre_counts[t] = 0

        # Confidence Breakdown (ML based)
        confidence_breakdown = {
            'High (Verified)': stats['malicious_logs'],
            'Medium (Suspicious)': stats['suspicious_logs'],
            'Low (Anomaly)': max(0, stats['total_logs'] - stats['malicious_logs'] - stats['suspicious_logs'] - stats['normal_logs'])
        }
        
        # Severity Breakdown from open incidents
        cursor.execute('SELECT severity, COUNT(*) FROM incidents WHERE status != "Resolved" GROUP BY severity')
        sev_rows = cursor.fetchall()
        sev_breakdown = {row[0]: row[1] for row in sev_rows}

        return {
            'total_logs': stats['total_logs'],
            'total_malicious': stats['malicious_logs'],
            'total_suspicious': stats['suspicious_logs'],
            'total_normal': stats['normal_logs'],
            'blocked_ips_count': stats['blocked_ips_count'],
            'active_alerts': stats['active_alerts'],
            'false_positives': stats['false_positives'],
            'open_incidents': stats['open_incidents'],
            'resolved_incidents': stats['resolved_incidents'],
            'logs_per_hour': logs_per_hour,
            'top_blocked_ips': top_blocked_ips,
            'threat_score': threat_score,
            'detection_accuracy': det_accuracy,
            'active_agents': active_agents,
            'total_agents': len(agents),
            'mitre_counts': mitre_counts,
            'confidence_breakdown': confidence_breakdown,
            'severity_breakdown': sev_breakdown,
            'recent_malicious': recent_malicious,
            'attack_types': database.get_attack_distribution()
        }
    except Exception as e:
        print(f"CRITICAL ERROR in compute_analytics: {e}")
        import traceback
        traceback.print_exc()
        return {
            'total_logs': 0, 'total_malicious': 0, 'total_suspicious': 0, 'total_normal': 0,
            'blocked_ips_count': 0, 'active_alerts': 0, 'false_positives': 0,
            'open_incidents': 0, 'resolved_incidents': 0, 'logs_per_hour': {},
            'top_blocked_ips': [], 'mitre_counts': {}, 'recent_malicious': [],
            'threat_score': 0, 'detection_accuracy': 0, 'active_agents': 0, 'total_agents': 0,
            'confidence_breakdown': {}, 'severity_breakdown': {}, 'attack_types': {}
        }
    finally:
        if conn:
            conn.close()


@app.route('/dashboard', methods=['GET'])
@login_required
def soc_dashboard():
    analytics = compute_analytics()
    return render_template('soc_dashboard.html', analytics=analytics, user=session, page_title="Threat Overview")

@app.route('/api/dashboard/stats', methods=['GET'])
def dashboard_stats():
    """Real-time dashboard statistics for auto-refresh"""
    analytics = compute_analytics()
    return jsonify({
        "status": "success",
        "stats": {
            "total_logs": analytics['total_logs'],
            "total_malicious": analytics['total_malicious'],
            "total_suspicious": analytics['total_suspicious'],
            "total_normal": analytics['total_normal'],
            "blocked_ips_count": analytics['blocked_ips_count'],
            "active_alerts": analytics['active_alerts'],
            "false_positives": analytics['false_positives'],
            "open_incidents": analytics['open_incidents'],
            "resolved_incidents": analytics['resolved_incidents']
        },
        "attack_types": analytics.get('attack_types', {}),
        "logs_per_hour": analytics['logs_per_hour'],
        "recent_malicious": analytics['recent_malicious'],
        "threat_score": analytics.get('threat_score', 0),
        "detection_accuracy": analytics.get('detection_accuracy', 0),
        "mitre_counts": analytics.get('mitre_counts', {}),
        "confidence_breakdown": analytics.get('confidence_breakdown', {}),
        "severity_breakdown": analytics.get('severity_breakdown', {}),
        "agents": database.get_all_agents(),
        "recent_logs": analytics.get('recent_logs', [])[:10]
    })

@app.route('/dashboard/classic', methods=['GET'])
def dashboard_classic():
    """Original dashboard for backwards compatibility"""
    analytics = compute_analytics()
    return render_template('dashboard.html', analytics=analytics)

@app.route('/api/classify-flow', methods=['POST'])
def classify_flow():
    """
    Classify network flow based on numerical features.
    Expects JSON with network flow features.
    """
    if not ml_flow_classifier.FLOW_READY:
        return jsonify({'error': 'Network flow classifier not available'}), 503
    
    try:
        flow_data = request.get_json()
        if not flow_data:
            return jsonify({'error': 'No flow data provided'}), 400
        
        if isinstance(flow_data, list):
            results = ml_flow_classifier.classify_flow_batch(flow_data)
            response = []
            for i, (attack_type, threat_level, confidence, description) in enumerate(results):
                response.append({
                    'flow_index': i,
                    'attack_type': attack_type,
                    'threat_level': threat_level,
                    'confidence': f"{confidence:.2f}%",
                    'description': description
                })
            return jsonify({'results': response, 'count': len(response)})
        else:
            attack_type, threat_level, confidence, description = ml_flow_classifier.classify_network_flow(flow_data)
            return jsonify({
                'attack_type': attack_type,
                'threat_level': threat_level,
                'confidence': f"{confidence:.2f}%",
                'description': description
            })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/flow-classifier-info', methods=['GET'])
def flow_classifier_info():
    """Get information about the network flow classifier"""
    info = ml_flow_classifier.get_flow_classifier_info()
    info['attack_types'] = [str(a) for a in info['attack_types']]
    return jsonify(info)

@app.route('/test-alert', methods=['GET'])
def test_alert():
    """Test endpoint to manually trigger a SocketIO alert"""
    test_data = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'ip': '1.2.3.4',
        'message': 'This is a test alert',
        'vt_status': 'Test',
        'confidence': '100.00%'
    }
    socketio.emit('malicious_log_alert', test_data, namespace='/')
    return jsonify({"status": "success", "message": "Test alert emitted"})

@socketio.on('connect')
def handle_connect():
    """Handle new WebSocket connection"""
    from flask_socketio import emit
    emit('connection_response', {'data': 'Connected to ILA-SOC Real-Time Alerts'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection"""


@app.route('/api/logs/filter', methods=['GET'])
def filter_logs():
    """
    Filter logs by time range and status.
    Query params: start_date, end_date, status, preset (1h, 24h, 7d, 30d)
    """
    try:
        from datetime import timedelta
        
        preset = request.args.get('preset', '')
        start_date = request.args.get('start_date', '')
        end_date = request.args.get('end_date', '')
        status_filter = request.args.get('status', 'all')
        
        now = datetime.now()
        
        if preset:
            if preset == '1h':
                start_time = (now - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
            elif preset == '24h':
                start_time = (now - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
            elif preset == '7d':
                start_time = (now - timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
            elif preset == '30d':
                start_time = (now - timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")
            else:
                start_time = None
            end_time = now.strftime("%Y-%m-%d %H:%M:%S")
        else:
            start_time = f"{start_date} 00:00:00" if start_date else None
            end_time = f"{end_date} 23:59:59" if end_date else None
        
        logs = database.get_logs_by_time_range(start_time, end_time, status_filter)
        
        return jsonify({
            'status': 'success',
            'logs': logs,
            'count': len(logs),
            'filters': {
                'start_time': start_time,
                'end_time': end_time,
                'status': status_filter
            }
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/action/block-ip', methods=['POST'])
def manual_block_ip():
    """Manually block an IP address"""
    try:
        data = request.get_json()
        ip = data.get('ip')
        reason = data.get('reason', 'Manual block by analyst')
        
        if not ip:
            return jsonify({'status': 'error', 'message': 'IP address required'}), 400
        
        database.save_blocked_ip(ip)
        
        socketio.emit('ip_blocked', {
            'ip': ip,
            'reason': reason,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
        
        return jsonify({
            'status': 'success',
            'message': f'IP {ip} has been blocked',
            'ip': ip
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/action/isolate-host', methods=['POST'])
def isolate_host():
    """Simulate host isolation"""
    try:
        data = request.get_json()
        ip = data.get('ip')
        hostname = data.get('hostname', 'Unknown')
        
        if not ip:
            return jsonify({'status': 'error', 'message': 'IP address required'}), 400
        
        
        socketio.emit('host_isolated', {
            'ip': ip,
            'hostname': hostname,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
        
        return jsonify({
            'status': 'success',
            'message': f'Host {ip} isolation initiated',
            'actions': ['Network disconnected', 'System quarantined', 'Team alerted']
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/action/escalate', methods=['POST'], endpoint='legacy_escalate')
def legacy_escalate_incident():
    """Escalate incident to senior team"""
    try:
        data = request.get_json()
        incident_id = data.get('incident_id')
        escalate_to = data.get('escalate_to', 'Senior Security Analyst')
        priority = data.get('priority', 'High')
        notes = data.get('notes', '')
        
        
        if incident_id:
            database.log_incident_action(
                incident_id, 
                'escalate', 
                f"Escalated to {escalate_to} with {priority} priority. Notes: {notes}",
                'analyst'
            )
        
        socketio.emit('incident_escalated', {
            'incident_id': incident_id,
            'escalate_to': escalate_to,
            'priority': priority,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
        
        return jsonify({
            'status': 'success',
            'message': f'Incident escalated to {escalate_to}',
            'priority': priority
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/incidents/<int:incident_id>/notify', methods=['POST'])
@login_required
def notify_incident_team(incident_id):
    """Notify the team about an incident via Email."""
    try:
        # Get incident details
        conn = database.get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM incidents WHERE id = ?', (incident_id,))
        row = cursor.fetchone()
        
        if not row:
            conn.close()
            return jsonify({'status': 'error', 'message': 'Incident not found'}), 404
        
        incident = dict(row)
        conn.close()
        
        subject = f"[ILA-SOC] ALERT: Incident INC-{incident_id} Needs Attention"
        recipient = os.getenv('SOC_L2_EMAIL', 'analyst@ila-soc.internal')
        
        body = f"""
SOC Incident Notification

Incident ID: INC-{incident_id}
Title: {incident.get('title', 'N/A')}
Severity: {incident.get('severity', 'N/A')}
Status: {incident.get('status', 'N/A')}
Host: {incident.get('host', 'N/A')}
User: {incident.get('user', 'N/A')}

Description:
{incident.get('summary', incident.get('description', 'No details available.'))}

Action required: Please log in to the SOC Console to review the investigation.
        """
        
        success = send_soc_notification_email(subject, body, recipient)
        
        if success:
            return jsonify({
                'status': 'success', 
                'message': f'Notification email sent to {recipient}'
            })
        else:
            return jsonify({
                'status': 'error', 
                'message': 'Failed to send email. Check server SMTP configuration.'
            }), 500
            
    except Exception as e:
        traceback.print_exc()
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/playbook/<attack_type>', methods=['GET'])
def get_playbook(attack_type):
    """Get automated response playbook for attack type"""
    playbooks = {
        'ransomware': {
            'name': 'Ransomware Response',
            'severity': 'Critical',
            'steps': [
                {'order': 1, 'action': 'isolate_host', 'description': 'Immediately isolate infected systems'},
                {'order': 2, 'action': 'block_ip', 'description': 'Block all C2 IP addresses'},
                {'order': 3, 'action': 'notify', 'description': 'Alert incident response team'},
                {'order': 4, 'action': 'preserve', 'description': 'Preserve forensic evidence'},
                {'order': 5, 'action': 'assess', 'description': 'Assess scope of encryption'},
                {'order': 6, 'action': 'restore', 'description': 'Begin restoration from backups'}
            ],
            'auto_actions': ['isolate_host', 'block_ip', 'notify']
        },
        'brute_force': {
            'name': 'Brute Force Attack Response',
            'severity': 'High',
            'steps': [
                {'order': 1, 'action': 'block_ip', 'description': 'Block attacking IP addresses'},
                {'order': 2, 'action': 'lockout', 'description': 'Temporarily lock targeted accounts'},
                {'order': 3, 'action': 'notify', 'description': 'Alert security team'},
                {'order': 4, 'action': 'analyze', 'description': 'Analyze attack patterns'},
                {'order': 5, 'action': 'harden', 'description': 'Implement rate limiting'}
            ],
            'auto_actions': ['block_ip', 'notify']
        },
        'ddos': {
            'name': 'DDoS Attack Response',
            'severity': 'High',
            'steps': [
                {'order': 1, 'action': 'activate_ddos', 'description': 'Activate DDoS mitigation'},
                {'order': 2, 'action': 'block_ip', 'description': 'Block attack source IPs'},
                {'order': 3, 'action': 'reroute', 'description': 'Reroute traffic through scrubbing'},
                {'order': 4, 'action': 'notify', 'description': 'Alert NOC and security team'},
                {'order': 5, 'action': 'monitor', 'description': 'Monitor attack progression'}
            ],
            'auto_actions': ['block_ip', 'notify']
        },
        'lateral_movement': {
            'name': 'Lateral Movement Response',
            'severity': 'Critical',
            'steps': [
                {'order': 1, 'action': 'isolate_host', 'description': 'Isolate compromised hosts'},
                {'order': 2, 'action': 'revoke', 'description': 'Revoke compromised credentials'},
                {'order': 3, 'action': 'block_ip', 'description': 'Block internal lateral IPs'},
                {'order': 4, 'action': 'scan', 'description': 'Scan for additional compromise'},
                {'order': 5, 'action': 'notify', 'description': 'Alert incident response team'}
            ],
            'auto_actions': ['isolate_host', 'notify']
        },
        'credential_theft': {
            'name': 'Credential Theft Response',
            'severity': 'Critical',
            'steps': [
                {'order': 1, 'action': 'revoke', 'description': 'Force password reset for affected accounts'},
                {'order': 2, 'action': 'isolate_host', 'description': 'Isolate compromised endpoints'},
                {'order': 3, 'action': 'analyze', 'description': 'Analyze credential access patterns'},
                {'order': 4, 'action': 'notify', 'description': 'Alert security and affected users'},
                {'order': 5, 'action': 'enhance', 'description': 'Enable MFA on all accounts'}
            ],
            'auto_actions': ['notify']
        }
    }
    
    playbook = playbooks.get(attack_type.lower().replace(' ', '_'), {
        'name': 'Generic Security Response',
        'severity': 'Medium',
        'steps': [
            {'order': 1, 'action': 'analyze', 'description': 'Analyze the security event'},
            {'order': 2, 'action': 'contain', 'description': 'Contain the threat'},
            {'order': 3, 'action': 'notify', 'description': 'Notify security team'},
            {'order': 4, 'action': 'document', 'description': 'Document findings'}
        ],
        'auto_actions': ['notify']
    })
    
    return jsonify({'status': 'success', 'playbook': playbook})


@app.route('/api/report/pdf', methods=['GET'])
@login_required
def generate_pdf_report():
    """Generate PDF incident report"""
    try:
        from backend import pdf_report
        
        start_date = request.args.get('start_date', '')
        end_date = request.args.get('end_date', '')
        status_filter = request.args.get('status', 'all')
        
        analytics = compute_analytics()
        
        if start_date or end_date:
            start_time = f"{start_date} 00:00:00" if start_date else None
            end_time = f"{end_date} 23:59:59" if end_date else None
            logs = database.get_logs_by_time_range(start_time, end_time, status_filter)
        else:
            logs = database.get_all_logs()
        
        incidents = database.get_all_incidents()
        
        filepath, filename = pdf_report.generate_incident_report(
            analytics, logs, incidents, start_date, end_date
        )
        
        return send_file(
            filepath,
            as_attachment=True,
            download_name=filename,
            mimetype='application/pdf'
        )
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/clear-all-events', methods=['POST'])
def clear_all_events():
    """Clear all logs, blocked IPs, and incidents to reset the dashboard"""
    try:
        result = database.clear_all_events()
        
        app.last_results = None
        
        return jsonify({
            'status': 'success',
            'message': 'All events cleared successfully',
            'deleted': result
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/logs/clear-all', methods=['POST'])
@login_required
def clear_all_logs():
    """Clear all logs from the database"""
    try:
        count = database.delete_all_logs()
        app.last_results = None
        
        return jsonify({
            'status': 'success',
            'message': f'Deleted {count} logs successfully',
            'count': count
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/log/<int:log_id>/status', methods=['PUT'])
def update_log_status(log_id):
    """Update the analyst-assigned status of a log"""
    try:
        data = request.get_json()
        new_status = data.get('status')
        
        if new_status not in ['Normal', 'Suspicious', 'Malicious']:
            return jsonify({'status': 'error', 'message': 'Invalid status'}), 400
        
        updated = database.update_log_status(log_id, new_status)
        
        if updated:
            return jsonify({
                'status': 'success',
                'message': f'Log #{log_id} marked as {new_status}'
            })
        else:
            return jsonify({'status': 'error', 'message': 'Log not found'}), 404
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/log/<int:log_id>/investigate', methods=['POST'])
@login_required
def investigate_log_api(log_id):
    """Ensure an alert exists for this log and return the alert_id for deep linking"""
    try:
        # Check if alert already exists
        conn = database.get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT alert_id FROM alerts WHERE log_id = ?', (log_id,))
        row = cursor.fetchone()
        
        if row:
            conn.close()
            return jsonify({'status': 'success', 'alert_id': row[0]})
            
        # If not, we need the log data to create one
        cursor.execute('SELECT * FROM logs WHERE id = ?', (log_id,))
        log = cursor.fetchone()
        
        if not log:
            conn.close()
            return jsonify({'status': 'error', 'message': 'Log not found'}), 404
            
        # Create alert manually (force promote)
        # log structure: id, timestamp, message, status, actions_taken, blocked_ip, vt_status
        alert_id = alerts_db.create_alert(
            source_engine='Manual Investigation',
            severity='MEDIUM' if log[3] == 'Suspicious' else 'HIGH',
            confidence=0.85,
            raw_log=log[2],
            host='Manual',
            user='Analyst',
            log_id=log_id
        )
        
        conn.close()
        return jsonify({'status': 'success', 'alert_id': alert_id})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/alerts/clear-all', methods=['POST'])
@login_required
def clear_all_alerts():
    try:
        conn = database.get_db_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM alerts')
        conn.commit()
        conn.close()
        return jsonify({'status': 'success', 'message': 'All alerts cleared successfully'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/incidents/clear-all', methods=['POST'])
@login_required
def clear_all_incidents():
    try:
        conn = database.get_db_connection()
        cursor = conn.cursor()
        tables = [
            'incidents', 'incident_notes', 'incident_recommendations', 
            'incident_iocs', 'incident_response_summaries', 'incident_phases'
        ]
        for table in tables:
            cursor.execute(f"DELETE FROM {table}")
        conn.commit()
        conn.close()
        return jsonify({'status': 'success', 'message': 'All incidents cleared successfully'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500



@app.route('/api/analytics/logs', methods=['GET'])
def get_analytics_logs():
    """Get logs that have been sent to analytics"""
    try:
        logs = database.get_analytics_logs()
        return jsonify({
            'status': 'success',
            'logs': logs,
            'count': len(logs)
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/analytics/log/<int:log_id>/remove', methods=['POST'])
def remove_from_analytics(log_id):
    """Remove a log from analytics queue"""
    try:
        updated = database.remove_from_analytics(log_id)
        
        if updated:
            return jsonify({
                'status': 'success',
                'message': f'Log #{log_id} removed from analytics'
            })
        else:
            return jsonify({'status': 'error', 'message': 'Log not found'}), 404
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/analytics/log/<int:log_id>/block-ip', methods=['POST'])
def analytics_block_ip(log_id):
    """Block IP associated with a log from analytics"""
    try:
        log = database.get_log_by_id(log_id)
        if not log:
            return jsonify({'status': 'error', 'message': 'Log not found'}), 404
        
        ip = log.get('blocked_ip') or extract_ip(log.get('message', ''))
        
        if not ip or ip == 'Unknown':
            return jsonify({'status': 'error', 'message': 'No IP address found in log'}), 400
        
        database.save_blocked_ip(ip)
        
        socketio.emit('ip_blocked', {
            'ip': ip,
            'log_id': log_id,
            'reason': 'Blocked from analytics review',
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
        
        return jsonify({
            'status': 'success',
            'message': f'IP {ip} has been blocked',
            'ip': ip
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/analytics/log/<int:log_id>/escalate', methods=['POST'])
def analytics_escalate(log_id):
    """Escalate a log to an incident"""
    try:
        log = database.get_log_by_id(log_id)
        if not log:
            return jsonify({'status': 'error', 'message': 'Log not found'}), 404
        
        ip = log.get('blocked_ip') or extract_ip(log.get('message', ''))
        msg = log.get('message', '')
        if isinstance(msg, dict):
            msg = msg.get('log_text', str(msg))
        description = str(msg)[:500] if msg else 'Escalated from log analysis'
        
        incident_id = database.create_incident(
            log_id=log_id,
            incident_type='Security Alert',
            severity='High',
            ip_address=ip or 'Unknown',
            description=description
        )
        
        socketio.emit('incident_created', {
            'incident_id': incident_id,
            'log_id': log_id,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
        
        return jsonify({
            'status': 'success',
            'message': f'Log escalated to incident #{incident_id}',
            'incident_id': incident_id
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/analytics/log/<int:log_id>/isolate', methods=['POST'])
def analytics_isolate_host(log_id):
    """Isolate host associated with a log"""
    try:
        log = database.get_log_by_id(log_id)
        if not log:
            return jsonify({'status': 'error', 'message': 'Log not found'}), 404
        
        ip = log.get('blocked_ip') or extract_ip(log.get('message', ''))
        
        if not ip or ip == 'Unknown':
            return jsonify({'status': 'error', 'message': 'No IP address found in log'}), 400
        
        socketio.emit('host_isolated', {
            'ip': ip,
            'log_id': log_id,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
        
        return jsonify({
            'status': 'success',
            'message': f'Host {ip} isolation initiated',
            'actions': ['Network disconnected', 'System quarantined', 'Team alerted']
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/analytics')
@login_required
def analytics_page():
    """Alert Triage Queue page (L1)"""
    return redirect(url_for('alert_triage_page'))


@app.route('/settings')
@login_required
def settings_page():
    """Settings page for system configuration"""
    users = database.get_all_users()
    settings = database.get_all_settings()
    vt_configured = config_manager.is_api_key_configured('virustotal') or bool(os.getenv('VT_API_KEY', ''))
    agent_key_configured = config_manager.is_api_key_configured('agent') or bool(os.getenv('AGENT_API_KEY', ''))
    return render_template('settings.html', 
                         users=users, 
                         settings=settings,
                         vt_configured=vt_configured,
                         agent_key_configured=agent_key_configured,
                         user=session)


@app.route('/api/settings/api-key', methods=['POST'])
@login_required
def update_api_key():
    """Update API key settings with server-side validation"""
    data = request.get_json()
    key_type = data.get('key_type', '')
    key_value = data.get('value', '')
    
    if not key_type:
        return jsonify({'status': 'error', 'message': 'Key type is required'}), 400
    
    if not key_value or not key_value.strip():
        return jsonify({'status': 'error', 'message': 'API key value cannot be empty'}), 400
    
    key_value = key_value.strip()
    
    if len(key_value) < 8:
        return jsonify({'status': 'error', 'message': 'API key must be at least 8 characters'}), 400
    
    if key_type == 'virustotal':
        config_manager.set_vt_api_key(key_value)
        return jsonify({'status': 'success', 'message': 'VirusTotal API key updated'})
    elif key_type == 'agent':
        config_manager.set_agent_api_key(key_value)
        return jsonify({'status': 'success', 'message': 'Agent API key updated'})
    else:
        return jsonify({'status': 'error', 'message': 'Invalid key type'}), 400


@app.route('/api/settings/api-key/<key_type>', methods=['GET'])
@login_required
def get_api_key_status(key_type):
    """Check if an API key is configured"""
    if key_type == 'virustotal':
        configured = config_manager.is_api_key_configured('virustotal') or bool(os.getenv('VT_API_KEY', ''))
        return jsonify({'status': 'success', 'configured': configured})
    elif key_type == 'agent':
        configured = config_manager.is_api_key_configured('agent') or bool(os.getenv('AGENT_API_KEY', ''))
        return jsonify({'status': 'success', 'configured': configured})
    else:
        return jsonify({'status': 'error', 'message': 'Invalid key type'}), 400


@app.route('/api/settings/password', methods=['POST'])
@login_required
def change_password():
    """Change user password"""
    data = request.get_json()
    current_password = data.get('current_password', '')
    new_password = data.get('new_password', '')
    
    if not current_password or not new_password:
        return jsonify({'status': 'error', 'message': 'Both passwords required'}), 400
    
    user = database.get_user_by_username(session['username'])
    if not user or not check_password_hash(user['password_hash'], current_password):
        return jsonify({'status': 'error', 'message': 'Current password is incorrect'}), 401
    
    new_hash = generate_password_hash(new_password)
    database.update_user_password(user['id'], new_hash)
    
    return jsonify({'status': 'success', 'message': 'Password changed successfully'})


@app.route('/api/settings/threshold', methods=['POST'])
@login_required
def update_threshold():
    """Update alert threshold settings"""
    data = request.get_json()
    threshold_type = data.get('type', '')
    value = data.get('value', '')
    
    if threshold_type and value:
        database.set_setting(f'threshold_{threshold_type}', str(value))
        return jsonify({'status': 'success', 'message': f'{threshold_type} threshold updated'})
    
    return jsonify({'status': 'error', 'message': 'Invalid threshold data'}), 400


@app.route('/agents')
@login_required
def agents_page():
    """Agent monitoring page"""
    return render_template('agents.html', user=session)


database.init_incidents_table()


URL_CHECK_RATE_LIMIT = {}
URL_RATE_LIMIT_WINDOW = 60
URL_RATE_LIMIT_MAX = 60


def get_extension_api_key():
    """Get the Chrome Extension API key from config or environment"""
    return config_manager.get_api_key('extension') or os.getenv('EXTENSION_API_KEY', '')


def require_extension_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key') or (request.get_json(silent=True) or {}).get('api_key')
        expected_key = get_extension_api_key()
        if not expected_key:
            return jsonify({'error': 'Extension API key not configured. Set it in Settings.'}), 401
        if api_key != expected_key:
            return jsonify({'error': 'Invalid API key'}), 401
        return f(*args, **kwargs)
    return decorated


def check_url_rate_limit(client_ip):
    now = time.time()
    if client_ip not in URL_CHECK_RATE_LIMIT:
        URL_CHECK_RATE_LIMIT[client_ip] = []
    URL_CHECK_RATE_LIMIT[client_ip] = [t for t in URL_CHECK_RATE_LIMIT[client_ip] if now - t < URL_RATE_LIMIT_WINDOW]
    if len(URL_CHECK_RATE_LIMIT[client_ip]) >= URL_RATE_LIMIT_MAX:
        return False
    URL_CHECK_RATE_LIMIT[client_ip].append(now)
    return True


@app.route('/api/url/check', methods=['POST'])
def url_check():

    try:

        api_key = request.headers.get('X-API-Key') or (request.get_json(silent=True) or {}).get('api_key')
        expected_key = get_extension_api_key()
        if not expected_key:
            return jsonify({'error': 'Extension API key not configured. Set it in Settings.'}), 401
        if api_key != expected_key:
            return jsonify({'error': 'Invalid API key'}), 401

        client_ip = request.remote_addr
        if not check_url_rate_limit(client_ip):
            return jsonify({'error': 'Rate limit exceeded', 'retry_after': URL_RATE_LIMIT_WINDOW}), 429

        data = request.get_json(silent=True)
        if not data or 'url' not in data:
            return jsonify({'error': 'Missing url field'}), 400

        url = data['url'].strip()
        if not url or len(url) > 2048:
            return jsonify({'error': 'Invalid URL'}), 400

        start_time = time.time()
        result = classify_url_with_model(url)
        elapsed_ms = round((time.time() - start_time) * 1000, 2)

        from urllib.parse import urlparse
        try:
            domain = urlparse(url if '://' in url else f'http://{url}').hostname or ''
        except Exception:
            domain = ''

        try:
            database.save_url_check(
                url=url,
                domain=domain,
                risk_score=result['risk_score'],
                verdict=result['verdict'],
                reason=result['reason'],
                nudge_level=result['nudge_level'],
                features_json=json.dumps(result.get('features', {})),
                response_time_ms=elapsed_ms
            )
        except Exception as e:
            pass

        score = result['risk_score']
        if score >= 80:
            confidence = 'High'
        elif score >= 50:
            confidence = 'Medium'
        else:
            confidence = 'Low'

        # Normalize verdict to Title Case for nudge engine compatibility
        verdict = result['verdict']
        if verdict.upper() == 'MALICIOUS':
            verdict = 'Malicious'
        elif verdict.upper() == 'SUSPICIOUS':
            verdict = 'Suspicious'
        else:
            verdict = 'Safe'

        response_data = {
            'url':              url,
            'risk_score':       result['risk_score'],
            'verdict':          verdict,
            'reason':           result['reason'],
            'nudge_level':      result['nudge_level'],
            'confidence':       confidence,
            'response_time_ms': elapsed_ms
        }

        return jsonify(response_data)

    except Exception as e:
        traceback.print_exc()
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/url/feedback', methods=['POST'])
def url_feedback():

    api_key = request.headers.get('X-API-Key') or (request.get_json(silent=True) or {}).get('api_key')
    expected_key = get_extension_api_key()
    if not expected_key:
        return jsonify({'error': 'Extension API key not configured. Set it in Settings.'}), 401
    if api_key != expected_key:
        return jsonify({'error': 'Invalid API key'}), 401

    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Missing request body'}), 400

    url = data.get('url', '')
    action = data.get('action', '')

    if not url or action not in ('proceed', 'cancel', 'report'):
        return jsonify({'error': 'Invalid feedback data. action must be proceed, cancel, or report'}), 400

    try:
        database.save_url_feedback(
            url=url,
            risk_score=data.get('risk_score'),
            verdict=data.get('verdict'),
            action=action,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
    except Exception as e:
        pass

    return jsonify({'status': 'ok', 'message': 'Feedback recorded'})


@app.route('/api/url/stats', methods=['GET'])
@login_required
def url_stats():
    try:
        stats = database.get_url_check_stats()
        recent = database.get_recent_url_checks(limit=20)
        return jsonify({'stats': stats, 'recent_checks': recent})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/url-intelligence')
@login_required
def url_intelligence_page():
    return render_template('url_intelligence.html', user=session)


@app.route('/api/url/logs', methods=['GET'])
@login_required
def url_logs_api():
    try:
        page = max(1, request.args.get('page', 1, type=int))
        per_page = max(1, min(request.args.get('per_page', 25, type=int), 100))
        risk_level = request.args.get('risk_level', None)
        if risk_level and risk_level not in ('Phishing', 'Suspicious', 'Safe', 'all'):
            return jsonify({'error': 'Invalid risk_level'}), 400
        domain_search = request.args.get('domain', None)
        date_from = request.args.get('date_from', None)
        date_to = request.args.get('date_to', None)
        sort_by = request.args.get('sort_by', 'newest')
        if sort_by not in ('newest', 'oldest', 'risk_high', 'risk_low'):
            sort_by = 'newest'

        date_pattern = re.compile(r'^\d{4}-\d{2}-\d{2}$')
        if date_from and not date_pattern.match(date_from):
            date_from = None
        if date_to and not date_pattern.match(date_to):
            date_to = None

        result = database.get_url_logs_paginated(
            page=page,
            per_page=per_page,
            risk_level=risk_level,
            domain_search=domain_search,
            date_from=date_from,
            date_to=date_to,
            sort_by=sort_by
        )

        stats = database.get_url_check_stats()
        feedback = database.get_url_feedback_stats()
        timeline = database.get_url_scans_over_time(days=30)

        total_feedback = sum(feedback.values()) if feedback else 0
        override_rate = round((feedback.get('proceed', 0) / total_feedback * 100), 1) if total_feedback > 0 else 0.0

        return jsonify({
            'logs': result['logs'],
            'pagination': {
                'page': result['page'],
                'per_page': result['per_page'],
                'total': result['total'],
                'total_pages': result['total_pages']
            },
            'metrics': {
                'total': stats.get('total_checks', 0),
                'phishing': stats.get('phishing', 0),
                'suspicious': stats.get('suspicious', 0),
                'safe': stats.get('safe', 0),
                'override_rate': override_rate
            },
            'feedback': feedback,
            'timeline': timeline,
            'filtered_counts': result['counts']
        })
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


# ── 1. Log a behavior event ───────────────────────────────────────────────────
@app.route("/api/behavior/log", methods=["POST"])
def log_behavior():
    try:
        data = request.get_json(force=True)
        required = ["user_id", "event_type", "url",
                    "risk_score", "verdict", "session_id"]
        missing = [f for f in required if f not in data]
        if missing:
            return jsonify({"error": f"Missing fields: {missing}"}), 400
        event = BehaviorEvent(
            user_id    = str(data["user_id"]),
            event_type = str(data["event_type"]),
            url        = str(data["url"]),
            risk_score = float(data["risk_score"]),
            verdict    = str(data["verdict"]),
            timestamp  = datetime.utcnow(),
            session_id = str(data["session_id"])
        )
        behavior_store.log_event(event)
        return jsonify({"status": "logged"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── 2. Get event history for a user ──────────────────────────────────────────
@app.route("/api/behavior/events/<user_id>", methods=["GET"])
@app.route("/api/behavior/user-profile/<user_id>", methods=["GET"])
def get_user_profile_detail(user_id):
    """Fetch detailed profile for a specific user including classification and URL history."""
    try:
        events = behavior_store.get_user_events(user_id, last_n=50)
        if not events:
            return jsonify({"status": "error", "message": "User profile not found"}), 404
        
        # Get profile classification
        profile = profiler.get_user_profile(user_id, events)
        
        # Calculate statistics
        warnings_dismissed = sum(1 for e in events if e["event_type"] in ["warning_dismissed", "blocked_action_bypassed"])
        safe_visits = sum(1 for e in events if e["event_type"] == "safe_url_visited")
        risky_visits = sum(1 for e in events if e["event_type"] == "risky_url_visited")
        
        return jsonify({
            "status": "success",
            "user_id": user_id,
            "profile": profile,
            "stats": {
                "total_events": len(events),
                "warnings_dismissed": warnings_dismissed,
                "safe_visits": safe_visits,
                "risky_visits": risky_visits
            },
            "history": events
        }), 200
    except Exception as e:
        print(f"[ERROR] Profile fetch failed: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500


def get_behavior_events(user_id):
    try:
        events = behavior_store.get_user_events(user_id)
        return jsonify(events), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/behavior/all-users", methods=["GET"])
def get_all_behavior_users():
    """Fetch and summarize behavior data for all users tracked in the system."""
    try:
        df = behavior_store.get_all_events()
        if df.empty:
            return jsonify([]), 200
        
        users_data = []
        # Group by user_id to get the latest state and statistics for each user
        for user_id, group in df.groupby("user_id"):
            # Sort group by timestamp DESC to get the last event easily
            group = group.sort_values(by="timestamp", ascending=False)
            
            # Get profile classification
            events_list = group.to_dict('records')
            profile = profiler.get_user_profile(user_id, events_list)
            
            # Count warning dismissals and bypasses
            warnings_ignored = len(group[group["event_type"].isin(["warning_dismissed", "blocked_action_bypassed"])])
            
            # Get the most recent event
            last_event_row = group.iloc[0]
            
            users_data.append({
                "user_id": user_id,
                "behavior_type": profile["user_type"].capitalize(),
                "risk_score": round(group["risk_score"].mean() * 100, 1),
                "warnings_ignored": warnings_ignored,
                "last_event": last_event_row["event_type"].replace('_', ' ').capitalize(),
                "timestamp": last_event_row["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
            })
            
        return jsonify(users_data), 200
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500


# ── 3. Get behavior profile for a user ───────────────────────────────────────
@app.route("/api/behavior/profile/<user_id>", methods=["GET"])
def get_behavior_profile(user_id):
    try:
        events = behavior_store.get_user_events(user_id)
        if len(events) < 5:
            return jsonify({
                "status":        "insufficient_data",
                "events_needed": 5 - len(events)
            }), 200
        profile = profiler.get_user_profile(user_id, events)
        profile["theory_explanation"] = \
            profiler.get_behavior_theory_explanation(profile["user_type"])
        return jsonify(profile), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── 4. Decide nudge for a user + URL ─────────────────────────────────────────
@app.route("/api/nudge/decide", methods=["POST"])
def decide_nudge():
    try:
        data = request.get_json(force=True)
        required = ["user_id", "url", "risk_score", "verdict"]
        missing = [f for f in required if f not in data]
        if missing:
            return jsonify({"error": f"Missing fields: {missing}"}), 400
        events = behavior_store.get_user_events(data["user_id"])
        if len(events) >= 5:
            profile   = profiler.get_user_profile(data["user_id"], events)
            user_type = profile["user_type"]
            features  = profile["features"]
        else:
            user_type = "cautious"
            features  = {}
        nudge = nudge_engine_inst.get_nudge(
            user_type,
            data["verdict"],
            float(data["risk_score"]),
            data["url"],
            features
        )
        return jsonify(nudge), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── 5. Export behavior dataset as CSV (admin) ─────────────────────────────────
@app.route("/api/dataset/export", methods=["GET"])
def export_dataset():
    if request.headers.get("X-Admin-Key") != ADMIN_KEY:
        return jsonify({"error": "Forbidden"}), 403
    try:
        df    = dataset_builder.build_dataset(behavior_store)
        path  = dataset_builder.export_csv(df)
        stats = dataset_builder.get_statistics(df)
        return jsonify({"exported_to": path, "statistics": stats}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── 6. Dataset statistics only (admin) ───────────────────────────────────────
@app.route("/api/dataset/stats", methods=["GET"])
def dataset_stats():
    if request.headers.get("X-Admin-Key") != ADMIN_KEY:
        return jsonify({"error": "Forbidden"}), 403
    try:
        df    = dataset_builder.build_dataset(behavior_store)
        stats = dataset_builder.get_statistics(df)
        return jsonify(stats), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── 7. Health check for all new modules ──────────────────────────────────────
@app.route("/api/behavior/health", methods=["GET"])
def behavior_health():
    try:
        behavior_store.get_all_events()
        test_nudge = nudge_engine_inst.get_nudge(
            "impulsive", "Suspicious", 0.75, "http://test.com", {}
        )
        return jsonify({
            "status":          "ok",
            "db_connected":    True,
            "modules_loaded":  [
                "BehaviorStore", "UserProfiler",
                "NudgeEngine",   "DatasetBuilder"
            ],
            "test_nudge_type": test_nudge.get("nudge_type"),
            "timestamp":       datetime.utcnow().isoformat()
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "detail": str(e)}), 500


# ── 8. Train behavior classifier ─────────────────────────────────────────────
@app.route("/api/behavior/train", methods=["POST"])
def train_behavior_model():
    if request.headers.get("X-Admin-Key") != ADMIN_KEY:
        return jsonify({"error": "Forbidden"}), 403
    try:
        # Build dataset from current behavior store
        df = dataset_builder.build_dataset(behavior_store)

        if df.empty:
            return jsonify({"error": "No data available for training"}), 400

        # Show dataset info
        label_counts = df["label"].value_counts().to_dict()
        label_counts = {k: int(v) for k, v in label_counts.items()}

        # Train the classifier
        result = classifier.train(df)

        if "error" in result:
            return jsonify({
                "status": "failed",
                "reason": result["error"]
            }), 400

        # Build feature importance list sorted by score
        importances = sorted(
            result["feature_importances"].items(),
            key=lambda x: -x[1]
        )

        return jsonify({
            "status":        "trained",
            "dataset_shape": {"rows": int(len(df)), "cols": int(len(df.columns))},
            "label_counts":  label_counts,
            "accuracy":      round(result["accuracy"] * 100, 2),
            "feature_importances": [
                {"feature": k, "importance_pct": round(v * 100, 2)}
                for k, v in importances
            ],
            "model_saved_to": "behavior_dataset/behavior_model.pkl"
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── 9. Generate synthetic behavioral dataset ──────────────────────────────────
@app.route("/api/dataset/generate-synthetic", methods=["POST"])
def generate_synthetic_dataset():
    if request.headers.get("X-Admin-Key") != ADMIN_KEY:
        return jsonify({"error": "Forbidden"}), 403
    try:
        import subprocess, sys
        result = subprocess.run(
            [sys.executable, "behavior_dataset/generate_synthetic.py"],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            return jsonify({
                "status": "error",
                "detail": result.stderr
            }), 500
        return jsonify({
            "status": "generated",
            "output": result.stdout,
            "files": [
                "behavior_dataset/synthetic_behavior_dataset.csv",
                "behavior_dataset/synthetic_cautious.csv",
                "behavior_dataset/synthetic_impulsive.csv",
                "behavior_dataset/synthetic_negligent.csv",
            ]
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── 10. Train classifier on synthetic dataset ─────────────────────────────────
@app.route("/api/behavior/train-synthetic", methods=["POST"])
def train_on_synthetic():
    if request.headers.get("X-Admin-Key") != ADMIN_KEY:
        return jsonify({"error": "Forbidden"}), 403
    try:
        path = "behavior_dataset/synthetic_behavior_dataset.csv"
        if not os.path.exists(path):
            return jsonify({
                "error": "Synthetic dataset not found. Generate it first."
            }), 400

        df = pd.read_csv(path)

        feature_cols = [
            "warning_dismissal_rate",
            "risky_url_ratio",
            "avg_risk_score_on_bypass",
            "response_time_variance",
            "heeded_rate",
            "download_attempt_rate",
            "total_events",
        ]

        result = classifier.train(df[feature_cols + ["label"]])

        if "error" in result:
            return jsonify({
                "status": "failed",
                "reason": result["error"]
            }), 400

        importances = sorted(
            result["feature_importances"].items(),
            key=lambda x: -x[1]
        )

        return jsonify({
            "status":       "trained",
            "dataset_size": int(len(df)),
            "label_counts": df["label"].value_counts().to_dict(),
            "accuracy":     round(result["accuracy"] * 100, 2),
            "feature_importances": [
                {"feature": k, "importance_pct": round(v * 100, 2)}
                for k, v in importances
            ],
            "model_saved_to": "behavior_dataset/behavior_model.pkl"
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
# ── 11. Demo mode check ───────────────────────────────────────────────────────
@app.route("/api/url/demo-check", methods=["POST"])
def url_demo_check():
    try:
        data    = request.get_json(force=True)
        url     = data.get("url", "")
        verdict = data.get("force_verdict", "Suspicious")
        score   = float(data.get("force_score", 0.75))

        # Map verdict to nudge level
        nudge_map = {
            "Malicious":  "high",
            "Suspicious": "medium",
            "Safe":       "none"
        }

        return jsonify({
            "url":              url,
            "verdict":          verdict,
            "risk_score":       score,
            "confidence":       "High",
            "reason":           "Demo mode — forced verdict for presentation",
            "response_time_ms": 10.0,
            "nudge_level":      nudge_map.get(verdict, "medium"),
            "demo_mode":        True
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, use_reloader=False, allow_unsafe_werkzeug=True)
