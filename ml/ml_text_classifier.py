"""
ML Text Classifier for ILA-SOC

This module handles text-based log classification, separate from network flow analysis.
It supports multiple ML pipelines:
1. Enhanced TF-IDF model (preferred) - SMOTE-balanced with better class distribution
2. TF-IDF model (fallback) - Original TF-IDF with character n-grams
3. 32-feature model (fallback) - Original feature extraction
4. Isolation Forest (anomaly detection) - Zero-day/novel attack detection
5. Temporal Analyzer - Slow attack/APT detection

The system automatically uses the best available model.
"""

import json
import numpy as np
import re
import joblib
import os
import sys
from typing import Tuple, Optional, Dict, Any
from collections import Counter, deque
from datetime import datetime
import time
from scipy.sparse import hstack, csr_matrix
import math

from ml.contextual_features import extract_contextual_features

text_model = None
text_scaler = None
tfidf_model = None
tfidf_vectorizer = None
enhanced_model = None
enhanced_vectorizer = None
anomaly_detector = None
xgboost_model = None
xgboost_label_encoder = None
rf_calibrated = None
xgb_calibrated = None
xgb_calibrated_le = None
context_scaler = None
MODEL_READY = False
TFIDF_READY = False
ENHANCED_READY = False
ANOMALY_READY = False
XGBOOST_READY = False
CALIBRATED_READY = False

TRUSTED_DOMAINS = [
    "google.com", "microsoft.com", "paypal.com", "apple.com", "github.com",
    "microsoftonline.com", "amazon.com", "facebook.com", "twitter.com", "linkedin.com",
    "yahoo.com", "netflix.com", "instagram.com"
]

BRAND_KEYWORDS = ["google", "microsoft", "paypal", "apple", "github", "amazon", "facebook", "yahoo", "netflix"]

import urllib.parse

def apply_context_correction(log_text: str, ml_label: str, ml_conf: float) -> Tuple[str, float]:
    if not log_text or ml_label is None:
        return ml_label, ml_conf
        
    text = str(log_text).strip().lower()
    
    # ONLY apply if it's a clear URL or domain
    is_url = text.startswith('http://') or text.startswith('https://')
    is_domain = not is_url and (re.match(r'^[a-z0-9.-]+\.[a-z]{2,}$', text) and '/' not in text)
    
    if not is_url and not is_domain:
        return ml_label, ml_conf
        
    parse_text = text if is_url else 'http://' + text
        
    try:
        domain = urllib.parse.urlparse(parse_text).netloc
        if ':' in domain:
            domain = domain.split(':')[0]
    except:
        return ml_label, ml_conf
        
    if not domain:
        return ml_label, ml_conf
        
    parts = domain.split('.')
    if len(parts) >= 2:
        base_domain = f"{parts[-2]}.{parts[-1]}"
    else:
        base_domain = domain
        
    ml_score = ml_conf if ml_label == "Malicious" else (50.0 if ml_label == "Suspicious" else 0.0)
    heuristic_score = 0.0
    domain_trust_score = 0.0
    
    is_trusted = base_domain in TRUSTED_DOMAINS or domain in TRUSTED_DOMAINS
    if is_trusted:
        domain_trust_score = -400.0  # Force downgrade
        
    is_brand_mismatch = False
    if not is_trusted:
        for brand in BRAND_KEYWORDS:
            if brand in text and brand not in base_domain:
                is_brand_mismatch = True
                break
                
    if is_brand_mismatch:
        heuristic_score = 250.0  # Force upgrade
        
    # Combine scores as requested
    final_score = 0.6 * ml_score + 0.3 * heuristic_score + 0.1 * domain_trust_score
    
    # Clamp to valid confidence
    final_score = max(0.0, min(100.0, final_score))
    
    if final_score >= 60.0:
        new_label = "Malicious"
    elif final_score >= 30.0:
        new_label = "Suspicious"
    else:
        new_label = "Normal"
        
    return new_label, final_score

def clean_log(log_text):
    """
    Clean log text to match training data preprocessing.
    Removes timestamps, IPs, UUIDs, paths, numbers, and normalizes whitespace.
    """
    text = log_text.lower().strip()
    text = re.sub(r'\d{4}-\d{2}-\d{2}', '', text)
    text = re.sub(r'\d{2}:\d{2}:\d{2}', '', text)
    text = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '', text)
    text = re.sub(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', '', text)
    text = re.sub(r'/[\w/.-]+', '', text)
    text = re.sub(r'\b\d+\b', '', text)
    text = re.sub(r'\s+', ' ', text)
    
    return text.strip()

try:
    enhanced_model_path = "models/text_model_enhanced.pkl"
    enhanced_vectorizer_path = "models/tfidf_vectorizer_enhanced.pkl"
    anomaly_detector_path = "models/anomaly_detector.pkl"
    
    if os.path.exists(enhanced_model_path) and os.path.exists(enhanced_vectorizer_path):
        enhanced_model = joblib.load(enhanced_model_path)
        enhanced_vectorizer = joblib.load(enhanced_vectorizer_path)
        ENHANCED_READY = True
        print(f"[OK] Enhanced TF-IDF model loaded (SMOTE-balanced, PREFERRED)")
        print(f"   Model classes: {enhanced_model.classes_}")
    
    if os.path.exists(anomaly_detector_path):
        anomaly_detector = joblib.load(anomaly_detector_path)
        ANOMALY_READY = True
        print(f"[OK] Isolation Forest anomaly detector loaded (Zero-Day Detection)")
except Exception as e:
    print(f"[WARNING] Failed to load enhanced models: {e}")

try:
    tfidf_model_path = "models/text_model_tfidf.pkl"
    tfidf_vectorizer_path = "models/tfidf_vectorizer.pkl"
    
    if os.path.exists(tfidf_model_path) and os.path.exists(tfidf_vectorizer_path):
        tfidf_model = joblib.load(tfidf_model_path)
        tfidf_vectorizer = joblib.load(tfidf_vectorizer_path)
        TFIDF_READY = True
        if ENHANCED_READY:
            print(f"[OK] TF-IDF ML model loaded (FALLBACK)")
        else:
            print(f"[OK] TF-IDF ML model loaded successfully (PREFERRED)")
        print(f"   Model classes: {tfidf_model.classes_}")
    else:
        print(f"ℹ️  TF-IDF model not found, will use 32-feature model")
except Exception as e:
    print(f"⚠️  Failed to load TF-IDF model: {e}")
    print(f"   Will fall back to 32-feature model")

try:
    text_model = joblib.load("models/text_model_legacy.pkl")
    text_scaler = joblib.load("models/text_scaler_legacy.pkl")
    MODEL_READY = True
    if TFIDF_READY:
        print(f"[OK] 32-feature ML model loaded (FALLBACK)")
    else:
        print(f"[OK] 32-feature ML model loaded successfully")
    print(f"   Model classes: {text_model.classes_}")
    print(f"   MODEL_READY: {MODEL_READY}")
except Exception as e:
    print(f"⚠️  Failed to load 32-feature ML model: {e}")
    print(f"   MODEL_READY: {MODEL_READY}")
    if not TFIDF_READY:
        print(f"   Will fall back to rule-based classification")

try:
    xgboost_model_path = "models/xgboost_text_model.pkl"
    if os.path.exists(xgboost_model_path):
        xgb_data = joblib.load(xgboost_model_path)
        xgboost_model = xgb_data['model']
        xgboost_label_encoder = xgb_data['label_encoder']
        XGBOOST_READY = True
        print(f"[OK] XGBoost text classifier loaded (Ensemble member)")
        print(f"   Classes: {xgb_data['classes']}")
    else:
        print(f"ℹ️  XGBoost model not found, ensemble disabled")
except Exception as e:
    print(f"⚠️  Failed to load XGBoost model: {e}")

try:
    rf_cal_path = "models/rf_calibrated.pkl"
    xgb_cal_path = "models/xgb_calibrated.pkl"
    ctx_scaler_path = "models/context_scaler.pkl"
    if (os.path.exists(rf_cal_path) and os.path.exists(xgb_cal_path)
            and os.path.exists(ctx_scaler_path) and TFIDF_READY and tfidf_vectorizer is not None):
        rf_cal_data = joblib.load(rf_cal_path)
        rf_calibrated = rf_cal_data['model']
        xgb_cal_data = joblib.load(xgb_cal_path)
        xgb_calibrated = xgb_cal_data['model']
        xgb_calibrated_le = xgb_cal_data['label_encoder']
        context_scaler = joblib.load(ctx_scaler_path)

        expected_classes = {'Malicious', 'Normal', 'Suspicious'}
        rf_cls = set(str(c) for c in rf_cal_data['classes'])
        xgb_cls = set(str(c) for c in xgb_cal_data['classes'])
        if rf_cls != expected_classes or xgb_cls != expected_classes:
            raise ValueError(f"Class mismatch: RF={rf_cls}, XGB={xgb_cls}, expected={expected_classes}")

        tfidf_dim = len(tfidf_vectorizer.get_feature_names_out())
        from ml.contextual_features import NUM_FEATURES as CTX_FEATURES
        expected_dim = tfidf_dim + CTX_FEATURES
        print(f"   Expected feature dimension: {expected_dim} ({tfidf_dim} TF-IDF + {CTX_FEATURES} contextual)")

        CALIBRATED_READY = True
        print(f"[OK] Calibrated ensemble loaded (RF+XGBoost with contextual features)")
        print(f"   RF classes: {rf_cal_data['classes']}")
        print(f"   XGB classes: {xgb_cal_data['classes']}")
    else:
        print(f"ℹ️  Calibrated models not found, using uncalibrated pipeline")
except Exception as e:
    CALIBRATED_READY = False
    print(f"⚠️  Failed to load calibrated models: {e}")


def extract_text_features(log_text: str) -> np.ndarray:
    """
    Extract numeric features from a raw text log.
    
    This function analyzes the text content of a log entry and converts it into
    a numeric feature vector suitable for machine learning classification.
    
    Features (32 total):
    - Basic numeric features (4): length, digit count, uppercase count, special char count
    - Suspicious keyword counts (6): failed, unauthorized, invalid, denied, timeout, error
    - Malicious keyword counts (8): attack, mimikatz, injection, sql, xss, bruteforce, malware, exploit
    - Protocol keyword flags (4): http, ssh, ftp, dns
    - Log level score (1): INFO=0, WARNING=1, ERROR=2, CRITICAL=3
    - Text statistics (2): word count, Shannon entropy
    - Additional features (7): IP count, number count, avg word length, alphanum ratio, 
                                has timestamp, has file path, unique char count
    
    Args:
        log_text: Raw log message as a string
        
    Returns:
        numpy.ndarray: Feature vector of length 32
        
    Example:
        >>> log = "Failed login attempt from 192.168.1.100"
        >>> features = extract_text_features(log)
        >>> features.shape
        (32,)
    """
    log_lower = log_text.lower()
    features = []
    
    # ========== 1. BASIC NUMERIC FEATURES (4 features) ==========
    features.append(len(log_text))
    features.append(sum(c.isdigit() for c in log_text))
    features.append(sum(c.isupper() for c in log_text))
    
    special_chars = set('!@#$%^&*(){}[]<>?/|\\~`')
    features.append(sum(c in special_chars for c in log_text))
    
    # ========== 2. SUSPICIOUS KEYWORD COUNTS (6 features) ==========
    suspicious_keywords = ["failed", "unauthorized", "invalid", "denied", "timeout", "error"]
    for keyword in suspicious_keywords:
        features.append(log_lower.count(keyword))
    
    # ========== 3. MALICIOUS KEYWORD COUNTS (8 features) ==========
    malicious_keywords = ["attack", "mimikatz", "injection", "sql", "xss", "bruteforce", "malware", "exploit"]
    for keyword in malicious_keywords:
        features.append(log_lower.count(keyword))
    
    # ========== 4. PROTOCOL KEYWORD FLAGS (4 features) ==========
    protocols = ["http", "ssh", "ftp", "dns"]
    for protocol in protocols:
        features.append(1 if protocol in log_lower else 0)
    
    # ========== 5. LOG LEVEL SCORE (1 feature) ==========
    log_level_score = 0
    if any(level in log_lower for level in ["info"]):
        log_level_score = 0
    elif any(level in log_lower for level in ["warning", "warn"]):
        log_level_score = 1
    elif any(level in log_lower for level in ["error"]):
        log_level_score = 2
    elif any(level in log_lower for level in ["critical", "alert", "emerg"]):
        log_level_score = 3
    features.append(log_level_score)
    
    # ========== 6. WORD COUNT & ENTROPY (2 features) ==========
    words = log_text.split()
    features.append(len(words))
    
    shannon_entropy = 0.0
    if len(log_text) > 0:
        char_freq = Counter(log_text)
        total_chars = len(log_text)
        for count in char_freq.values():
            prob = count / total_chars
            shannon_entropy -= prob * math.log2(prob)
    features.append(shannon_entropy)
    
    # ========== 7. ADDITIONAL FEATURES (7 features) ==========
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    features.append(len(re.findall(ip_pattern, log_text)))
    
    number_pattern = r'\b\d+\b'
    features.append(len(re.findall(number_pattern, log_text)))
    
    avg_word_length = sum(len(word) for word in words) / len(words) if words else 0
    features.append(avg_word_length)
    
    alphanum_count = sum(c.isalnum() for c in log_text)
    alphanum_ratio = alphanum_count / len(log_text) if len(log_text) > 0 else 0
    features.append(alphanum_ratio)
    
    timestamp_pattern = r'\d{4}-\d{2}-\d{2}|\d{2}:\d{2}:\d{2}'
    features.append(1 if re.search(timestamp_pattern, log_text) else 0)
    
    filepath_pattern = r'[/\\][a-zA-Z0-9_\-./\\]+'
    features.append(1 if re.search(filepath_pattern, log_text) else 0)
    
    features.append(len(set(log_text)))
    
    return np.array(features, dtype=np.float32)


BENIGN_WINDOWS_EVENT_IDS = [
    "4624", "4625", "4634", "4647", "4648", "4672", "4673", "4688", "4689",
    "4698", "4702", "4720", "4722", "4723", "4724", "4725", "4726", "4728",
    "4732", "4733", "4738", "4740", "4756", "4767", "4768", "4769", "4770",
    "4771", "4776", "4798", "4799", "4800", "4801", "4802", "4803",
    "5156", "5157", "5158", "5379", "5380", "5381", "5382",
    "158", "1014", "1001", "1073758208", "7036", "7040", "7045",
    "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", 
    "16", "17", "18", "19", "20", "21", "22", "23", "24", "25", "26"
]

BENIGN_WINDOWS_PATTERNS = [
    "microsoft-windows-security-auditing",
    "microsoft-windows-time-service",
    "microsoft-windows-dns-client",
    "microsoft-windows-powershell",
    "microsoft-windows-sysmon",
    "microsoft-windows-kernel-power",
    "microsoft-windows-taskscheduler",
    "microsoft-windows-grouppolicy",
    "microsoft-windows-wmi",
    "windows error reporting",
    "software protection platform",
    "credential manager credentials were read",
    "local group membership was enumerated",
    "account was successfully logged on",
    "special privileges assigned to new logon",
    "vmictimeprovider",
    "svchost.exe",
    "lsass.exe targetimage",
    "a logon was attempted",
    "the time provider",
    "name resolution for the name",
    "powershell.exe started",
    "engine state is changed",
    "scheduled task registered",
    "user logon notification",
    "service state transition",
    "service started successfully",
    "system shutdown",
    "windows is starting up",
    "interactive logon",
    "network logon",
    "remote desktop services",
    "terminal services",
    "logonid:",
    "logon type: 2",
    "logon type: 3",
    "logon type: 10",
    "workstation name:",
    "logon process: user32",
    "authentication package: negotiate",
    "process command line",
    "group policy",
    "gpupdate",
    "windows update",
    "wsus",
    "bits transfer",
    "certificate services",
    "active directory",
    "microsoftaccount:user=",
    "windowslive:(token)",
    "windowslive:(cert)",
    "virtualapp/didlogical",
    "nt authority\\system",
    "nt authority\\network service",
    "nt authority\\local service",
    "ping 8.8.8.8",
    "ping google.com",
    "notepad.exe",
    "explorer.exe",
    "chrome.exe",
    "msedge.exe",
    "dns queries",
    "name resolution"
]

# State for deduplication of repeated identical logs
_LAST_LOG_HASH = None
_LAST_LOG_RESULT = None

# State for behavioral reconnaissance tracking (3+ discovery commands in 120s window)
_RECON_STATE = {} 

def is_recon_behavior_detected(data: dict) -> bool:
    """
    Stateful detection for reconnaissance sequences.
    Returns True if this event is the 3rd+ discovery command from this host in 120s.
    """
    try:
        # Extract context
        host = data.get('hostname') or data.get('host') or data.get('Computer') or 'unknown'
        user = data.get('user') or data.get('username') or data.get('SubjectUserName') or ''
        host_key = f"{host}:{user}" if user else host
        
        cmd = str(data.get('CommandLine') or data.get('command_line') or data.get('message', '')).lower()
        eid = str(data.get('event_id') or data.get('EventID') or '')
        
        # Recon Indicators specified by USER
        recon_indicators = [
            'whoami', 'hostname', 'tasklist', 'ipconfig', 'arp', 'route', 'net.exe', 'net1.exe', 
            'systeminfo', 'nltest', 'quser', 'query.exe', 'wmic', 'net user', 'net localgroup'
        ]
        
        if not (any(c in cmd for c in recon_indicators) or eid in ['4798', '4799']):
            return False
            
        # Update state
        now = time.time()
        if host_key not in _RECON_STATE:
            _RECON_STATE[host_key] = deque(maxlen=10)
            
        while _RECON_STATE[host_key] and now - _RECON_STATE[host_key][0] > 120:
            _RECON_STATE[host_key].popleft()
            
        _RECON_STATE[host_key].append(now)
        return len(_RECON_STATE[host_key]) >= 3
    except:
        return False


CRITICAL_ATTACK_SIGNATURES = {
    "credential_theft": [
        "mimikatz", "sekurlsa", "logonpasswords", "kerberos::golden",
        "hashdump", "sam.hiv", "ntds.dit", "credential theft", "credential dump",
        "lsadump", "dcsync", "secretsdump", "pypykatz", "procdump -ma lsass"
    ],
    "lateral_movement": [
        "psexec", "wmic", "winrm", "dcom", "pass-the-hash", "pth", "pass-the-ticket",
        "golden ticket", "silver ticket", "beacon", "c2", "command and control"
    ],
    "persistence": [
        "schtasks /create", "schtasks create", "reg add", "run key", "startup folder",
        "service install", "backdoor", "rootkit", "persistence", "autorun", "at job"
    ],
    "privilege_escalation": [
        "privilege escalation", "escalate privilege", "setuid", "getsystem", "token impersonation",
        "runas /user", "chmod 777", "chmod +s", "sudo -i", "sudo su"
    ],
    "reverse_shell": [
        "reverse shell", "/dev/tcp", "netcat", "nc -e", "bash -i", "python -c",
        "php -r", "ruby -rsocket", "powershell -nop", "-enc", "encoded command"
    ],
    "web_attacks": [
        "sql injection", "union select", "'--", "or 1=1", "xss", "<script>",
        "alert(", "document.cookie", "webshell", "shell.php", "eval(", "cmd.php",
        "../../../", "..\\..\\", "/etc/passwd", "path traversal", "lfi", "rfi"
    ],
    "network_attacks": [
        "port scan", "nmap", "reconnaissance", "arp spoof", "mitm", "man in the middle",
        "syn flood", "ddos", "dns tunneling", "exfiltration"
    ],
    "malware": [
        "trojan", "ransomware", "keylogger", "spyware", "botnet", "dropper",
        "payload", "shellcode", "exploit", "metasploit", "cobalt strike"
    ],
    "anti_forensics": [
        "anti-forensic", "history -c", "rm -rf /var/log", "clear event log",
        "timestomp", "log tampering", "wipe", "shred"
    ],
    "log4shell_jndi": [
        "jndi:", "${jndi:", "jndi:ldap", "jndi:rmi", "jndi:dns", "log4j", "log4shell",
        "${lower:", "${upper:", "${env:", "${java:", "${base64:", "jndi:corba"
    ],
    "active_directory": [
        "dcsync", "dcsynce", "drsuapi", "replication", "kerberoasting", "as-rep roasting",
        "asreproast", "bloodhound", "sharphound", "rubeus", "krbrelayup", "addmember",
        "dscacls", "dsquery", "dsrm", "group policy", "gpo abuse", "acl abuse",
        "shadowcredentials", "samaccountname", "nopac", "zerologon"
    ],
    "cloud_attacks": [
        "imds", "instance metadata", "169.254.169.254", "metadata.google", "metadata.azure",
        "sts:assumeRole", "iam:CreateAccessKey", "s3:GetObject", "ec2:RunInstances",
        "cloudtrail", "ssm:sendcommand", "lambda:invoke", "ecs:runtask",
        "gcloud auth", "azure login", "aws configure", "service account key",
        "storage bucket", "blob container", "credential exposure"
    ],
    "container_kubernetes": [
        "container escape", "pod escape", "kubectl exec", "docker.sock", "docker exec",
        "crictl exec", "containerd", "privileged container", "hostpid", "hostnetwork",
        "serviceaccount token", "kubelet api", "etcd", "kube-apiserver", "kube-proxy",
        "configmap", "secret mount", "clusterrolebinding", "podsecuritypolicy",
        "node shell", "nsenter", "breakout", "cve-2022-0185"
    ],
    "modern_evasion": [
        "amsi bypass", "amsi.dll", "amsiscanbuffer", "amsicontext", "amsiopensession",
        "etw patching", "etweventwrite", "nttracevent", "patchamsi", "invoke-obfuscation",
        "reflective loading", "donut", "shellcode runner", "process hollowing",
        "dll sideloading", "unhooking", "syscall", "direct syscall", "hells gate",
        "heavens gate", "wow64", "ppid spoofing", "process ghosting", "herpaderping"
    ],
    "api_attacks": [
        "graphql introspection", "graphql injection", "rest api abuse", "api key exposure",
        "jwt tampering", "jwt none algorithm", "oauth abuse", "openid connect",
        "ssrf", "server-side request forgery", "bola", "broken object level",
        "mass assignment", "parameter pollution", "rate limit bypass", "api enumeration"
    ],
    "supply_chain": [
        "typosquatting", "dependency confusion", "package hijack", "npm audit",
        "pip install malicious", "gem install attack", "cargo audit", "nuget attack",
        "codecov breach", "solarwinds", "3cx", "notpetya", "build system compromise",
        "ci/cd attack", "github actions abuse", "gitlab runner", "jenkins exploit"
    ],
    "ransomware_specific": [
        "lockbit", "conti", "ryuk", "revil", "sodinokibi", "maze", "dharma", "phobos",
        "wannacry", "eternalblue", "petya", "blackcat", "alphv", "hive", "babuk",
        "clop", "blackmatter", "darkside", ".encrypted", ".locked", "ransom note"
    ],
    "zero_day_indicators": [
        "proxyshell", "proxylogon", "proxynotshell", "cve-2021-44228", "cve-2021-40444",
        "cve-2022-26134", "cve-2023-23397", "cve-2023-27350", "cve-2024-", "0day",
        "zero-day", "unpatched", "exploit kit", "spring4shell", "text4shell"
    ]
}

SUSPICIOUS_PATTERNS = [
    "failed password", "failed login", "authentication failure", "access denied",
    "unauthorized", "permission denied", "invalid user", "unknown user",
    "brute force", "multiple attempts", "rate limit", "blocked",
    "suspicious", "anomaly", "warning", "critical", "alert",
    "lateral movement", "credential dumping", "suspicious execution",
    "powershell -enc", "brute force login", "suspicious powershell"
]


def is_benign_windows_event(log_text: str) -> bool:
    """
    Check if a log is a known-benign Windows event that should not be flagged.
    Uses multiple heuristics to minimize false positives.
    
    Returns:
        True if the log matches benign Windows event patterns
    """
    global _LAST_LOG_HASH, _LAST_LOG_RESULT
    
    log_lower = log_text.lower().strip()
    
    # Deduplication of identical logs in short intervals
    current_hash = hash(log_lower)
    if current_hash == _LAST_LOG_HASH:
        return _LAST_LOG_RESULT
    
    _LAST_LOG_HASH = current_hash
    _LAST_LOG_RESULT = False # Default until proven benign
    
    # MALICIOUS OVERRIDES - Always flag these even if in Windows logs
    MALICIOUS_INDICATORS = [
        "mimikatz", "sekurlsa", "hashdump", "credential dump",
        "reverse shell", "nc -e", "netcat", "metasploit",
        "cobalt strike", "meterpreter", "beacon", "c2 ",
        "privilege escalation", "token impersonation",
        "jndi:", "${jndi:", "log4shell",
        "ransomware", "encrypted your files",
        "-enc ", "encodedcommand", "bypass -enc"
    ]
    for indicator in MALICIOUS_INDICATORS:
        if indicator in log_lower:
            return False
    
    # Event ID Check
    for event_id in BENIGN_WINDOWS_EVENT_IDS:
        # Match "EventID: 1" or "EventID=1" or similar
        pattern = r'\bevent\s*i?d?\s*[:=]\s*' + re.escape(event_id) + r'\b'
        if re.search(pattern, log_lower):
            # Context-Aware Refinement for specific event IDs
            
            # Event 5379: Credential Manager read
            if event_id == "5379":
                if any(k in log_lower for k in ["windowslive", "microsoftaccount", "virtualapp/didlogical"]):
                    _LAST_LOG_RESULT = True
                    return True
                    
            # Event 4624: Successful Logon / 4672: Special Privileges
            if event_id in ["4624", "4672"]:
                if any(k in log_lower for k in ["nt authority", "system", "svchost.exe", "services.exe", "workgroup"]):
                    _LAST_LOG_RESULT = True
                    return True
            
            # Event 4798/4799: Group Enumeration
            if event_id in ["4798", "4799"]:
                if "svchost.exe" in log_lower or "services.exe" in log_lower:
                    _LAST_LOG_RESULT = True
                    return True

            # For Event ID 1 (Process Create), check command line if it looks malicious
            if event_id == "1" or event_id == "4688":
                if any(k in log_lower for k in ["whoami", "net user", "net group", "psexec"]):
                    # If it's a known benign service, it might still be okay, but we'll be cautious
                    if not any(b in log_lower for b in ["nt authority", "system"]):
                        _LAST_LOG_RESULT = False
                        return False
            _LAST_LOG_RESULT = True
            return True
    
    # Pattern Check
    benign_matches = sum(1 for p in BENIGN_WINDOWS_PATTERNS if p in log_lower)
    if benign_matches >= 1:
        # Safeguard: if it contains powershell, check for suspicious flags
        if "powershell" in log_lower:
            if any(k in log_lower for k in ["-enc", "encoded", "bypass", "hidden", "noni"]):
                _LAST_LOG_RESULT = False
                return False
        _LAST_LOG_RESULT = True
        return True
    
    # SYSTEM/NT AUTHORITY context usually implies benign system activity unless malicious indicators present
    if any(k in log_lower for k in ["nt authority\\system", "nt authority\\network service", "workgroup"]):
        # Check if it also has suspicious process activity
        if not any(s in log_lower for s in ["cmd.exe", "powershell.exe", "temp\\"]):
            _LAST_LOG_RESULT = True
            return True
    
    if "microsoft-windows" in log_lower:
        _LAST_LOG_RESULT = True
        return True
    
    if "eventid:" in log_lower or "eventid=" in log_lower:
        if not any(attack in log_lower for attack in ["attack", "malicious", "exploit", "injection"]):
            _LAST_LOG_RESULT = True
            return True
    
    _LAST_LOG_RESULT = False
    return False


def classify_sysmon_event(data: dict) -> Optional[Tuple[str, float]]:
    """
    Specialized classification for Sysmon telemetry using semantic parsing.
    Implements Rule 4 from the specification.
    """
    event_id = str(data.get('event_id') or data.get('EventID') or '')
    command_line = str(data.get('CommandLine') or data.get('command_line') or '').lower()
    image = str(data.get('Image') or data.get('image') or '').lower()
    parent_image = str(data.get('ParentImage') or data.get('parent_image') or '').lower()
    
    # RULE 2: MALICIOUS
    malicious_indicators = [
        "mimikatz", "sekurlsa", "logonpasswords", "golden ticket",
        "reverse shell", "nc -e", "netcat", "beacon", "meterpreter",
        "lsadump", "dcsync", "secretsdump", "pypykatz"
    ]
    if any(ind in command_line for ind in malicious_indicators):
        return "Malicious", 98.0

    # Process Creation (Event ID 1 / 4688)
    if event_id in ["1", "4688"]:
        # Check for encoded commands (Rule 2)
        if any(k in command_line for k in ["-enc", "encodedcommand", "bypass -enc"]):
            return "Malicious", 96.0
            
        # Check for discovery/lateral movement sequences (Recon Behavioral Logic)
        if is_recon_behavior_detected(data):
            return "Suspicious", 85.0

        # Benign Process Check (Rule 2 Normal)
        if "explorer.exe" in parent_image:
            # Normal apps spawned by explorer
            benign_apps = ["notepad.exe", "chrome.exe", "msedge.exe", "calc.exe", "winword.exe", "excel.exe"]
            if any(app in image for app in benign_apps):
                return "Normal", 95.0
        
        if "ping.exe" in image or "nslookup.exe" in image:
            return "Normal", 98.0
            
        if "svchost.exe" in image and not command_line:
            return "Normal", 90.0
            
        # Context-aware svchost/services logic
        if ("svchost.exe" in image or "services.exe" in image) and "nt authority" in str(data).lower():
            return "Normal", 98.0

    # Network Connection (Event ID 3)
    elif event_id == "3":
        dest_port = str(data.get('DestinationPort') or '')
        dest_ip = str(data.get('DestinationIp') or '')
        
        # Rule 2: Normal DNS/HTTP
        if dest_port in ["53", "80", "443"]:
            return "Normal", 98.0
            
        # Suspicious outbound on non-standard ports
        if dest_port in ["4444", "5555", "8888"]:
            return "Suspicious", 85.0

    # Process Access (Event ID 10)
    elif event_id == "10":
        target = str(data.get('TargetImage') or '').lower()
        if "lsass.exe" in target:
            # LSASS access is highly suspicious unless it's a known provider
            source_image = str(data.get('SourceImage') or '').lower()
            if not any(k in source_image for k in ["svchost.exe", "services.exe", "wininit.exe"]):
                return "Suspicious", 90.0

    # Default for Sysmon: if not explicitly malicious/suspicious, it's likely normal telemetry
    if not any(k in command_line for k in ["attack", "exploit", "malware", "unauthorized"]):
        return "Normal", 85.0
        
    return None


def classify_structured_log(data: dict) -> Optional[Tuple[str, float]]:
    """
    Intelligent routing for structured agent telemetry.
    Implements Rule 1 and Rule 2.
    """
    # Identify source type
    source = str(data.get('source', '')).lower()
    channel = str(data.get('channel', '') or data.get('Channel', '')).lower()
    provider = str(data.get('provider', '') or data.get('ProviderName', '')).lower()
    event_type = str(data.get('event_type', '')).lower()
    
    # RULE 1: Agent operational logs -> Always Normal
    agent_keywords = ['heartbeat', 'registration', 'retry', 'buffer', 'flush', 'sender', 'collector']
    if any(k in source for k in agent_keywords) or any(k in event_type for k in agent_keywords):
        return "Normal", 100.0
        
    # RULE 1 & 2: Sysmon Telemetry
    if 'sysmon' in channel or 'sysmon' in provider or 'sysmon' in source:
        return classify_sysmon_event(data)
        
    # RULE 1 & 2: Generic Windows Logs
    if 'microsoft-windows' in channel or 'microsoft-windows' in provider:
        event_id = str(data.get('event_id') or data.get('EventID') or '')
        
        # Behavioral Recon Correlation (Check sequence before early Normal return)
        if event_id in ['4688', '4798', '4799']:
            if is_recon_behavior_detected(data):
                return "Suspicious", 82.0

        if event_id in BENIGN_WINDOWS_EVENT_IDS:
            return "Normal", 95.0
        
        # Context-aware Windows check
        msg = str(data.get('message', '') or data.get('log_text', '')).lower()
        if any(p in msg for p in BENIGN_WINDOWS_PATTERNS):
            return "Normal", 92.0
            
    return None


def signature_based_detection(log_text: str) -> Tuple[Optional[str], Optional[float], Optional[str]]:
    """
    Pre-ML signature-based detection for obvious attack patterns.
    Excludes known-benign Windows events to reduce false positives.
    
    Returns:
        Tuple of (label, confidence, matched_category) or (None, None, None) if no match
    """
    log_lower = log_text.lower()
    
    if is_benign_windows_event(log_text):
        return "Normal", 85.0, "benign_windows_event"
    
    for category, signatures in CRITICAL_ATTACK_SIGNATURES.items():
        for sig in signatures:
            if sig.lower() in log_lower:
                return "Malicious", 95.0, category
    
    HIGH_CONFIDENCE_SUSPICIOUS = [
        "alert", "brute force", "lateral movement", "credential dumping",
        "suspicious execution", "powershell -enc", "suspicious powershell"
    ]
    high_conf_hit = any(p in log_lower for p in HIGH_CONFIDENCE_SUSPICIOUS)

    suspicious_matches = sum(1 for p in SUSPICIOUS_PATTERNS if p.lower() in log_lower)
    if suspicious_matches >= 2:
        return "Suspicious", 85.0, "suspicious_activity"
    elif suspicious_matches == 1:
        conf = 75.0 if high_conf_hit else 60.0
        return "Suspicious", conf, "suspicious_activity"
    
    return None, None, None


def classify_with_tfidf(log_text: str) -> Tuple[Optional[str], Optional[float]]:
    """
    Classify using TF-IDF model (better vocabulary preservation).
    When XGBoost is available, uses RF+XGBoost ensemble averaging.
    
    Args:
        log_text: Raw log message as a string
        
    Returns:
        Tuple of (label, confidence) or (None, None) if failed
    """
    if not TFIDF_READY or tfidf_model is None or tfidf_vectorizer is None:
        return None, None
    
    try:
        features = tfidf_vectorizer.transform([log_text])
        rf_probs = tfidf_model.predict_proba(features)[0]

        if XGBOOST_READY:
            return _xgboost_ensemble_probs(features, rf_probs, tfidf_model.classes_)

        label_index = np.argmax(rf_probs)
        label = tfidf_model.classes_[label_index]
        confidence = float(rf_probs[label_index] * 100)
        
        return label, confidence
    
    except Exception as e:
        print(f"⚠️  TF-IDF classification failed: {e}, falling back to 32-feature model")
        return None, None


def classify_with_features(log_text: str) -> Tuple[Optional[str], Optional[float]]:
    """
    Classify using 32-feature extraction model (original approach).
    
    Args:
        log_text: Raw log message as a string
        
    Returns:
        Tuple of (label, confidence) or (None, None) if failed
    """
    if not MODEL_READY or text_model is None or text_scaler is None:
        return None, None
    
    try:
        cleaned_text = clean_log(log_text)
        features = extract_text_features(cleaned_text)
        features = np.array(features).reshape(1, -1)
        
        scaled = text_scaler.transform(features)
        
        probs = text_model.predict_proba(scaled)[0]
        
        label_index = np.argmax(probs)
        label = text_model.classes_[label_index]
        confidence = float(probs[label_index] * 100)
        
        return label, confidence
    
    except Exception as e:
        print(f"❌ Error during 32-feature classification: {e}")
        return None, None


def classify_with_calibrated_ensemble(log_text: str) -> Tuple[Optional[str], Optional[float]]:
    """
    Classify using calibrated RF+XGBoost ensemble with contextual features.
    Uses dynamic confidence-based weighting and anomaly score integration.
    """
    if not CALIBRATED_READY or not TFIDF_READY or tfidf_vectorizer is None:
        return None, None

    try:
        tfidf_vec = tfidf_vectorizer.transform([log_text])
        ctx = extract_contextual_features(log_text).reshape(1, -1)
        ctx_scaled = context_scaler.transform(ctx)
        combined = hstack([tfidf_vec, csr_matrix(ctx_scaled)])

        canonical = ['Malicious', 'Normal', 'Suspicious']

        rf_proba = rf_calibrated.predict_proba(combined)[0]
        rf_classes_list = list(rf_calibrated.classes_)
        rf_map = {str(rf_classes_list[i]): rf_proba[i] for i in range(len(rf_classes_list))}

        xgb_proba = xgb_calibrated.predict_proba(combined)[0]
        xgb_classes_list = list(xgb_calibrated_le.classes_)
        xgb_map = {str(xgb_classes_list[i]): xgb_proba[i] for i in range(len(xgb_classes_list))}

        rf_conf = max(rf_proba)
        xgb_conf = max(xgb_proba)

        rf_best = max(rf_map, key=rf_map.get)
        if rf_best in ('Malicious', 'Suspicious') and rf_conf > 0.8:
            return rf_best, float(rf_conf * 100)

        total = rf_conf + xgb_conf
        if total == 0:
            total = 1.0
        rf_w = np.clip(rf_conf / total, 0.3, 0.8)
        xgb_w = 1.0 - rf_w

        ensemble = {}
        for lbl in canonical:
            ensemble[lbl] = rf_w * rf_map.get(lbl, 0.0) + xgb_w * xgb_map.get(lbl, 0.0)

        if ANOMALY_READY and anomaly_detector is not None:
            anomaly = detect_anomaly(log_text)
            if anomaly['available']:
                anom_boost = 0.0
                if anomaly['is_anomaly']:
                    anom_boost = min(anomaly['confidence'] / 100.0, 0.3)
                for lbl in canonical:
                    if lbl == 'Normal':
                        ensemble[lbl] = ensemble[lbl] * (1.0 - anom_boost * 0.2)
                    else:
                        ensemble[lbl] = ensemble[lbl] * (1.0 + anom_boost * 0.2)
                total_e = sum(ensemble.values())
                if total_e > 0:
                    ensemble = {k: v / total_e for k, v in ensemble.items()}

        best_label = max(ensemble, key=ensemble.get)
        best_conf = float(ensemble[best_label] * 100)
        return best_label, best_conf

    except Exception as e:
        print(f"⚠️  Calibrated ensemble failed: {e}")
        return None, None


def _xgboost_ensemble_probs(text_vector, rf_probs, rf_classes):
    """
    Combine Random Forest probabilities with XGBoost probabilities.
    Uses weighted average: 0.7 RF + 0.3 XGBoost (RF-dominant ensemble).

    Confidence safeguard: If RF predicts Malicious or Suspicious with
    probability > 0.8, the RF prediction is used directly — XGBoost
    cannot downgrade a high-confidence threat detection to Normal.

    Returns combined (label, confidence) or original RF result if XGBoost unavailable.
    """
    if not XGBOOST_READY or xgboost_model is None or xgboost_label_encoder is None:
        label_index = np.argmax(rf_probs)
        return str(rf_classes[label_index]), float(rf_probs[label_index] * 100)

    try:
        rf_prob_map = {str(rf_classes[i]): rf_probs[i] for i in range(len(rf_classes))}
        rf_label_index = np.argmax(rf_probs)
        rf_label = str(rf_classes[rf_label_index])
        rf_conf = float(rf_probs[rf_label_index])

        if rf_label in ('Malicious', 'Suspicious') and rf_conf > 0.8:
            return rf_label, float(rf_conf * 100)

        xgb_probs_raw = xgboost_model.predict_proba(text_vector)[0]

        canonical_labels = ['Malicious', 'Normal', 'Suspicious']
        xgb_label_map = {str(xgboost_label_encoder.classes_[i]): xgb_probs_raw[i]
                         for i in range(len(xgboost_label_encoder.classes_))}

        ensemble_probs = {}
        for lbl in canonical_labels:
            rf_p = rf_prob_map.get(lbl, 0.0)
            xgb_p = xgb_label_map.get(lbl, 0.0)
            ensemble_probs[lbl] = 0.7 * rf_p + 0.3 * xgb_p

        best_label = max(ensemble_probs, key=ensemble_probs.get)
        best_conf = float(ensemble_probs[best_label] * 100)
        return best_label, best_conf

    except Exception as e:
        print(f"⚠️  XGBoost ensemble failed, using RF only: {e}")
        label_index = np.argmax(rf_probs)
        return str(rf_classes[label_index]), float(rf_probs[label_index] * 100)


def classify_with_enhanced(log_text: str) -> Tuple[Optional[str], Optional[float]]:
    """
    Classify using enhanced SMOTE-balanced TF-IDF model (RF only).
    XGBoost ensemble is NOT used here because enhanced_vectorizer differs
    from tfidf_vectorizer that XGBoost was trained on.
    
    Args:
        log_text: Raw log message as a string
        
    Returns:
        Tuple of (label, confidence) or (None, None) if failed
    """
    if not ENHANCED_READY or enhanced_model is None or enhanced_vectorizer is None:
        return None, None
    
    try:
        cleaned_text = clean_log(log_text)
        text_vector = enhanced_vectorizer.transform([cleaned_text])
        
        probs = enhanced_model.predict_proba(text_vector)[0]

        label_index = np.argmax(probs)
        label = enhanced_model.classes_[label_index]
        confidence = float(probs[label_index] * 100)
        
        return label, confidence
    
    except Exception as e:
        print(f"❌ Error during enhanced classification: {e}")
        return None, None


def detect_anomaly(log_text: str) -> Dict[str, Any]:
    """
    Detect if a log entry is anomalous (potential zero-day attack).
    
    Uses Isolation Forest trained on normal logs to detect novel/unseen
    attack patterns that don't match known signatures or ML training data.
    
    Args:
        log_text: Raw log message as a string
        
    Returns:
        Dictionary with:
            - is_anomaly: True if the log is flagged as anomalous
            - anomaly_score: Raw score from Isolation Forest (negative = more anomalous)
            - confidence: Normalized confidence (0-100)
            - available: Whether anomaly detection is available
    """
    if not ANOMALY_READY or anomaly_detector is None:
        return {
            'is_anomaly': False,
            'anomaly_score': 0.0,
            'confidence': 0.0,
            'available': False
        }
    
    try:
        cleaned_text = clean_log(log_text)
        vectorizer = enhanced_vectorizer if ENHANCED_READY else tfidf_vectorizer
        
        if vectorizer is None:
            return {'is_anomaly': False, 'anomaly_score': 0.0, 'confidence': 0.0, 'available': False}
        
        text_vector = vectorizer.transform([cleaned_text])
        
        prediction = anomaly_detector.predict(text_vector)[0]
        score = anomaly_detector.decision_function(text_vector)[0]
        
        is_anomaly = (prediction == -1)
        
        confidence = min(100, max(0, (0.1 - score) * 200))
        
        return {
            'is_anomaly': is_anomaly,
            'anomaly_score': float(score),
            'confidence': float(confidence),
            'available': True
        }
    
    except Exception as e:
        print(f"❌ Error during anomaly detection: {e}")
        return {'is_anomaly': False, 'anomaly_score': 0.0, 'confidence': 0.0, 'available': False}


def classify_text_log(log_text: str, use_anomaly_boost: bool = True) -> Tuple[Optional[str], Optional[float]]:
    """
    Classify a text log using hybrid signature + ML + anomaly approach.
    Implements intelligent routing for structured agent telemetry.
    """
    # 1. Structured Data Routing (Rule 1, 2, 4)
    structured_data = None
    if isinstance(log_text, dict):
        structured_data = log_text
    elif log_text.strip().startswith('{') and log_text.strip().endswith('}'):
        try:
            structured_data = json.loads(log_text)
        except:
            pass
            
    if structured_data:
        structured_res = classify_structured_log(structured_data)
        if structured_res:
            return structured_res
        # If structured check returns None, we continue to ML but use stringified text
        log_text = str(structured_data)

    # 2. Signature-based detection (high confidence)
    sig_label, sig_conf, sig_category = signature_based_detection(log_text)
    if sig_label is not None:
        return sig_label, sig_conf
    
    label, confidence = None, None

    if CALIBRATED_READY:
        label, confidence = classify_with_calibrated_ensemble(log_text)

    if label is None and ENHANCED_READY:
        label, confidence = classify_with_enhanced(log_text)
    
    if label is None and TFIDF_READY:
        label, confidence = classify_with_tfidf(log_text)
    
    if label is None and MODEL_READY:
        label, confidence = classify_with_features(log_text)
    
    if label is None:
        return None, None
    
    # 5. Anomaly boost: If anomaly detector flags entry, boost threat level
    if use_anomaly_boost and ANOMALY_READY and label == 'Normal':
        anomaly_result = detect_anomaly(log_text)
        if anomaly_result['is_anomaly'] and anomaly_result['anomaly_score'] < -0.05:
            label = 'Suspicious'
            confidence = max(confidence, 60.0)
    
    # 6. Apply context-aware corrections (domain/URL check)
    label, confidence = apply_context_correction(log_text, label, confidence)
    
    # 7. Final Safety Threshold (Rule 3 & 5)
    # If ML says Malicious but confidence is low, and it's not a known signature, downgrade
    if label == "Malicious" and confidence < 75.0:
        # Re-verify if any high-confidence signatures matched (they should have returned earlier, but just in case)
        is_high_conf_threat = False
        for cat in CRITICAL_ATTACK_SIGNATURES.values():
            if any(sig.lower() in log_text.lower() for sig in cat):
                is_high_conf_threat = True
                break
        
        if not is_high_conf_threat:
            # Downgrade to Suspicious or Normal based on confidence
            if confidence > 50.0:
                label = "Suspicious"
            else:
                label = "Normal"
                
    # 8. Rule 5: Fallback to Normal if it lacks threat indicators and confidence is shaky
    if label != "Normal" and confidence < 60.0:
        if not any(k in log_text.lower() for k in ["attack", "malicious", "exploit", "mimikatz", "bypass", "encoded"]):
            label = "Normal"

    return label, confidence


def classify_text_log_extended(log_text: str) -> Dict[str, Any]:
    """
    Extended classification with anomaly detection and temporal analysis.
    """
    result = {
        'label': None,
        'confidence': None,
        'model_used': None,
        'anomaly': None,
        'signature': None,
        'enhanced_available': ENHANCED_READY,
        'anomaly_available': ANOMALY_READY,
        'xgboost_available': XGBOOST_READY,
        'calibrated_available': CALIBRATED_READY
    }
    
    # 1. Structured Data Routing
    structured_data = None
    if isinstance(log_text, dict):
        structured_data = log_text
    elif isinstance(log_text, str) and log_text.strip().startswith('{') and log_text.strip().endswith('}'):
        try:
            structured_data = json.loads(log_text)
        except: pass
            
    if structured_data:
        structured_res = classify_structured_log(structured_data)
        if structured_res:
            result['label'], result['confidence'] = structured_res
            result['model_used'] = 'structured_router'
            return result
        log_text = str(structured_data)

    # 2. Signature-based detection
    sig_label, sig_conf, sig_category = signature_based_detection(log_text)
    if sig_label is not None:
        result['label'] = sig_label
        result['confidence'] = sig_conf
        result['model_used'] = 'signature'
        result['signature'] = {'category': sig_category, 'confidence': sig_conf}
    else:
        # 3. ML Detection
        if CALIBRATED_READY:
            label, confidence = classify_with_calibrated_ensemble(log_text)
            if label is not None:
                result['label'] = label
                result['confidence'] = confidence
                result['model_used'] = 'calibrated_ensemble'

        if result['label'] is None and ENHANCED_READY:
            label, confidence = classify_with_enhanced(log_text)
            if label is not None:
                result['label'] = label
                result['confidence'] = confidence
                result['model_used'] = 'enhanced_tfidf'
        
        if result['label'] is None and TFIDF_READY:
            label, confidence = classify_with_tfidf(log_text)
            if label is not None:
                result['label'] = label
                result['confidence'] = confidence
                result['model_used'] = 'tfidf+xgboost' if XGBOOST_READY else 'tfidf'
        
        if result['label'] is None and MODEL_READY:
            label, confidence = classify_with_features(log_text)
            if label is not None:
                result['label'] = label
                result['confidence'] = confidence
                result['model_used'] = '32_feature'
    
    # 4. Anomaly Detection
    if ANOMALY_READY:
        result['anomaly'] = detect_anomaly(log_text)
    
    # 5. Safety & Context Checks
    if result['label'] is not None and result['model_used'] != 'signature':
        label, confidence = apply_context_correction(log_text, result['label'], result['confidence'])
        
        # Apply Safety Thresholds (Rule 5)
        if label == "Malicious" and confidence < 75.0:
            is_high_conf_threat = False
            for cat in CRITICAL_ATTACK_SIGNATURES.values():
                if any(sig.lower() in log_text.lower() for sig in cat):
                    is_high_conf_threat = True
                    break
            if not is_high_conf_threat:
                label = "Suspicious" if confidence > 50.0 else "Normal"
                
        if label != "Normal" and confidence < 60.0:
            if not any(k in log_text.lower() for k in ["attack", "malicious", "exploit", "mimikatz", "bypass", "encoded"]):
                label = "Normal"
                
        result['label'] = label
        result['confidence'] = confidence
        
    return result
