#!/usr/bin/env python3
"""
Network Flow Classifier Module
Classifies network traffic based on flow features (packet counts, bytes, timing, etc.)
Works alongside the text-based log classifier for comprehensive threat detection.
"""

import pickle
import os
import numpy as np
import warnings
warnings.filterwarnings('ignore')

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
MODELS_DIR = os.path.join(PROJECT_DIR, 'models')

FLOW_MODEL = None
FLOW_SCALER = None
FLOW_FEATURES = None
FLOW_READY = False

LABEL_MAPPING = {}
THREAT_LEVEL = {}

ATTACK_DESCRIPTIONS = {
    'Benign': 'Normal network traffic',
    'Normal': 'Normal network traffic',
    'Bot': 'Botnet command and control traffic',
    'Brute Force': 'Credential brute force attack',
    'DDoS': 'Distributed Denial of Service attack',
    'DoS': 'Denial of Service attack',
    'Infiltration': 'Network infiltration attempt',
    'PortScan': 'Port scanning reconnaissance',
    'Web Attack': 'Web application attack (XSS, SQLi, etc.)',
    'Heartbleed': 'OpenSSL Heartbleed exploit',
    'SSH-Patator': 'SSH password brute force attack',
    'Fuzzers': 'Fuzzing attack to find vulnerabilities',
    'Exploits': 'Exploitation of known vulnerabilities',
    'Shellcode': 'Shellcode injection attack',
    'Worms': 'Self-propagating worm activity',
    'Backdoor': 'Backdoor/trojan communication',
    'Analysis': 'Suspicious analysis/reconnaissance activity',
    'Reconnaissance': 'Network reconnaissance activity',
    'Generic': 'Generic malicious activity',
    'XSS': 'Cross-site scripting attack',
    'SQL Injection': 'SQL injection attack'
}

def load_flow_model():
    """Load the trained network flow classifier (prefers enhanced model if available)"""
    global FLOW_MODEL, FLOW_SCALER, FLOW_FEATURES, FLOW_READY, LABEL_MAPPING, THREAT_LEVEL
    
    enhanced_model_path = os.path.join(MODELS_DIR, 'flow_classifier_enhanced.pkl')
    enhanced_scaler_path = os.path.join(MODELS_DIR, 'flow_scaler_enhanced.pkl')
    enhanced_features_path = os.path.join(MODELS_DIR, 'flow_features_enhanced.pkl')
    enhanced_labels_path = os.path.join(MODELS_DIR, 'flow_labels_enhanced.pkl')
    
    legacy_model_path = os.path.join(MODELS_DIR, 'flow_classifier.pkl')
    legacy_scaler_path = os.path.join(MODELS_DIR, 'flow_scaler.pkl')
    legacy_features_path = os.path.join(MODELS_DIR, 'flow_features.pkl')
    legacy_labels_path = os.path.join(MODELS_DIR, 'flow_labels.pkl')
    
    use_enhanced = all(os.path.exists(p) for p in [enhanced_model_path, enhanced_scaler_path, enhanced_features_path])
    use_legacy = all(os.path.exists(p) for p in [legacy_model_path, legacy_scaler_path, legacy_features_path])
    
    if use_enhanced:
        model_path, scaler_path, features_path, labels_path = (
            enhanced_model_path, enhanced_scaler_path, enhanced_features_path, enhanced_labels_path
        )
        model_type = "ENHANCED"
    elif use_legacy:
        model_path, scaler_path, features_path, labels_path = (
            legacy_model_path, legacy_scaler_path, legacy_features_path, legacy_labels_path
        )
        model_type = "LEGACY"
    else:
        print("⚠️ Network flow classifier not found (run train_flow_classifier.py)")
        return False
    
    try:
        with open(model_path, 'rb') as f:
            FLOW_MODEL = pickle.load(f)
        with open(scaler_path, 'rb') as f:
            FLOW_SCALER = pickle.load(f)
        with open(features_path, 'rb') as f:
            FLOW_FEATURES = pickle.load(f)
        
        if os.path.exists(labels_path):
            with open(labels_path, 'rb') as f:
                label_data = pickle.load(f)
                if 'attack_types' in label_data:
                    LABEL_MAPPING = {i: t for i, t in enumerate(label_data['attack_types'])}
                    THREAT_LEVEL = label_data.get('threat_mapping', {})
                else:
                    LABEL_MAPPING = label_data.get('label_mapping', {})
                    THREAT_LEVEL = label_data.get('threat_level', {})
        else:
            LABEL_MAPPING = {
                0: 'Benign', 1: 'Bot', 2: 'Brute Force', 3: 'DDoS',
                4: 'DoS', 5: 'Infiltration', 6: 'PortScan', 7: 'Web Attack',
                8: 'Heartbleed', 9: 'SSH-Patator'
            }
            THREAT_LEVEL = {
                'Benign': 'Normal', 'Bot': 'Malicious', 'Brute Force': 'Malicious',
                'DDoS': 'Malicious', 'DoS': 'Malicious', 'Infiltration': 'Malicious',
                'PortScan': 'Suspicious', 'Web Attack': 'Malicious',
                'Heartbleed': 'Malicious', 'SSH-Patator': 'Malicious'
            }
        
        FLOW_READY = True
        attack_count = len(FLOW_MODEL.classes_)
        print(f"[OK] Network flow classifier loaded ({model_type})")
        print(f"   Features: {len(FLOW_FEATURES)}")
        print(f"   Attack types: {attack_count}")
        
        if use_enhanced and attack_count < 11:
            print(f"[WARNING] Enhanced model has only {attack_count} classes (expected >10)")
        
        return True
    except Exception as e:
        print(f"❌ Failed to load flow classifier: {e}")
        return False

load_flow_model()

def classify_network_flow(flow_features: dict) -> tuple:
    """
    Classify a network flow based on its features.
    
    Args:
        flow_features: Dictionary with network flow features
                      (Flow Duration, Total Fwd Packet, etc.)
    
    Returns:
        tuple: (attack_type, threat_level, confidence, description)
    """
    if not FLOW_READY:
        return ('Unknown', 'Unknown', 0.0, 'Flow classifier not available')
    
    try:
        feature_vector = []
        for feat in FLOW_FEATURES:
            value = flow_features.get(feat, 0)
            if value is None or (isinstance(value, float) and np.isnan(value)):
                value = 0
            if value == np.inf or value == -np.inf:
                value = 0
            feature_vector.append(float(value))
        
        X = np.array([feature_vector])
        X_scaled = FLOW_SCALER.transform(X)
        
        attack_type = FLOW_MODEL.predict(X_scaled)[0]
        
        probabilities = FLOW_MODEL.predict_proba(X_scaled)[0]
        class_idx = list(FLOW_MODEL.classes_).index(attack_type)
        confidence = probabilities[class_idx] * 100
        
        threat_level = THREAT_LEVEL.get(attack_type, 'Unknown')
        description = ATTACK_DESCRIPTIONS.get(attack_type, 'Unknown attack type')
        
        return (attack_type, threat_level, confidence, description)
        
    except Exception as e:
        print(f"Flow classification error: {e}")
        return ('Error', 'Unknown', 0.0, str(e))

def classify_flow_batch(flows: list) -> list:
    """
    Classify multiple network flows at once.
    
    Args:
        flows: List of dictionaries with network flow features
    
    Returns:
        list: List of (attack_type, threat_level, confidence, description) tuples
    """
    if not FLOW_READY:
        return [('Unknown', 'Unknown', 0.0, 'Flow classifier not available')] * len(flows)
    
    try:
        X = []
        for flow in flows:
            feature_vector = []
            for feat in FLOW_FEATURES:
                value = flow.get(feat, 0)
                if value is None or (isinstance(value, float) and np.isnan(value)):
                    value = 0
                if value == np.inf or value == -np.inf:
                    value = 0
                feature_vector.append(float(value))
            X.append(feature_vector)
        
        X = np.array(X)
        X_scaled = FLOW_SCALER.transform(X)
        
        attack_types = FLOW_MODEL.predict(X_scaled)
        probabilities = FLOW_MODEL.predict_proba(X_scaled)
        
        results = []
        for i, attack_type in enumerate(attack_types):
            class_idx = list(FLOW_MODEL.classes_).index(attack_type)
            confidence = probabilities[i][class_idx] * 100
            threat_level = THREAT_LEVEL.get(attack_type, 'Unknown')
            description = ATTACK_DESCRIPTIONS.get(attack_type, 'Unknown attack type')
            results.append((attack_type, threat_level, confidence, description))
        
        return results
        
    except Exception as e:
        print(f"Batch flow classification error: {e}")
        return [('Error', 'Unknown', 0.0, str(e))] * len(flows)

def get_flow_classifier_info() -> dict:
    """Get information about the flow classifier"""
    return {
        'ready': FLOW_READY,
        'features': len(FLOW_FEATURES) if FLOW_FEATURES else 0,
        'attack_types': list(FLOW_MODEL.classes_) if FLOW_MODEL else [],
        'threat_levels': THREAT_LEVEL,
        'descriptions': ATTACK_DESCRIPTIONS
    }

if __name__ == '__main__':
    print("\n=== Network Flow Classifier Test ===\n")
    
    test_flow = {
        'Flow Duration': 214392,
        'Total Fwd Packet': 9,
        'Total Bwd packets': 21,
        'Total Length of Fwd Packet': 388.0,
        'Total Length of Bwd Packet': 24564.0,
        'Fwd Packet Length Max': 194.0,
        'Fwd Packet Length Min': 0.0,
        'Fwd Packet Length Mean': 43.11,
        'Bwd Packet Length Max': 1460.0,
        'Bwd Packet Length Mean': 1169.71,
        'Flow Bytes/s': 116384.94,
        'Flow Packets/s': 139.93,
    }
    
    for feat in FLOW_FEATURES:
        if feat not in test_flow:
            test_flow[feat] = 0.0
    
    attack_type, threat_level, confidence, description = classify_network_flow(test_flow)
    
    print(f"Attack Type:   {attack_type}")
    print(f"Threat Level:  {threat_level}")
    print(f"Confidence:    {confidence:.2f}%")
    print(f"Description:   {description}")
    
    print("\nClassifier Info:")
    info = get_flow_classifier_info()
    print(f"  Ready: {info['ready']}")
    print(f"  Features: {info['features']}")
    print(f"  Attack Types: {info['attack_types']}")
