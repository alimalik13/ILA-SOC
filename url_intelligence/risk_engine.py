from typing import Dict, Any, Tuple
from url_intelligence.feature_extractor import extract_features

# ── Scoring weights (tuned for accuracy) ─────────────────────
WEIGHTS = {
    'is_ip_address':              35,
    'has_at_symbol':              25,
    'has_double_slash_redirect':  20,
    'has_punycode':               30,
    'is_suspicious_tld':          20,
    'has_phishing_path':          20,
    'no_https':                   15,
    'long_url':                   10,
    'excessive_subdomains':       15,
    'high_entropy':               15,
    'many_digits':                10,
    'brand_with_numbers':         15,
    'excessive_hyphens':          15,
    'has_credential_form':        45,
    'suspicious_form':            90,
    'has_content_phishing':       35,
    'is_test_phishing':          100,
    'brand_impersonation':        40,
}

def compute_risk_score(url: str) -> Dict[str, Any]:
    features = extract_features(url)
    score = 0.0
    reasons = []

    # Immediate safe return ONLY IF no malicious content signals exist
    if features.get('is_legitimate_brand'):
        has_critical_threat = (
            features.get('has_malware_keywords') or
            features.get('has_fake_alert') or
            features.get('is_test_phishing')
        )
        if not has_critical_threat:
            return {
                'risk_score': 0.0,
                'verdict': 'Safe',
                'reason': 'Verified legitimate domain',
                'nudge_level': 'none',
                'features': features
            }
        else:
            reasons.append('Verified domain but compromised content detected')

    # ── Structural signals ────────────────────────────────────
    if features['is_ip_address']:
        score += WEIGHTS['is_ip_address']
        reasons.append('IP address used instead of domain')

    if features['has_at_symbol']:
        score += WEIGHTS['has_at_symbol']
        reasons.append('Contains @ symbol (redirect trick)')

    if features['has_double_slash_redirect']:
        score += WEIGHTS['has_double_slash_redirect']
        reasons.append('Double-slash redirect detected')

    if features['has_punycode']:
        score += WEIGHTS['has_punycode']
        reasons.append('Punycode/IDN homograph attack')

    if features['is_suspicious_tld']:
        score += WEIGHTS['is_suspicious_tld']
        reasons.append(f"Suspicious TLD: {features['tld']}")

    if features['has_brand_keyword'] and not features['is_legitimate_brand']:
        brands = ', '.join(features['brand_impersonation'][:3])
        score += WEIGHTS['brand_impersonation']
        reasons.append(f'Brand impersonation detected: {brands}')

    if features['has_phishing_path']:
        kws = ', '.join(features['phishing_path_keywords'][:3])
        score += WEIGHTS['has_phishing_path']
        reasons.append(f'Phishing path keywords: {kws}')

    if not features['is_https']:
        score += WEIGHTS['no_https']
        reasons.append('No HTTPS encryption')

    if features['url_length'] > 75:
        score += WEIGHTS['long_url']
        reasons.append('Abnormally long URL')

    if features['num_subdomains'] >= 3:
        score += WEIGHTS['excessive_subdomains']
        reasons.append(f"Excessive subdomains ({features['num_subdomains']})")

    if features['domain_entropy'] > 4.0:
        score += WEIGHTS['high_entropy']
        reasons.append(f"High domain entropy — randomised domain name")

    if features['num_digits_domain'] > 4:
        score += WEIGHTS['many_digits']
        reasons.append('Many digits in domain')

    if features['domain_has_numbers'] and features['has_brand_keyword']:
        score += WEIGHTS['brand_with_numbers']
        reasons.append('Brand keyword combined with numbers in domain')

    if features['num_hyphens'] >= 3:
        score += WEIGHTS['excessive_hyphens']
        reasons.append('Excessive hyphens in domain')

    # ── Content signals (higher weight) ──────────────────────
    if features.get('suspicious_form', 0):
        score += WEIGHTS['suspicious_form']
        reasons.append('Credential harvesting form on unverified domain')

    elif features.get('has_credential_form', 0):
        score += WEIGHTS['has_credential_form']
        reasons.append('Page contains login/password form')

    if features.get('has_content_phishing_keywords', 0):
        score += WEIGHTS['has_content_phishing']
        reasons.append('Phishing keywords found in page content')

    if features.get('is_test_phishing', 0):
        score += WEIGHTS['is_test_phishing']
        reasons.append('Known phishing pattern detected')

    if features.get('has_malware_keywords', 0):
        score += 50
        reasons.append('Malware-related content detected on page')

    score = min(score, 100.0)

    # ── Verdict thresholds (tightened) ───────────────────────
    verdict, nudge_level = _score_to_verdict(score)
    reason_text = '; '.join(reasons) if reasons else \
        'No suspicious indicators detected'

    return {
        'risk_score':  round(score, 2),
        'verdict':     verdict,
        'reason':      reason_text,
        'nudge_level': nudge_level,
        'features':    features
    }

def _score_to_verdict(score: float) -> Tuple[str, str]:
    if score >= 60:
        return 'Malicious', 'block'
    elif score >= 30:
        return 'Suspicious', 'warn'
    else:
        return 'Safe', 'none'
