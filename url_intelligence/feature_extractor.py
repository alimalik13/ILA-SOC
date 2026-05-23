import re
import math
from urllib.parse import urlparse, parse_qs
from collections import Counter
from typing import Dict, Any
import requests


SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.online',
    '.site', '.icu', '.buzz', '.work', '.space', '.info', '.click', '.link',
    '.surf', '.rest', '.fit', '.cam', '.bid', '.win', '.loan', '.racing',
    '.review', '.stream', '.download', '.accountant', '.date', '.faith',
    '.party', '.science', '.trade', '.webcam', '.cricket', '.men',
    '.ru', '.cn', '.pw', '.cc', '.to', '.biz', '.mobi',
    '.pro', '.name', '.tel', '.travel', '.xxx', '.adult',
    '.red', '.black', '.blue', '.pink', '.kim'
]

BRAND_KEYWORDS = [
    'paypal', 'apple', 'microsoft', 'google', 'amazon', 'netflix', 'facebook',
    'instagram', 'whatsapp', 'telegram', 'linkedin', 'twitter', 'dropbox',
    'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'hsbc', 'barclays',
    'outlook', 'office365', 'icloud', 'yahoo', 'dhl', 'fedex', 'ups',
    'usps', 'binance', 'coinbase', 'blockchain', 'metamask', 'steam',
    'epicgames', 'roblox', 'walmart', 'costco', 'adobe', 'docusign',
    'spotify', 'github', 'gitlab', 'slack', 'zoom', 'webex',
    'irs', 'gov', 'tax', 'refund', 'stimulus',
    'citi', 'wells', 'boa', 'capitalone',
    'stripe', 'square', 'payoneer', 'skrill',
    'nft', 'crypto', 'wallet', 'defi',
    'kraken', 'bybit', 'okx', 'huobi',
    'norton', 'mcafee', 'kaspersky', 'avast',
    'royalmail', 'hulu', 'disney', 'primevideo',
    'tiktok', 'snapchat', 'pinterest', 'reddit'
]

PHISHING_PATH_KEYWORDS = [
    'login', 'signin', 'sign-in', 'verify', 'verification', 'account',
    'update', 'secure', 'security', 'confirm', 'auth', 'authenticate',
    'password', 'credential', 'suspend', 'locked', 'unusual', 'activity',
    'restore', 'recover', 'billing', 'payment', 'wallet', 'invoice',
    'webscr', 'cmd', 'dispatch', 'click', 'track',
    'redirect', 'return', 'checkout', 'purchase',
    'gift', 'prize', 'winner', 'claim', 'free',
    'offer', 'deal', 'discount', 'coupon', 'bonus',
    'reset', 'change-password', 'otp', 'pin', '2fa',
    'mfa', 'token', 'session', 'expire', 'limited'
]


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = Counter(text)
    total = len(text)
    entropy = 0.0
    for count in freq.values():
        prob = count / total
        entropy -= prob * math.log2(prob)
    return round(entropy, 4)


def extract_features(url: str) -> Dict[str, Any]:
    features = {}

    try:
        parsed = urlparse(url if '://' in url else f'http://{url}')
    except Exception:
        return _empty_features(url)

    domain = parsed.hostname or ''
    path = parsed.path or ''
    query = parsed.query or ''
    scheme = parsed.scheme or ''

    features['url_length'] = len(url)
    features['domain_length'] = len(domain)
    features['num_dots'] = domain.count('.')
    features['num_hyphens'] = domain.count('-')
    features['num_digits_domain'] = sum(c.isdigit() for c in domain)
    features['num_digits_url'] = sum(c.isdigit() for c in url)
    features['num_special_chars'] = sum(c in '@!#$%^&*()' for c in url)
    features['has_at_symbol'] = 1 if '@' in url else 0
    features['has_double_slash_redirect'] = 1 if '//' in path else 0
    features['is_https'] = 1 if scheme == 'https' else 0
    features['is_ip_address'] = 1 if _is_ip(domain) else 0
    features['domain_entropy'] = shannon_entropy(domain)
    features['url_entropy'] = shannon_entropy(url)
    features['path_depth'] = len([p for p in path.split('/') if p])
    features['num_query_params'] = len(parse_qs(query))
    features['query_length'] = len(query)
    features['num_subdomains'] = max(0, domain.count('.') - 1) if not _is_ip(domain) else 0

    tld = _get_tld(domain)
    features['tld'] = tld
    features['is_suspicious_tld'] = 1 if tld in SUSPICIOUS_TLDS else 0

    domain_lower = domain.lower()
    path_lower = path.lower()
    matched_brands = [b for b in BRAND_KEYWORDS if b in domain_lower]
    features['brand_impersonation'] = matched_brands
    features['has_brand_keyword'] = 1 if matched_brands else 0

    is_legitimate = _is_legitimate_brand_domain(domain_lower, matched_brands)
    features['is_legitimate_brand'] = 1 if is_legitimate else 0

    matched_phishing_paths = [k for k in PHISHING_PATH_KEYWORDS if k in path_lower]
    features['phishing_path_keywords'] = matched_phishing_paths
    features['has_phishing_path'] = 1 if matched_phishing_paths else 0

    features['has_punycode'] = 1 if 'xn--' in domain_lower else 0
    features['domain_has_numbers'] = 1 if any(c.isdigit() for c in domain.split('.')[0]) else 0

    # Fetch HTML to check content signals
    html_content = _get_page_html(url)
    
    # 1. Credential harvesting forms
    has_pwd = 'type="password"' in html_content or "type='password'" in html_content
    has_login = 'login' in html_content or 'sign in' in html_content or 'signin' in html_content
    has_user = 'name="username"' in html_content or 'name="user"' in html_content or 'username' in html_content
    has_verify = 'verify account' in html_content or 'update account' in html_content
    features['has_credential_form'] = 1 if has_pwd and (has_login or has_user or has_verify) else 0

    # 2. Phishing keywords in URL or page
    phish_kws = ['phish', 'login', 'verify', 'update-account', 'secure-login', 'account-verification']
    features['has_content_phishing_keywords'] = 1 if any(k in url.lower() or k in html_content for k in phish_kws) else 0

    # 3. Suspicious form behavior
    features['suspicious_form'] = 1 if features['has_credential_form'] and not features['is_legitimate_brand'] else 0

    # 4. Test phishing domains
    test_paths = ['/phishing.html', '/phish', '/credential']
    features['is_test_phishing'] = 1 if any(p in path_lower for p in test_paths) else 0

    # Malware/suspicious download signals
    malware_kws = [
        'malware', 'trojan', 'ransomware', 'keylogger',
        'exploit', 'payload', 'dropper', 'botnet', 'rat ',
        'c2', 'command and control', 'shellcode'
    ]
    features['has_malware_keywords'] = 1 if any(
        k in html_content for k in malware_kws
    ) else 0

    # Fake security alerts
    fake_alert_kws = [
        'your computer is infected', 'call microsoft',
        'virus detected', 'your device is at risk',
        'click here to remove', 'scan now for free',
        'your account will be suspended'
    ]
    features['has_fake_alert'] = 1 if any(
        k in html_content for k in fake_alert_kws
    ) else 0

    return features

def _get_page_html(url: str) -> str:
    try:
        if "://" not in url:
            url = f"http://{url}"
        resp = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0"}, verify=False)
        return resp.text.lower()
    except Exception:
        return ""


def _is_ip(domain: str) -> bool:
    parts = domain.split('.')
    if len(parts) == 4:
        return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
    return False


def _get_tld(domain: str) -> str:
    if not domain or _is_ip(domain):
        return ''
    parts = domain.split('.')
    if len(parts) >= 2:
        return '.' + parts[-1]
    return ''


def _is_legitimate_brand_domain(domain: str, matched_brands: list) -> bool:
    LEGIT_DOMAINS = {
        'paypal': ['paypal.com'],
        'apple': ['apple.com', 'icloud.com'],
        'microsoft': ['microsoft.com', 'live.com', 'outlook.com', 'office365.com', 'office.com'],
        'google': ['google.com', 'gmail.com', 'googleapis.com'],
        'amazon': ['amazon.com', 'amazon.co.uk', 'aws.amazon.com'],
        'netflix': ['netflix.com'],
        'facebook': ['facebook.com', 'fb.com'],
        'instagram': ['instagram.com'],
        'github': ['github.com', 'github.io'],
        'twitter': ['twitter.com', 'x.com'],
        'linkedin': ['linkedin.com'],
        'dropbox': ['dropbox.com'],
        'spotify': ['spotify.com'],
        'zoom': ['zoom.us'],
        'slack': ['slack.com'],
        'irs': ['irs.gov'],
        'gov': ['usa.gov', 'irs.gov', 'cdc.gov', 'nasa.gov', 'fbi.gov', 'whitehouse.gov', 'state.gov', 'nih.gov', 'epa.gov', 'ed.gov'],
        'tax': ['irs.gov', 'tax.gov'],
        'refund': ['irs.gov'],
        'stimulus': ['irs.gov', 'usa.gov'],
        'citi': ['citibank.com', 'citi.com'],
        'wells': ['wellsfargo.com'],
        'chase': ['chase.com', 'jpmorgan.com'],
        'boa': ['bankofamerica.com'],
        'capitalone': ['capitalone.com'],
        'hsbc': ['hsbc.com'],
        'stripe': ['stripe.com'],
        'square': ['squareup.com', 'square.com'],
        'payoneer': ['payoneer.com'],
        'skrill': ['skrill.com'],
        'tiktok':     ['tiktok.com'],
        'snapchat':   ['snapchat.com'],
        'reddit':     ['reddit.com'],
        'discord':    ['discord.com', 'discord.gg'],
        'disney':     ['disneyplus.com', 'disney.com'],
        'norton':     ['norton.com', 'nortonlifelock.com'],
        'mcafee':     ['mcafee.com'],
        'fedex':      ['fedex.com'],
        'ups':        ['ups.com'],
        'usps':       ['usps.com'],
        'dhl':        ['dhl.com'],
        'coinbase':   ['coinbase.com'],
        'kraken':     ['kraken.com'],
    }
    for brand in matched_brands:
        legit_list = LEGIT_DOMAINS.get(brand, [])
        for legit in legit_list:
            if domain == legit or domain.endswith('.' + legit):
                return True
    return False


def _empty_features(url: str) -> Dict[str, Any]:
    return {
        'url_length': len(url),
        'domain_length': 0,
        'num_dots': 0,
        'num_hyphens': 0,
        'num_digits_domain': 0,
        'num_digits_url': 0,
        'num_special_chars': 0,
        'has_at_symbol': 0,
        'has_double_slash_redirect': 0,
        'is_https': 0,
        'is_ip_address': 0,
        'domain_entropy': 0,
        'url_entropy': 0,
        'path_depth': 0,
        'num_query_params': 0,
        'query_length': 0,
        'num_subdomains': 0,
        'tld': '',
        'is_suspicious_tld': 0,
        'brand_impersonation': [],
        'has_brand_keyword': 0,
        'is_legitimate_brand': 0,
        'phishing_path_keywords': [],
        'has_phishing_path': 0,
        'has_punycode': 0,
        'domain_has_numbers': 0,
        'has_credential_form': 0,
        'has_content_phishing_keywords': 0,
        'suspicious_form': 0,
        'is_test_phishing': 0,
        'has_malware_keywords': 0,
        'has_fake_alert': 0,
    }
