import os
import requests
import time
import ipaddress
from backend import database

VT_API_KEY = os.getenv('VT_API_KEY')
VT_API_BASE_URL = 'https://www.virustotal.com/api/v3'

def is_private_ip(ip_address):
    """
    Check if an IP address is private/local (RFC 1918).
    
    Args:
        ip_address (str): IP address to check
        
    Returns:
        bool: True if private IP, False otherwise
    """
    try:
        ip = ipaddress.ip_address(ip_address)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False

def check_virus_total(ip_or_url, bypass_cache=False):
    """
    Check if an IP address or URL is malicious using VirusTotal API v3.
    
    Args:
        ip_or_url (str): IP address or URL to check
        bypass_cache (bool): If True, skip cache and force fresh API call
        
    Returns:
        dict: Dictionary containing malicious count, suspicious count, 
              harmless count, and overall status
    """
    if not VT_API_KEY:
        print("⚠️ VT_API_KEY not found in environment variables")
        return {
            'malicious': 0,
            'suspicious': 0,
            'harmless': 0,
            'status': 'Error',
            'error': 'API key not configured'
        }
    
    if not ip_or_url or ip_or_url == "Unknown":
        return {
            'malicious': 0,
            'suspicious': 0,
            'harmless': 0,
            'status': 'Error',
            'error': 'Invalid IP/URL'
        }
    
    is_url = '://' in ip_or_url or '/' in ip_or_url
    
    if not is_url and is_private_ip(ip_or_url):
        print(f"\n🏠 PRIVATE IP DETECTED: {ip_or_url} - Skipping VirusTotal lookup")
        return {
            'malicious': 0,
            'suspicious': 0,
            'harmless': 0,
            'status': 'Local Network (Skipped)',
            'error': None
        }
    
    if not bypass_cache:
        cached_result = database.get_cached_vt_result(ip_or_url)
        if cached_result:
            print(f"\n💾 CACHE HIT: {ip_or_url} - Using cached VirusTotal result")
            print(f"   ✅ Cached Status: {cached_result.get('status')}")
            print(f"      Malicious: {cached_result.get('malicious', 0)}, Suspicious: {cached_result.get('suspicious', 0)}, Harmless: {cached_result.get('harmless', 0)}")
            return cached_result
    else:
        print(f"\n🔄 CACHE BYPASS: {ip_or_url} - Forcing fresh VirusTotal lookup")
        database.log_cache_event(ip_or_url, 'cache_bypass')
    
    try:
        if is_url:
            import base64
            url_id = base64.urlsafe_b64encode(ip_or_url.encode()).decode().strip("=")
            endpoint = f"{VT_API_BASE_URL}/urls/{url_id}"
        else:
            endpoint = f"{VT_API_BASE_URL}/ip_addresses/{ip_or_url}"
        
        headers = {
            'x-apikey': VT_API_KEY,
            'Accept': 'application/json'
        }
        
        print(f"\n🔍 VIRUSTOTAL CHECK: {ip_or_url}")
        response = requests.get(endpoint, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            if 'data' in data and 'attributes' in data['data']:
                stats = data['data']['attributes'].get('last_analysis_stats', {})
                
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                harmless = stats.get('harmless', 0)
                undetected = stats.get('undetected', 0)
                
                if malicious > 0:
                    status = 'Malicious'
                elif suspicious > 0:
                    status = 'Suspicious'
                else:
                    status = 'Clean'
                
                result = {
                    'malicious': malicious,
                    'suspicious': suspicious,
                    'harmless': harmless,
                    'undetected': undetected,
                    'status': status
                }
                
                print(f"   ✅ VirusTotal Results:")
                print(f"      Status: {status}")
                print(f"      Malicious: {malicious}, Suspicious: {suspicious}, Harmless: {harmless}")
                
                database.save_vt_cache(ip_or_url, result, is_refresh=bypass_cache)
                print(f"   💾 Saved result to cache")
                
                return result
            else:
                print(f"   ⚠️ No analysis data found for {ip_or_url}")
                return {
                    'malicious': 0,
                    'suspicious': 0,
                    'harmless': 0,
                    'status': 'Not Found',
                    'error': 'No data available'
                }
        
        elif response.status_code == 404:
            print(f"   ℹ️ {ip_or_url} not found in VirusTotal database")
            result = {
                'malicious': 0,
                'suspicious': 0,
                'harmless': 0,
                'status': 'Not Found',
                'error': 'Not in VT database'
            }
            database.save_vt_cache(ip_or_url, result, is_refresh=bypass_cache)
            print(f"   💾 Saved 'Not Found' result to cache")
            return result
        
        elif response.status_code == 429:
            print(f"   ⚠️ VirusTotal API rate limit exceeded")
            return {
                'malicious': 0,
                'suspicious': 0,
                'harmless': 0,
                'status': 'Error',
                'error': 'Rate limit exceeded'
            }
        
        else:
            print(f"   ❌ VirusTotal API error: {response.status_code}")
            return {
                'malicious': 0,
                'suspicious': 0,
                'harmless': 0,
                'status': 'Error',
                'error': f'HTTP {response.status_code}'
            }
    
    except requests.exceptions.Timeout:
        print(f"   ❌ VirusTotal API timeout")
        return {
            'malicious': 0,
            'suspicious': 0,
            'harmless': 0,
            'status': 'Error',
            'error': 'Request timeout'
        }
    
    except Exception as e:
        print(f"   ❌ VirusTotal check failed: {e}")
        return {
            'malicious': 0,
            'suspicious': 0,
            'harmless': 0,
            'status': 'Error',
            'error': str(e)
        }
