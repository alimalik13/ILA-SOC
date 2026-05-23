"""
Data Manager Module for ILA-SOC Dashboard
Provides centralized data handling for real-time dashboard updates
"""
from backend import database
from datetime import datetime, timedelta
import os


class DataManager:
    """Centralized data manager for dashboard statistics and real-time updates"""
    
    def __init__(self):
        self.last_update = None
        self.cache_timeout = 5  # seconds
        self._cached_stats = None
    
    def get_dashboard_stats(self):
        """Get aggregated dashboard statistics"""
        logs = database.get_all_logs()
        blocked_ips = database.get_blocked_ips()
        
        total_logs = len(logs)
        total_malicious = sum(1 for log in logs if log['status'] == 'Malicious')
        total_suspicious = sum(1 for log in logs if log['status'] == 'Suspicious')
        total_normal = sum(1 for log in logs if log['status'] == 'Normal')
        
        return {
            'total_logs': total_logs,
            'total_malicious': total_malicious,
            'total_suspicious': total_suspicious,
            'total_normal': total_normal,
            'blocked_ips_count': len(blocked_ips)
        }
    
    def get_logs_per_hour(self):
        """Get log counts grouped by hour for timeline chart"""
        logs = database.get_all_logs()
        hourly_counts = {str(h): 0 for h in range(24)}
        
        for log in logs:
            try:
                ts = datetime.strptime(log['timestamp'], '%Y-%m-%d %H:%M:%S')
                hour = str(ts.hour)
                hourly_counts[hour] = hourly_counts.get(hour, 0) + 1
            except (ValueError, KeyError):
                pass
        
        return hourly_counts
    
    def get_attack_type_distribution(self):
        """Get distribution of attack types from malicious logs"""
        logs = database.get_all_logs()
        attack_types = {}
        
        for log in logs:
            if log['status'] == 'Malicious':
                message = log.get('message', '')
                if isinstance(message, dict):
                    attack_type = message.get('attack_type', 'Unknown')
                else:
                    attack_type = self._detect_attack_type(str(message))
                
                attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
        
        return attack_types
    
    def _detect_attack_type(self, message):
        """Simple attack type detection from log message"""
        message_lower = message.lower()
        
        attack_patterns = {
            'Brute Force': ['failed login', 'authentication failure', 'invalid password'],
            'SQL Injection': ['sql', 'select * from', 'union select', 'drop table'],
            'XSS': ['<script', 'javascript:', 'onerror='],
            'Command Injection': ['cmd.exe', '/bin/sh', '&&', '||', ';rm'],
            'Path Traversal': ['../', '..\\', '%2e%2e'],
            'Privilege Escalation': ['sudo', 'runas', 'privilege'],
            'Malware': ['malware', 'virus', 'trojan', 'ransomware'],
            'Data Exfiltration': ['exfiltrat', 'upload', 'transfer'],
            'Reconnaissance': ['scan', 'nmap', 'port scan'],
            'Credential Theft': ['credential', 'password', 'hash dump']
        }
        
        for attack_type, patterns in attack_patterns.items():
            if any(pattern in message_lower for pattern in patterns):
                return attack_type
        
        return 'Unknown Attack'
    
    def get_recent_threats(self, limit=20):
        """Get most recent malicious/suspicious logs for live feed"""
        logs = database.get_all_logs()
        
        threats = [log for log in logs if log['status'] in ('Malicious', 'Suspicious')]
        threats.sort(key=lambda x: x['timestamp'], reverse=True)
        
        recent = []
        for log in threats[:limit]:
            message = log.get('message', '')
            if isinstance(message, dict):
                display_message = message.get('log_text', str(message))[:100]
            else:
                display_message = str(message)[:100]
            
            recent.append({
                'id': log['id'],
                'timestamp': log['timestamp'],
                'status': log['status'],
                'message': display_message
            })
        
        return recent
    
    def get_full_analytics(self):
        """Get comprehensive analytics data for dashboard"""
        stats = self.get_dashboard_stats()
        logs_per_hour = self.get_logs_per_hour()
        attack_types = self.get_attack_type_distribution()
        recent_malicious = self.get_recent_threats()
        blocked_ips = database.get_blocked_ips()
        cache_stats = database.get_cache_stats()
        
        top_blocked = []
        for ip_info in blocked_ips[:10]:
            top_blocked.append({
                'ip': ip_info['ip'],
                'timestamp': ip_info['timestamp']
            })
        
        return {
            'total_logs': stats['total_logs'],
            'total_malicious': stats['total_malicious'],
            'total_suspicious': stats['total_suspicious'],
            'total_normal': stats['total_normal'],
            'blocked_ips_count': stats['blocked_ips_count'],
            'logs_per_hour': logs_per_hour,
            'attack_types': attack_types,
            'top_signatures': {},
            'recent_malicious': recent_malicious,
            'top_blocked_ips': top_blocked,
            'cache_stats': cache_stats
        }


class ConfigManager:
    """Manages API keys and application configuration"""
    
    @staticmethod
    def get_api_key(key_name, env_fallback=None):
        """Get API key from database settings, falling back to environment variable"""
        db_value = database.get_setting(f'api_key_{key_name}')
        if db_value:
            return db_value
        
        if env_fallback:
            return os.getenv(env_fallback, '')
        
        env_key = key_name.upper().replace(' ', '_')
        return os.getenv(env_key, '')
    
    @staticmethod
    def set_api_key(key_name, value):
        """Save API key to database settings"""
        database.set_setting(f'api_key_{key_name}', value)
    
    @staticmethod
    def get_vt_api_key():
        """Get VirusTotal API key"""
        return ConfigManager.get_api_key('virustotal', 'VT_API_KEY')
    
    @staticmethod
    def set_vt_api_key(value):
        """Set VirusTotal API key"""
        ConfigManager.set_api_key('virustotal', value)
    
    @staticmethod
    def get_agent_api_key():
        """Get Agent API key"""
        db_value = database.get_setting('api_key_agent')
        if db_value:
            return db_value
        return os.getenv('AGENT_API_KEY', 'ila-soc-agent-key-2024')
    
    @staticmethod
    def set_agent_api_key(value):
        """Set Agent API key"""
        database.set_setting('api_key_agent', value)
    
    @staticmethod
    def get_threshold(threshold_type, default=80):
        """Get alert threshold value"""
        value = database.get_setting(f'threshold_{threshold_type}')
        return int(value) if value else default
    
    @staticmethod
    def set_threshold(threshold_type, value):
        """Set alert threshold value"""
        database.set_setting(f'threshold_{threshold_type}', str(value))
    
    @staticmethod
    def is_api_key_configured(key_name):
        """Check if an API key is configured (either in DB or env)"""
        key = ConfigManager.get_api_key(key_name)
        return bool(key and len(key) > 0)


data_manager = DataManager()
config_manager = ConfigManager()
