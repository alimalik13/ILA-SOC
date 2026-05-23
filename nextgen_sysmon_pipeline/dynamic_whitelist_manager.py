from typing import Dict, Any

class DynamicWhitelistManager:
    """
    Maintains and evaluates adaptive whitelists for enterprise workflows to 
    suppress false positives before they generate alerts.
    """
    def __init__(self):
        # Internal IP Ranges
        self.internal_subnets = ['10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.']
        
        # Approved application ports mapped to subnets or global
        self.approved_ports = {
            '8080': 'INTERNAL_ONLY', # Tomcat/Jenkins
            '8443': 'INTERNAL_ONLY', # Internal Web Apps
            '3389': 'INTERNAL_ONLY', # RDP (Should only be internal)
        }
        
        # Known benign execution paths
        self.benign_execution_chains = {
            'code.exe': ['git.exe', 'python.exe', 'node.exe', 'cmd.exe', 'powershell.exe'],
            'services.exe': ['svchost.exe', 'msmpeng.exe'],
            'wininit.exe': ['lsass.exe', 'services.exe']
        }

    def _is_internal_ip(self, ip: str) -> bool:
        return any(ip.startswith(subnet) for subnet in self.internal_subnets)

    def evaluate_whitelist(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates the event against known whitelists.
        Returns a dictionary containing suppression flags and justifications.
        """
        eid = str(event.get('event_id', ''))
        result = {
            'is_whitelisted': False,
            'suppression_reason': '',
            'confidence_reduction': 0.0 # Amount to reduce the ML risk score
        }
        
        # 1. Developer Workflow Whitelist (EID 1)
        if eid == '1':
            parent = event.get('parent_image', '').split('\\')[-1].lower()
            child = event.get('image', '').split('\\')[-1].lower()
            
            if parent in self.benign_execution_chains and child in self.benign_execution_chains[parent]:
                result['is_whitelisted'] = True
                result['suppression_reason'] = f"Approved execution chain: {parent} -> {child}"
                result['confidence_reduction'] = 0.9 # Heavily suppress ML score
                
        # 2. Internal Network Whitelist (EID 3)
        elif eid == '3':
            dest_ip = event.get('destination_ip', '')
            dest_port = str(event.get('destination_port', ''))
            
            if self._is_internal_ip(dest_ip):
                if dest_port in self.approved_ports and self.approved_ports[dest_port] == 'INTERNAL_ONLY':
                    result['is_whitelisted'] = True
                    result['suppression_reason'] = f"Approved internal port usage: {dest_port}"
                    result['confidence_reduction'] = 1.0 # Completely suppress
                    
        return result
