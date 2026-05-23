import re
import math
from typing import Dict, Any, List
from .process_tracker import ProcessTracker

class SysmonFeatureExtractor:
    """
    EventID-aware structured feature extraction module.
    Translates raw JSON Sysmon telemetry into numerical/categorical vectors.
    """
    def __init__(self, tracker: ProcessTracker):
        self.tracker = tracker
        
        # Threat Intelligence / Baselines
        self.lolbins = {'powershell.exe', 'cmd.exe', 'certutil.exe', 'bitsadmin.exe', 
                        'regsvr32.exe', 'rundll32.exe', 'wmic.exe', 'mshta.exe', 
                        'cscript.exe', 'wscript.exe', 'schtasks.exe', 'msbuild.exe'}
                        
        self.script_interpreters = {'powershell.exe', 'cmd.exe', 'cscript.exe', 'wscript.exe', 'python.exe'}
        self.office_apps = {'winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe'}
        
        self.suspicious_ports = {'4444', '8080', '1337', '31337', '666', '3389', '22'}
        self.common_external_ports = {'80', '443'}

    def extract_features(self, event: Dict[str, Any]) -> Dict[str, float]:
        """Main routing method based on EventID."""
        features = {}
        eid = str(event.get('event_id', ''))
        
        # 1. Update tracker if Process Creation
        if eid == '1':
            self.tracker.add_process(
                guid=event.get('process_guid', ''),
                image=event.get('image', ''),
                command_line=event.get('command_line', ''),
                parent_guid=event.get('parent_guid', '') # Assuming normalized schema adds this or extracts from raw
            )
            
        # 2. Extract Base Features (Apply to all)
        features.update(self._base_features(event))
        
        # 3. Extract EventID-specific features
        if eid == '1':
            features.update(self._process_creation_features(event))
        elif eid == '3':
            features.update(self._network_features(event))
        elif eid == '10':
            features.update(self._process_access_features(event))
        elif eid in ('12', '13', '14'):
            features.update(self._registry_features(event))
        elif eid == '22':
            features.update(self._dns_features(event))
        elif eid in ('17', '18'):
            features.update(self._named_pipe_features(event))
            
        return features

    # --- Feature Modules ---

    def _base_features(self, event: Dict[str, Any]) -> Dict[str, float]:
        """Features relevant across the entire dataset."""
        user = str(event.get('user', '')).lower()
        image = str(event.get('image', '')).lower()
        
        # Extract process depth from the temporal tracker
        guid = event.get('process_guid', '')
        depth = self.tracker.get_process_depth(guid)
        
        return {
            'is_system_user': 1.0 if 'system' in user or 'network service' in user else 0.0,
            'is_admin_user': 1.0 if 'admin' in user else 0.0,
            'is_lolbin': 1.0 if image.split('\\')[-1] in self.lolbins else 0.0,
            'suspicious_process_path': 1.0 if any(p in image for p in ['\\temp\\', '\\public\\', '\\programdata\\']) else 0.0,
            'process_depth': depth
        }

    def _process_creation_features(self, event: Dict[str, Any]) -> Dict[str, float]:
        """Event ID 1: Process Creation"""
        image = str(event.get('image', '')).lower().split('\\')[-1]
        p_image = str(event.get('parent_image', '')).lower().split('\\')[-1]
        cmd = str(event.get('command_line', '')).lower()
        
        suspicious_parent_child = 0.0
        if p_image in self.office_apps and image in self.script_interpreters:
            suspicious_parent_child = 1.0 # Macro executing shell
        elif p_image == 'svchost.exe' and image == 'cmd.exe':
            suspicious_parent_child = 1.0
            
        # Obfuscation checks
        b64_regex = r'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
        
        return {
            'suspicious_parent_child': suspicious_parent_child,
            'office_child_process': 1.0 if p_image in self.office_apps else 0.0,
            'script_interpreter_spawn': 1.0 if image in self.script_interpreters else 0.0,
            'unsigned_temp_execution': 1.0 if '\\temp\\' in str(event.get('image', '')).lower() else 0.0, # Proxy for unsigned/dropped binary execution
            'powershell_encoded': 1.0 if 'powershell' in image and ('-e ' in cmd or '-enc' in cmd or bool(re.search(b64_regex, cmd))) else 0.0,
            'commandline_entropy': self._calculate_entropy(cmd) if cmd else 0.0,
        }

    def _network_features(self, event: Dict[str, Any]) -> Dict[str, float]:
        """Event ID 3: Network Connection"""
        port = str(event.get('destination_port', ''))
        ip = str(event.get('destination_ip', ''))
        
        # Very basic check for external vs internal IP (excluding 10., 192.168., 172.16-31.)
        is_external = 0.0
        if ip and not (ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('127.')):
            is_external = 1.0
            
        return {
            'suspicious_port': 1.0 if port in self.suspicious_ports else 0.0,
            'external_network_connection': is_external,
            'non_standard_external_port': 1.0 if is_external and port not in self.common_external_ports else 0.0
        }

    def _process_access_features(self, event: Dict[str, Any]) -> Dict[str, float]:
        """Event ID 10: Process Access (Memory Dumping/Injection)"""
        target = str(event.get('target_object', '')).lower().split('\\')[-1]
        access = str(event.get('granted_access', '')).lower()
        
        return {
            'lsass_access': 1.0 if 'lsass.exe' in target else 0.0,
            # Common access rights used by Mimikatz/Dumpert
            'suspicious_access_right': 1.0 if any(h in access for h in ['0x1010', '0x1410', '0x1438', '0x1f0fff']) else 0.0
        }

    def _registry_features(self, event: Dict[str, Any]) -> Dict[str, float]:
        """Event ID 12/13/14: Registry Activity"""
        target = str(event.get('target_object', '')).lower()
        
        return {
            'registry_persistence': 1.0 if any(k in target for k in ['\\currentversion\\run', '\\services\\', 'userinit']) else 0.0,
            'registry_security_downgrade': 1.0 if 'enablelua' in target or 'realtimeprotection' in target else 0.0
        }

    def _dns_features(self, event: Dict[str, Any]) -> Dict[str, float]:
        """Event ID 22: DNS Query"""
        query = str(event.get('target_object', '')).lower()
        entropy = self._calculate_entropy(query) if query else 0.0
        
        return {
            'dns_entropy': entropy,
            'dns_dga_likely': 1.0 if entropy > 3.8 and len(query) > 15 else 0.0
        }

    def _named_pipe_features(self, event: Dict[str, Any]) -> Dict[str, float]:
        """Event ID 17/18: Named Pipes"""
        pipe = str(event.get('pipe_name', '')).lower()
        suspicious_pipes = {'\\psexecsvc', '\\paexec', '\\remcom_communicator', '\\csexec', '\\mojo', '\\postex_'}
        
        return {
            'named_pipe_usage': 1.0 if pipe else 0.0,
            'suspicious_named_pipe': 1.0 if any(p in pipe for p in suspicious_pipes) else 0.0
        }

    # --- Utils ---
    def _calculate_entropy(self, data: str) -> float:
        if not data: return 0.0
        prob = [float(data.count(c)) / len(data) for c in dict.fromkeys(list(data))]
        return -sum(p * math.log(p) / math.log(2.0) for p in prob)
