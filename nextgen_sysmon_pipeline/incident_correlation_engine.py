import time
import hashlib
from typing import Dict, Any, List

class IncidentCorrelationEngine:
    """
    Groups isolated structured alerts into cohesive Incidents using temporal,
    host, and process lineage relationships. Handles severity escalation.
    """
    def __init__(self):
        # Maps incident_hash -> Incident Dict
        self.active_incidents = {}
        # Correlation window: 15 minutes
        self.correlation_window = 900 
        
    def _generate_incident_hash(self, host: str, user: str, root_guid: str) -> str:
        """Creates a unique identifier for an attack chain."""
        return hashlib.md5(f"{host}_{user}_{root_guid}".encode()).hexdigest()

    def correlate_alert(self, alert: Dict[str, Any], raw_event: Dict[str, Any], root_guid: str) -> Dict[str, Any]:
        """
        Ingests an alert and correlates it into an existing incident or creates a new one.
        Returns the updated Incident object.
        """
        host = alert.get('host', 'Unknown')
        user = alert.get('user', 'Unknown')
        
        incident_hash = self._generate_incident_hash(host, user, root_guid)
        current_time = time.time()
        
        if incident_hash not in self.active_incidents:
            # Create new incident
            incident = {
                "incident_id": f"INC-{incident_hash[:8].upper()}",
                "status": "OPEN",
                "severity": alert.get('severity', 'LOW'),
                "host": host,
                "user": user,
                "root_process_guid": root_guid,
                "first_seen": alert.get('timestamp'),
                "last_seen": alert.get('timestamp'),
                "last_updated": current_time,
                "related_alerts": [],
                "raw_events": [],
                "escalation_triggers": set()
            }
            self.active_incidents[incident_hash] = incident
            
        incident = self.active_incidents[incident_hash]
        
        # Deduplication: Don't add the exact same alert twice to an incident
        alert_signature = alert.get('rule_name', '') + raw_event.get('process_guid', '')
        if not any(a.get('_sig') == alert_signature for a in incident['related_alerts']):
            alert['_sig'] = alert_signature
            incident['related_alerts'].append(alert)
            incident['raw_events'].append(raw_event)
            incident['last_seen'] = alert.get('timestamp')
            incident['last_updated'] = current_time
            
        # Run Severity Escalation
        self._escalate_severity(incident)
        
        return incident

    def _escalate_severity(self, incident: Dict[str, Any]):
        """
        Escalates severity based on the aggregation of multiple suspicious behaviors.
        """
        rules_triggered = set(a.get('rule_name') for a in incident['related_alerts'])
        
        # Escalation 1: Office -> PowerShell -> Network
        if "Office_Macro_Suspicious_Spawn" in rules_triggered and any(e.get('event_id') == '3' for e in incident['raw_events']):
            incident['severity'] = "CRITICAL"
            incident['escalation_triggers'].add("Macro Execution Followed By Network Connection")
            
        # Escalation 2: Suspicious Execution -> Credential Access
        if len(rules_triggered) > 1 and "LSASS_Memory_Dump_Access" in rules_triggered:
            incident['severity'] = "CRITICAL"
            incident['escalation_triggers'].add("Suspicious Execution Escalating to Credential Access")
            
        # Clean up sets for JSON serialization later
        incident['escalation_reasons'] = list(incident['escalation_triggers'])
