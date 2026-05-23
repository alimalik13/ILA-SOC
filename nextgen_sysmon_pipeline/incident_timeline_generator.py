from typing import Dict, Any, List

class IncidentTimelineGenerator:
    """
    Transforms raw incident data into a chronologically sorted, 
    human-readable timeline perfect for frontend UI rendering.
    """
    
    @staticmethod
    def generate_timeline(incident: Dict[str, Any]) -> List[Dict[str, Any]]:
        timeline = []
        
        # We merge raw events and alerts into a single chronological stream
        events_stream = []
        
        for raw in incident.get('raw_events', []):
            events_stream.append({
                "timestamp": raw.get('timestamp', ''),
                "type": "Raw Telemetry",
                "event_id": raw.get('event_id', ''),
                "description": IncidentTimelineGenerator._format_raw_event(raw),
                "guid": raw.get('process_guid', '')
            })
            
        for alert in incident.get('related_alerts', []):
            events_stream.append({
                "timestamp": alert.get('timestamp', ''),
                "type": "Structured Alert",
                "severity": alert.get('severity', ''),
                "description": f"Rule Triggered: {alert.get('rule_name')}",
                "context": alert.get('contextual_justifications', []),
                "guid": alert.get('raw_evidence', {}).get('process_guid', '') # Fallback
            })
            
        # Sort chronologically
        events_stream.sort(key=lambda x: x.get('timestamp', ''))
        return events_stream
        
    @staticmethod
    def _format_raw_event(raw: Dict[str, Any]) -> str:
        eid = str(raw.get('event_id', ''))
        if eid == '1':
            return f"Process Created: {raw.get('image', '').split('\\')[-1]} ({raw.get('command_line', '')})"
        elif eid == '3':
            return f"Network Connection: {raw.get('image', '').split('\\')[-1]} connected to {raw.get('destination_ip', '')}:{raw.get('destination_port', '')}"
        elif eid == '10':
            return f"Process Accessed: {raw.get('source_image', '').split('\\')[-1]} accessed {raw.get('target_image', '').split('\\')[-1]}"
        elif eid == '22':
            return f"DNS Query: {raw.get('image', '').split('\\')[-1]} requested {raw.get('target_object', '')}"
        return f"Event ID {eid} logged."
