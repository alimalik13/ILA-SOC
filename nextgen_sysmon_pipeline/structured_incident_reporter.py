import json
from nextgen_sysmon_pipeline.process_lineage_builder import ProcessLineageBuilder
from nextgen_sysmon_pipeline.incident_correlation_engine import IncidentCorrelationEngine
from nextgen_sysmon_pipeline.incident_timeline_generator import IncidentTimelineGenerator

class StructuredIncidentReporter:
    """
    Orchestrates the investigation objects. Consumes disparate alerts, 
    correlates them, builds the graphs, and outputs the final Investigation JSON.
    """
    def __init__(self):
        self.lineage_builder = ProcessLineageBuilder()
        self.correlation_engine = IncidentCorrelationEngine()
        
    def ingest_raw_event(self, event: dict):
        # We only need to cache Process Creates to build the tree later
        if str(event.get('event_id', '')) == '1':
            self.lineage_builder.add_process_event(event)
            
    def ingest_alert(self, alert: dict, raw_event: dict):
        # Determine the root guid. We'll find the oldest ancestor we know.
        guid = raw_event.get('process_guid', '')
        
        # Hack to find root: walk up the chain as far as we can
        root_guid = guid
        current = guid
        while current in self.lineage_builder.process_cache:
            parent = self.lineage_builder.process_cache[current].get('parent_guid')
            if not parent or parent == current:
                break
            root_guid = parent
            current = parent
            
        return self.correlation_engine.correlate_alert(alert, raw_event, root_guid)

    def generate_investigation_object(self, incident_id: str) -> dict:
        """Generates the final JSON payload for the SOC Analyst."""
        # Find the incident
        incident = None
        for inc in self.correlation_engine.active_incidents.values():
            if inc.get('incident_id') == incident_id:
                incident = inc
                break
                
        if not incident:
            return {"error": "Incident not found"}
            
        # Build the graph
        root_guid = incident.get('root_process_guid')
        process_tree = self.lineage_builder.build_lineage_tree(root_guid)
        
        # Build the timeline
        timeline = IncidentTimelineGenerator.generate_timeline(incident)
        
        # Assemble the final package
        investigation_object = {
            "incident_summary": {
                "id": incident.get('incident_id'),
                "severity": incident.get('severity'),
                "status": incident.get('status'),
                "host": incident.get('host'),
                "user": incident.get('user'),
                "first_seen": incident.get('first_seen'),
                "escalation_reasons": incident.get('escalation_reasons', [])
            },
            "attack_chain_graph": process_tree,
            "chronological_timeline": timeline,
            "metrics": {
                "total_alerts_collapsed": len(incident.get('related_alerts', [])),
                "total_raw_events": len(incident.get('raw_events', []))
            }
        }
        
        return investigation_object

if __name__ == "__main__":
    # Simulate an attack chain to generate sample JSON
    reporter = StructuredIncidentReporter()
    
    e1 = {"timestamp": "10:00:00", "event_id": "1", "process_guid": "guid1", "image": "explorer.exe", "command_line": "explorer.exe"}
    e2 = {"timestamp": "10:01:00", "event_id": "1", "process_guid": "guid2", "parent_guid": "guid1", "image": "winword.exe", "command_line": "winword.exe invoice.docm"}
    e3 = {"timestamp": "10:02:00", "event_id": "1", "process_guid": "guid3", "parent_guid": "guid2", "image": "powershell.exe", "command_line": "powershell.exe -enc SUVY..."}
    e4 = {"timestamp": "10:02:05", "event_id": "3", "process_guid": "guid3", "image": "powershell.exe", "destination_ip": "185.15.2.1", "destination_port": "4444"}
    
    for e in [e1, e2, e3, e4]:
        reporter.ingest_raw_event(e)
        
    alert1 = {"timestamp": "10:02:00", "rule_name": "Office_Macro_Suspicious_Spawn", "severity": "HIGH", "host": "WS-01", "user": "bob"}
    reporter.ingest_alert(alert1, e3)
    
    # Let's say we had a mock network alert
    alert2 = {"timestamp": "10:02:05", "rule_name": "Suspicious_Network_Connection", "severity": "HIGH", "host": "WS-01", "user": "bob"}
    incident = reporter.ingest_alert(alert2, e4)
    
    inv_obj = reporter.generate_investigation_object(incident['incident_id'])
    
    with open("sample_incident_investigation.json", "w") as f:
        json.dump(inv_obj, f, indent=2)
    print("Generated sample_incident_investigation.json successfully!")
