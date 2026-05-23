from typing import Dict, Any, List, Optional
import time
import hashlib

class StructuredAlertExplainer:
    """
    Generates highly detailed, SOC-readable explainability reports for structured alerts.
    Translates raw math features into human-readable context.
    """
    
    @staticmethod
    def generate_explanation(event: Dict[str, Any], features: Dict[str, float], 
                             context_verdict: str, justifications: List[str],
                             rule_triggered: str) -> Dict[str, Any]:
        """
        Creates a structured alert payload focused on explainability.
        """
        # Build the lineage string if we have it
        parent = event.get('parent_image', '').split('\\')[-1]
        child = event.get('image', '').split('\\')[-1]
        lineage = f"{parent} -> {child}" if parent else child
        
        # Identify the critical triggers
        triggers = []
        if features.get('office_child_process') == 1.0: triggers.append("Office Document Spawned Child")
        if features.get('lsass_access') == 1.0: triggers.append("LSASS Memory Access")
        if features.get('suspicious_named_pipe') == 1.0: triggers.append("Suspicious Named Pipe")
        if features.get('powershell_encoded') == 1.0: triggers.append("Encoded PowerShell Command")
        if features.get('dns_dga_likely') == 1.0: triggers.append("High Entropy DGA Domain")
        
        explanation = {
            "alert_type": "STRUCTURED_HIGH_CONFIDENCE",
            "rule_name": rule_triggered,
            "severity": "CRITICAL",
            "timestamp": event.get('timestamp', time.strftime("%Y-%m-%dT%H:%M:%SZ")),
            "host": event.get('computer', 'Unknown'),
            "user": event.get('user', 'Unknown'),
            "process_lineage": lineage,
            "triggering_behaviors": triggers,
            "contextual_risk_score": context_verdict,
            "contextual_justifications": justifications,
            "raw_evidence": {
                "command_line": event.get('command_line', ''),
                "target_object": event.get('target_object', '')
            }
        }
        
        return explanation
