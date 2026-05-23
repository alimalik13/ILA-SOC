from typing import Dict, Any, List

class TimelineRenderPayloads:
    """
    Decorates backend timeline events with UI metadata (icons, colors, badges)
    so the frontend can render them immediately without complex logic.
    """
    
    @staticmethod
    def prepare_timeline_for_ui(chronological_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        ui_timeline = []
        
        for event in chronological_events:
            event_type = event.get('type', '')
            ui_event = {
                "timestamp": event.get('timestamp'),
                "title": "",
                "description": event.get('description', ''),
                "icon": "fa-circle",
                "color_class": "text-secondary",
                "is_alert": False,
                "context": event.get('context', [])
            }
            
            if event_type == "Structured Alert":
                ui_event["is_alert"] = True
                ui_event["icon"] = "fa-exclamation-triangle"
                ui_event["color_class"] = "text-danger"
                ui_event["title"] = "Behavioral Alert"
                
            elif event_type == "Raw Telemetry":
                desc = event.get('description', '').lower()
                if "process created" in desc:
                    ui_event["icon"] = "fa-play-circle"
                    ui_event["color_class"] = "text-primary"
                    ui_event["title"] = "Process Execution"
                elif "network connection" in desc:
                    ui_event["icon"] = "fa-network-wired"
                    ui_event["color_class"] = "text-warning"
                    ui_event["title"] = "Network Activity"
                elif "dns query" in desc:
                    ui_event["icon"] = "fa-search"
                    ui_event["color_class"] = "text-info"
                    ui_event["title"] = "DNS Resolution"
                elif "accessed" in desc: # Process Access
                    ui_event["icon"] = "fa-unlock-alt"
                    ui_event["color_class"] = "text-danger"
                    ui_event["title"] = "Memory Access"
                else:
                    ui_event["title"] = "System Event"
                    
            ui_timeline.append(ui_event)
            
        return ui_timeline
