import traceback
from typing import Dict, Any

from nextgen_sysmon_pipeline.feature_extractor import SysmonFeatureExtractor
from nextgen_sysmon_pipeline.process_tracker import ProcessTracker
from nextgen_sysmon_pipeline.structured_shadow_logger import StructuredShadowLogger

class ShadowModeRunner:
    """
    The main entry point for passive parallel analytics.
    Designed to be dropped into the production Flask API with ZERO disruption.
    """
    def __init__(self):
        # Initialize the stateful components
        self.tracker = ProcessTracker()
        self.extractor = SysmonFeatureExtractor(self.tracker)
        self.logger = StructuredShadowLogger()
        print("[NextGen Sysmon] Shadow Mode initialized. Ready for passive telemetry collection.")

    def process_in_shadow_mode(self, raw_telemetry: Dict[str, Any], legacy_verdict: str):
        """
        Silently process incoming telemetry alongside the production pipeline.
        
        Args:
            raw_telemetry: The incoming Sysmon JSON dictionary.
            legacy_verdict: The classification verdict from the existing TF-IDF pipeline.
        """
        try:
            # 1. Ensure minimal fields exist
            eid = str(raw_telemetry.get('event_id', raw_telemetry.get('EventID', '')))
            if not eid:
                return # Not structured Sysmon telemetry
                
            # Normalize schema map if necessary (mapping raw Winlogbeat to our schema)
            # In a real setup, we would run a parser mapping here.
            # Assuming raw_telemetry is already mostly in the schema format for this example.
            
            # 2. Extract structured features (This natively updates the ProcessTracker)
            features = self.extractor.extract_features(raw_telemetry)
            
            # 3. Log the parallel comparison
            guid = raw_telemetry.get('process_guid', '')
            self.logger.log_shadow_event(
                event_id=eid,
                process_guid=guid,
                legacy_verdict=legacy_verdict,
                raw_json=raw_telemetry,
                feature_vector=features
            )
            
        except Exception as e:
            # SAFETY REQUIREMENT: NEVER block ingestion, NEVER crash server routes
            print(f"[SHADOW_MODE_ERROR] Caught exception during passive extraction: {e}")
            # traceback.print_exc() # In production, log this to an isolated error file
            pass

# Global instance for easy import in server.py
shadow_runner = ShadowModeRunner()

def dispatch_shadow_event(raw_json: Dict[str, Any], legacy_verdict: str):
    """
    Helper function to dispatch an event to the global shadow runner.
    """
    shadow_runner.process_in_shadow_mode(raw_json, legacy_verdict)
