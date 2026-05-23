from typing import Dict, Any, Tuple
from nextgen_sysmon_pipeline.contextual_baseline_engine import ContextualBaselineEngine
from nextgen_sysmon_pipeline.dynamic_whitelist_manager import DynamicWhitelistManager

class ContextualRiskScorer:
    """
    Acts as the final decision layer. Takes raw ML features, applies 
    Contextual Baselining and Dynamic Whitelisting, and produces a final weighted risk score.
    """
    def __init__(self, baseline_engine: ContextualBaselineEngine, whitelist_manager: DynamicWhitelistManager):
        self.baselines = baseline_engine
        self.whitelists = whitelist_manager

    def evaluate_risk(self, event: Dict[str, Any], raw_ml_features: Dict[str, float]) -> Tuple[float, str, List[str]]:
        """
        Calculates a contextual risk score (0.0 to 1.0).
        Returns: (final_risk_score, contextual_verdict, justification_list)
        """
        # Step 1: Base ML Risk (Mocked calculation based on our offline feature importance)
        # In production, this would be `model.predict_proba(features)`
        base_risk = self._calculate_mock_ml_risk(raw_ml_features)
        
        user = event.get('user', '')
        image = event.get('image', '')
        
        justifications = []
        final_risk = base_risk
        
        # Step 2: Check Dynamic Whitelist
        wl_eval = self.whitelists.evaluate_whitelist(event)
        if wl_eval['is_whitelisted']:
            reduction = wl_eval['confidence_reduction']
            final_risk = max(0.0, final_risk - reduction)
            justifications.append(f"Whitelisted: {wl_eval['suppression_reason']}")
            
        # Step 3: Check Role-Based Context
        if self.baselines.is_behavior_expected_for_role(user, image):
            final_risk = max(0.0, final_risk - 0.3)
            justifications.append(f"Context: Execution is expected for role {self.baselines.get_user_role(user)}")
        elif raw_ml_features.get('is_lolbin') == 1.0:
            # It's a LOLBin and NOT expected for this role!
            final_risk = min(1.0, final_risk + 0.4)
            justifications.append(f"Context: LOLBin executed by unexpected role {self.baselines.get_user_role(user)}")
            
        # Step 4: Check Historical Baseline Trust
        trust_score = self.baselines.get_historical_trust_score(user, image)
        if trust_score > 0.8:
            final_risk = max(0.0, final_risk - 0.2)
            justifications.append("Context: High historical trust (routine behavior)")
        elif trust_score == 0.0 and raw_ml_features.get('is_lolbin') == 1.0:
            final_risk = min(1.0, final_risk + 0.2)
            justifications.append("Context: First time seeing this behavior for this user")
            
        # Step 5: Absolute Critical Overrides (Things context cannot save)
        if raw_ml_features.get('office_child_process') == 1.0 and raw_ml_features.get('script_interpreter_spawn') == 1.0:
            final_risk = 1.0
            justifications.append("CRITICAL: Office document spawned script interpreter.")
            
        if raw_ml_features.get('lsass_access') == 1.0 and raw_ml_features.get('suspicious_access_right') == 1.0:
            final_risk = 1.0
            justifications.append("CRITICAL: Known credential dumping access right to LSASS.")

        # Determine Verdict
        if final_risk >= 0.8:
            verdict = "Malicious"
        elif final_risk >= 0.4:
            verdict = "Suspicious"
        else:
            verdict = "Normal"
            
        return final_risk, verdict, justifications
        
    def _calculate_mock_ml_risk(self, features: Dict[str, float]) -> float:
        """Mocks an ML model probability output based on feature weights."""
        risk = 0.0
        # Highly weighted features from our offline Random Forest
        if features.get('suspicious_process_path') == 1.0: risk += 0.4
        if features.get('is_lolbin') == 1.0: risk += 0.3
        if features.get('suspicious_parent_child') == 1.0: risk += 0.5
        if features.get('powershell_encoded') == 1.0: risk += 0.6
        if features.get('suspicious_port') == 1.0: risk += 0.4
        if features.get('dns_dga_likely') == 1.0: risk += 0.8
        
        return min(1.0, risk)
