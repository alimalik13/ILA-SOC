import json
import sqlite3
from collections import defaultdict
from typing import Dict, Any, List

class ContextualBaselineEngine:
    """
    Learns and maintains stateful baselines for Users, Hosts, and Roles.
    In a real deployment, this would be backed by Redis or an active database.
    """
    def __init__(self, db_path: str = None):
        # We will use simple in-memory dictionaries for this passive implementation
        # Mappings: role -> set(expected_behaviors)
        self.role_baselines = {
            'IT_ADMIN': {'powershell.exe', 'cmd.exe', 'wmic.exe', 'mmc.exe', 'ping.exe'},
            'DEVELOPER': {'git.exe', 'python.exe', 'code.exe', 'node.exe', 'docker.exe', 'cmd.exe', 'powershell.exe'},
            'HR_USER': {'winword.exe', 'excel.exe', 'chrome.exe', 'msedge.exe'},
            'FINANCE_USER': {'excel.exe', 'chrome.exe', 'msedge.exe', 'calc.exe'}
        }
        
        # User -> Role mapping (Mocked for demonstration)
        self.user_roles = {
            'acme\\admin_john': 'IT_ADMIN',
            'acme\\dev_sarah': 'DEVELOPER',
            'acme\\hr_michael': 'HR_USER',
            'acme\\fin_jessica': 'FINANCE_USER'
        }
        
        # Host -> Role mapping
        self.host_baselines = {
            'WS-DEV-01': 'DEVELOPER',
            'SRV-DC-01': 'IT_ADMIN'
        }
        
        # Dynamic baselines learned over time
        # Maps user -> dict of observed counts
        self.learned_user_baselines = defaultdict(lambda: defaultdict(int))
        self.learned_chain_baselines = defaultdict(int)

    def observe_event(self, user: str, host: str, image: str, parent_image: str):
        """Passively learns what is 'normal' for a user and host over time."""
        user_lower = user.lower()
        image_name = image.split('\\')[-1].lower()
        parent_name = parent_image.split('\\')[-1].lower() if parent_image else "none"
        
        self.learned_user_baselines[user_lower][image_name] += 1
        chain_str = f"{parent_name}->{image_name}"
        self.learned_chain_baselines[chain_str] += 1

    def get_user_role(self, user: str) -> str:
        return self.user_roles.get(user.lower(), 'UNKNOWN')

    def is_behavior_expected_for_role(self, user: str, image: str) -> bool:
        """Returns True if the executed binary is expected for the user's role."""
        role = self.get_user_role(user)
        if role == 'UNKNOWN':
            return False
            
        image_name = image.split('\\')[-1].lower()
        return image_name in self.role_baselines.get(role, set())

    def get_historical_trust_score(self, user: str, image: str) -> float:
        """
        Returns a score from 0.0 to 1.0 representing how 'normal' this is for the user 
        based on past passive observations.
        """
        user_lower = user.lower()
        image_name = image.split('\\')[-1].lower()
        
        observations = self.learned_user_baselines[user_lower][image_name]
        
        if observations > 100:
            return 1.0 # Highly trusted routine behavior
        elif observations > 10:
            return 0.8
        elif observations > 0:
            return 0.5
        else:
            return 0.0 # First time seeing this
