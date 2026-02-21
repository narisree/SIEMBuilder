"""
IRP Loader
Handles loading and serving Incident Response Playbook markdown files.
"""

from pathlib import Path
from typing import Dict, List, Optional


class IRPLoader:
    """Loads and manages Incident Response Playbooks from the Playbooks directory."""
    
    # Catalog of available IRPs
    IRP_CATALOG = {
        "IRP-Phishing": {
            "display_name": "Phishing",
            "filename": "IRP-Phishing.md",
            "icon": "🎣",
            "description": "Email-based attacks, spear phishing, BEC, credential harvesting"
        },
        "IRP-AccountCompromised": {
            "display_name": "Account Compromise",
            "filename": "IRP-AccountCompromised.md",
            "icon": "🔓",
            "description": "Credential theft, brute force, MFA bypass, session hijacking"
        },
        "IRP-Malware": {
            "display_name": "Malware",
            "filename": "IRP-Malware.md",
            "icon": "🦠",
            "description": "Trojans, RATs, C2 agents, infostealers, fileless malware"
        },
        "IRP-Ransom": {
            "display_name": "Ransomware",
            "filename": "IRP-Ransom.md",
            "icon": "💀",
            "description": "Ransomware encryption, double extortion, data extortion"
        },
        "IRP-DataLoss": {
            "display_name": "Data Loss",
            "filename": "IRP-DataLoss.md",
            "icon": "📤",
            "description": "Data exfiltration, insider threat, accidental exposure, device loss"
        }
    }
    
    # Mapping from MITRE tactics to relevant IRPs (used by Layer 2 escalation)
    TACTIC_TO_IRP = {
        "Initial Access": ["IRP-Phishing"],
        "Credential Access": ["IRP-AccountCompromised"],
        "Persistence": ["IRP-AccountCompromised", "IRP-Malware"],
        "Privilege Escalation": ["IRP-AccountCompromised"],
        "Lateral Movement": ["IRP-AccountCompromised", "IRP-Malware"],
        "Execution": ["IRP-Malware"],
        "Defense Evasion": ["IRP-Malware"],
        "Command and Control": ["IRP-Malware"],
        "Command And Control": ["IRP-Malware"],
        "Exfiltration": ["IRP-DataLoss"],
        "Collection": ["IRP-DataLoss"],
        "Impact": ["IRP-Ransom", "IRP-DataLoss"],
    }
    
    def __init__(self, playbooks_path: str = "Playbooks"):
        """Initialize the IRP Loader."""
        self.playbooks_path = Path(playbooks_path)
    
    def get_available_irps(self) -> Dict:
        """Return the catalog of available IRPs."""
        return self.IRP_CATALOG
    
    def load_irp_content(self, irp_key: str) -> Optional[str]:
        """
        Load the markdown content for a specific IRP.
        
        Args:
            irp_key: Key from IRP_CATALOG (e.g., 'IRP-Phishing')
            
        Returns:
            Markdown content string, or None if not found
        """
        irp_info = self.IRP_CATALOG.get(irp_key)
        if not irp_info:
            return None
        
        filepath = self.playbooks_path / irp_info["filename"]
        try:
            if filepath.exists():
                with open(filepath, 'r', encoding='utf-8') as f:
                    return f.read()
            return None
        except Exception:
            return None
    
    def get_irps_for_tactic(self, tactic: str) -> List[str]:
        """
        Get relevant IRP keys for a given MITRE tactic.
        
        Args:
            tactic: MITRE ATT&CK tactic name (e.g., 'Credential Access')
            
        Returns:
            List of IRP keys that are relevant
        """
        # Direct match
        if tactic in self.TACTIC_TO_IRP:
            return self.TACTIC_TO_IRP[tactic]
        
        # Fuzzy match - check if tactic string contains any known tactic
        results = []
        tactic_lower = tactic.lower()
        for known_tactic, irp_keys in self.TACTIC_TO_IRP.items():
            if known_tactic.lower() in tactic_lower:
                results.extend(irp_keys)
        
        # Deduplicate while preserving order
        seen = set()
        unique = []
        for k in results:
            if k not in seen:
                seen.add(k)
                unique.append(k)
        return unique
    
    def get_irps_for_use_case(self, use_case: Dict) -> List[Dict]:
        """
        Get relevant IRPs for a use case based on its MITRE tactics.
        
        Args:
            use_case: Dictionary with at minimum 'MITRE Tactics' key
            
        Returns:
            List of dicts with 'key', 'display_name', 'icon' for each relevant IRP
        """
        tactics = use_case.get('MITRE Tactics', '')
        irp_keys = self.get_irps_for_tactic(tactics)
        
        result = []
        for key in irp_keys:
            info = self.IRP_CATALOG.get(key, {})
            result.append({
                "key": key,
                "display_name": info.get("display_name", key),
                "icon": info.get("icon", "📋")
            })
        return result
