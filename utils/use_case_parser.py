"""
Use Case Parser
Parses YAML use cases using Claude API.
"""

import json
from typing import Dict, List
from utils.claude_client import ClaudeClient


class UseCaseParser:
    """Parses use case YAML files using Claude."""
    
    def __init__(self, claude_api_key: str):
        self.claude = ClaudeClient(claude_api_key)
    
    def parse_batch(self, yaml_files: List[Dict]) -> List[Dict]:
        """Parse a batch of YAML files."""
        system_prompt = """You are a SIEM integration specialist expert in Splunk detection mappings.

Your task: Analyze Splunk detection YAMLs and map them to appropriate log sources.

Available log sources (use exact slugs):
- palo_alto: Palo Alto Firewall
- windows_events: Windows Events
- linux: Linux systems
- azure_ad: Azure AD / Microsoft Entra ID
- cisco_asa: Cisco ASA Firewall
- checkpoint: Check Point Firewall  
- crowdstrike_edr: CrowdStrike EDR
- o365: Office 365 / Microsoft 365
- proofpoint: Proofpoint Email Security
- zscaler_proxy: Zscaler Proxy

Mapping rules:
1. Use 'data_source' field if present
2. Use 'datamodel' from SPL search field:
   - Network_Traffic → palo_alto, cisco_asa, checkpoint
   - Endpoint → windows_events, crowdstrike_edr, linux
   - Web → zscaler_proxy
   - Authentication → azure_ad, windows_events, o365
   - Email → proofpoint, o365

Output format (JSON array):
{
  "detection_id": "from id field",
  "name": "from name field",
  "mapped_sources": ["source_slug1", "source_slug2"],
  "mitre_technique": "from tags.mitre_attack_id",
  "mitre_tactics": "from tags (tactic names)",
  "description": "from description field",
  "spl_query": "from search field",
  "L1_What_It_Detects": "2-3 sentence explanation for L1 analysts",
  "L1_Validation_Steps": [
    "Step 1: Specific validation action",
    "Step 2: Another step",
    "Step 3: Another step",
    "Step 4: Another step",
    "Step 5: Another step",
    "Step 6: Escalation criteria"
  ]
}

Return ONLY valid JSON array."""
        
        yaml_texts = []
        for item in yaml_files:
            yaml_texts.append(f"---\nFile: {item['path']}\n{item['content']}\n")
        
        combined_yaml = "\n".join(yaml_texts)
        
        prompt = f"""Analyze these {len(yaml_files)} detection(s) and return JSON array:

{combined_yaml}

Remember: Return ONLY the JSON array, no markdown formatting."""
        
        messages = [{"role": "user", "content": prompt}]
        
        response = self.claude.client.messages.create(
            model=self.claude.model,
            max_tokens=8000,
            system=system_prompt,
            messages=messages
        )
        
        response_text = response.content[0].text.strip()
        
        if response_text.startswith("```json"):
            response_text = response_text[7:]
        if response_text.startswith("```"):
            response_text = response_text[3:]
        if response_text.endswith("```"):
            response_text = response_text[:-3]
        response_text = response_text.strip()
        
        try:
            parsed = json.loads(response_text)
            return parsed if isinstance(parsed, list) else [parsed]
        except:
            return []
