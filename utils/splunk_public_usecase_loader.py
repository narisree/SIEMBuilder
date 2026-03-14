"""
Splunk Public Use Case Loader
Handles loading and parsing of Splunk public use cases from local Excel file.
Uses the Normalized_Sources column for accurate log source mapping.
"""

import pandas as pd
from pathlib import Path
from typing import Dict, List, Optional


class SplunkPublicUseCaseLoader:
    """Loads and manages Splunk public use cases from Splunk_Library_batch_final.xlsx."""
    
    # Mapping of app source slugs to canonical names in the Normalized_Sources column.
    # Each slug maps to one or more canonical names (pipe-delimited in the Excel column).
    # This is EXACT matching — no fuzzy logic.
    SLUG_TO_CANONICAL = {
        "palo_alto": ["Palo Alto"],
        "windows_events": ["Windows Security Events", "Windows System Events", "Windows Application Events", "Windows Other Event Logs"],
        "sysmon_windows": ["Sysmon"],
        "powershell_scriptblock": ["PowerShell Script Block Logging"],
        "linux": ["Linux Auditd"],
        "azure_ad": ["Azure AD"],
        "cisco_asa": ["Cisco ASA"],
        "checkpoint": ["Checkpoint"],
        "crowdstrike_edr": ["CrowdStrike"],
        "o365": ["Office 365"],
        "proofpoint": ["Proofpoint"],
        "zscaler_proxy": ["Zscaler Proxy"],
        # Phase 2+ sources (pre-registered for when KB guides are added)
        "sysmon_linux": ["Sysmon for Linux"],
        "aws_cloudtrail": ["AWS CloudTrail"],
        "okta": ["Okta"],
        "cisco_ftd": ["Cisco Secure Firewall"],
        "suricata": ["Suricata IDS"],
        "kubernetes": ["Kubernetes"],
        "vmware_esxi": ["VMware ESXi"],
        "github": ["GitHub"],
        "nginx": ["Nginx"],
        "cisco_duo": ["Cisco Duo"],
        "cisco_ios": ["Cisco IOS"],
        "google_workspace": ["Google Workspace"],
    }
    
    # Expected column names in the Excel file (with potential variations)
    COLUMN_MAPPINGS = {
        'name': ['Use case Name', 'Use Case Name', 'Name', 'Detection Name', 'name'],
        'description': ['Description', 'description', 'Desc'],
        'log_source': ['Log Source', 'Log_Source', 'LogSource', 'Data Source', 'log_source'],
        'mitre_tactics': ['MITRE Tactics', 'MITRE_Tactics', 'Tactics', 'mitre_tactics'],
        'mitre_technique': ['MITRE Technique', 'MITRE_Technique', 'Technique', 'mitre_technique'],
        'spl': ['SPL', 'SPL ', 'SPL Query', 'spl_query', 'Search', 'search'],
        'normalized_sources': ['Normalized_Sources', 'Normalized Sources', 'normalized_sources'],
    }
    
    def __init__(self, kb_path: str = "kb"):
        """Initialize the Splunk Public Use Case Loader."""
        self.kb_path = Path(kb_path)
        # Support both the new file name and legacy file name
        self.library_file = self.kb_path / "Splunk_Library_batch_final.xlsx"
        if not self.library_file.exists():
            self.library_file = self.kb_path / "Splunk_Library_with_L1_Guidance.xlsx"
        self._use_cases = []
        self._column_map = {}
        self._has_normalized = False
        self._load_use_cases()
    
    def _find_column(self, df: pd.DataFrame, column_key: str) -> Optional[str]:
        """Find the actual column name in the DataFrame for a given key."""
        possible_names = self.COLUMN_MAPPINGS.get(column_key, [])
        for name in possible_names:
            if name in df.columns:
                return name
        return None
    
    def _load_use_cases(self) -> None:
        """Load all use cases from the Excel file."""
        if not self.library_file.exists():
            return
        
        try:
            df = pd.read_excel(self.library_file)
            
            # Build column mapping
            for key in self.COLUMN_MAPPINGS.keys():
                actual_col = self._find_column(df, key)
                if actual_col:
                    self._column_map[key] = actual_col
            
            # Check if Normalized_Sources column exists
            self._has_normalized = 'normalized_sources' in self._column_map
            
            # Convert DataFrame to list of dictionaries
            for _, row in df.iterrows():
                use_case = {}
                
                use_case['Use case Name'] = self._get_value(row, 'name', '')
                use_case['Description'] = self._get_value(row, 'description', '')
                use_case['Log Source'] = self._get_value(row, 'log_source', '')
                use_case['MITRE Tactics'] = self._get_value(row, 'mitre_tactics', '')
                use_case['MITRE Technique'] = self._get_value(row, 'mitre_technique', '')
                use_case['SPL'] = self._get_value(row, 'spl', '')
                
                # Store normalized sources for exact matching
                if self._has_normalized:
                    use_case['_normalized_sources'] = self._get_value(row, 'normalized_sources', '')
                
                # Only add if we have at least a name
                if use_case['Use case Name']:
                    self._use_cases.append(use_case)
                    
        except Exception as e:
            print(f"Error loading Splunk public use cases: {e}")
    
    def _get_value(self, row: pd.Series, key: str, default: str = '') -> str:
        """Get a value from a row using the column mapping."""
        col_name = self._column_map.get(key)
        if col_name and col_name in row.index:
            value = row[col_name]
            if pd.isna(value):
                return default
            return str(value).strip()
        return default
    
    def get_use_cases_for_source(self, source_slug: str) -> List[Dict]:
        """
        Get all use cases for a specific log source.
        Uses Normalized_Sources column for exact matching when available,
        falls back to fuzzy Log Source matching for legacy files.
        """
        canonical_names = self.SLUG_TO_CANONICAL.get(source_slug, [])
        if not canonical_names:
            return []
        
        filtered_cases = []
        
        for use_case in self._use_cases:
            matched = False
            
            if self._has_normalized:
                # Exact matching on Normalized_Sources (pipe-delimited)
                normalized = use_case.get('_normalized_sources', '')
                if normalized:
                    source_list = [s.strip() for s in normalized.split('|')]
                    for canon_name in canonical_names:
                        if canon_name in source_list:
                            matched = True
                            break
            else:
                # Legacy fallback: fuzzy matching on Log Source column
                log_source = use_case.get('Log Source', '').strip().lower()
                for canon_name in canonical_names:
                    if canon_name.lower() in log_source or log_source in canon_name.lower():
                        matched = True
                        break
            
            if matched:
                filtered_cases.append(use_case)
        
        return filtered_cases
    
    def get_all_use_cases(self) -> List[Dict]:
        """Get all use cases."""
        return self._use_cases.copy()
    
    def get_total_count(self) -> int:
        """Get total count of use cases."""
        return len(self._use_cases)
    
    def get_count_for_source(self, source_slug: str) -> int:
        """Get count of use cases for a specific log source."""
        return len(self.get_use_cases_for_source(source_slug))
    
    def get_all_log_sources(self) -> List[str]:
        """Get all unique log sources from the library."""
        sources = set()
        for use_case in self._use_cases:
            source = use_case.get('Log Source', '').strip()
            if source:
                sources.add(source)
        return sorted(list(sources))
    
    def get_all_normalized_sources(self) -> List[str]:
        """Get all unique normalized source names from the library."""
        sources = set()
        for use_case in self._use_cases:
            normalized = use_case.get('_normalized_sources', '')
            if normalized:
                for s in normalized.split('|'):
                    s = s.strip()
                    if s:
                        sources.add(s)
        return sorted(list(sources))
    
    def search_use_cases(self, query: str, source_slug: Optional[str] = None) -> List[Dict]:
        """Search use cases by keyword."""
        query_lower = query.lower()
        
        if source_slug:
            use_cases = self.get_use_cases_for_source(source_slug)
        else:
            use_cases = self._use_cases
        
        results = []
        for use_case in use_cases:
            searchable_text = ' '.join([
                use_case.get('Use case Name', ''),
                use_case.get('Description', ''),
                use_case.get('MITRE Technique', ''),
                use_case.get('MITRE Tactics', '')
            ]).lower()
            
            if query_lower in searchable_text:
                results.append(use_case)
        
        return results
    
    def is_available(self) -> bool:
        """Check if the Excel file exists and use cases are loaded."""
        return len(self._use_cases) > 0
