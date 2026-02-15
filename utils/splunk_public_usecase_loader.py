"""
Splunk Public Use Case Loader
Handles loading and parsing of Splunk public use cases from local Excel file.
"""

import pandas as pd
from pathlib import Path
from typing import Dict, List, Optional


class SplunkPublicUseCaseLoader:
    """Loads and manages Splunk public use cases from Splunk_Library_with_L1_Guidance.xlsx."""
    
    # Mapping of log source slugs to names in the Excel file
    LOG_SOURCE_MAPPING = {
        "palo_alto": ["Palo Alto", "Palo Alto Firewall", "pan:traffic", "pan:threat"],
        "windows_events": ["Windows", "Windows Events", "Windows Event", "WinEventLog", "XmlWinEventLog"],
        "linux": ["Linux", "Linux Auditd", "linux_audit", "syslog"],
        "azure_ad": ["Azure AD", "Azure Active Directory", "AzureAD", "Entra", "Microsoft Entra"],
        "cisco_asa": ["Cisco ASA", "Cisco Secure Firewall", "cisco:asa"],
        "checkpoint": ["Checkpoint", "Checkpoint Firewall", "Check Point"],
        "crowdstrike_edr": ["Crowdstrike", "CrowdStrike", "Crowdstrike EDR", "CrowdStrike Falcon"],
        "o365": ["O365", "Office 365", "Microsoft 365", "ms:o365"],
        "proofpoint": ["Proofpoint"],
        "zscaler_proxy": ["Zscaler", "Zscaler Proxy"]
    }
    
    # Expected column names in the Excel file (with potential variations)
    COLUMN_MAPPINGS = {
        'name': ['Use case Name', 'Use Case Name', 'Name', 'Detection Name', 'name'],
        'description': ['Description', 'description', 'Desc'],
        'log_source': ['Log Source', 'Log_Source', 'LogSource', 'Data Source', 'log_source'],
        'mitre_tactics': ['MITRE Tactics', 'MITRE_Tactics', 'Tactics', 'mitre_tactics'],
        'mitre_technique': ['MITRE Technique', 'MITRE_Technique', 'Technique', 'mitre_technique'],
        'spl': ['SPL', 'SPL ', 'SPL Query', 'spl_query', 'Search', 'search'],
        'l1_what_it_detects': ['L1_What_It_Detects', 'What It Detects', 'L1 What It Detects', 'what_it_detects'],
        'l1_validation_steps': ['L1_Validation_Steps', 'Validation Steps', 'L1 Validation Steps', 'validation_steps']
    }
    
    def __init__(self, kb_path: str = "kb"):
        """Initialize the Splunk Public Use Case Loader."""
        self.kb_path = Path(kb_path)
        self.library_file = self.kb_path / "Splunk_Library_with_L1_Guidance.xlsx"
        self._use_cases = []
        self._column_map = {}
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
            print(f"Warning: Excel file not found at {self.library_file}")
            return
        
        try:
            # Read the Excel file
            df = pd.read_excel(self.library_file)
            
            # Build column mapping
            for key in self.COLUMN_MAPPINGS.keys():
                actual_col = self._find_column(df, key)
                if actual_col:
                    self._column_map[key] = actual_col
            
            # Convert DataFrame to list of dictionaries
            for _, row in df.iterrows():
                use_case = {}
                
                # Map standard fields - use same keys as Internal Library for consistency
                use_case['Use case Name'] = self._get_value(row, 'name', '')
                use_case['Description'] = self._get_value(row, 'description', '')
                use_case['Log Source'] = self._get_value(row, 'log_source', '')
                use_case['MITRE Tactics'] = self._get_value(row, 'mitre_tactics', '')
                use_case['MITRE Technique'] = self._get_value(row, 'mitre_technique', '')
                use_case['SPL'] = self._get_value(row, 'spl', '')
                use_case['L1_What_It_Detects'] = self._get_value(row, 'l1_what_it_detects', '')
                
                # Handle validation steps - could be a string with newlines or a list
                validation_steps = self._get_value(row, 'l1_validation_steps', '')
                use_case['L1_Validation_Steps'] = self._parse_validation_steps(validation_steps)
                
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
            # Handle NaN values
            if pd.isna(value):
                return default
            return str(value).strip()
        return default
    
    def _parse_validation_steps(self, steps_value) -> List[str]:
        """Parse validation steps from various formats."""
        if pd.isna(steps_value) or not steps_value:
            return []
        
        steps_str = str(steps_value).strip()
        
        if not steps_str:
            return []
        
        # Try parsing as a list if it looks like JSON/Python list
        if steps_str.startswith('[') and steps_str.endswith(']'):
            try:
                import ast
                parsed = ast.literal_eval(steps_str)
                if isinstance(parsed, list):
                    return [str(s).strip() for s in parsed if s]
            except:
                pass
        
        # Split by newlines or numbered patterns
        lines = []
        
        # First try splitting by newlines
        if '\n' in steps_str:
            lines = steps_str.split('\n')
        # Try splitting by numbered patterns like "1." or "1)"
        elif any(f"{i}." in steps_str or f"{i})" in steps_str for i in range(1, 10)):
            import re
            lines = re.split(r'\d+[\.\)]\s*', steps_str)
        else:
            # Single line - return as single item
            lines = [steps_str]
        
        # Clean up the lines
        result = []
        for line in lines:
            cleaned = line.strip()
            # Remove leading numbers/bullets
            import re
            cleaned = re.sub(r'^[\d\.\)\-\*]+\s*', '', cleaned)
            if cleaned:
                result.append(cleaned)
        
        return result
    
    def get_use_cases_for_source(self, source_slug: str) -> List[Dict]:
        """Get all use cases for a specific log source."""
        matching_names = self.LOG_SOURCE_MAPPING.get(source_slug, [])
        
        if not matching_names:
            return []
        
        filtered_cases = []
        for use_case in self._use_cases:
            log_source = use_case.get('Log Source', '').strip()
            
            # Check if the log source matches any of the mapping names
            matched = False
            for name in matching_names:
                if name.lower() in log_source.lower() or log_source.lower() in name.lower():
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
    
    def search_use_cases(self, query: str, source_slug: Optional[str] = None) -> List[Dict]:
        """Search use cases by keyword."""
        query_lower = query.lower()
        
        if source_slug:
            use_cases = self.get_use_cases_for_source(source_slug)
        else:
            use_cases = self._use_cases
        
        results = []
        for use_case in use_cases:
            # Search in name, description, and technique
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
