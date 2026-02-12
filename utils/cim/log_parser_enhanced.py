"""
Enhanced Log Parser with Vendor Schema Support
Uses learned vendor schemas for accurate field extraction, especially for positional formats.
Falls back to structural parsing if vendor schema not available.
"""

import csv
import json
import re
from io import StringIO
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum


class LogFormat(Enum):
    """Supported log formats."""
    JSON = "json"
    XML = "xml"
    KEY_VALUE = "key_value"
    SYSLOG = "syslog"
    CEF = "cef"
    LEEF = "leef"
    CSV = "csv"
    UNKNOWN = "unknown"


@dataclass
class ParsedLog:
    """Result of log parsing."""
    format: LogFormat
    fields: Dict[str, List[str]] = field(default_factory=dict)
    field_positions: Dict[str, int] = field(default_factory=dict)
    sample_events: List[str] = field(default_factory=list)
    raw_headers: List[str] = field(default_factory=list)
    vendor: Optional[str] = None
    product: Optional[str] = None
    confidence: float = 0.0
    has_header: bool = True
    schema_used: bool = False  # NEW: indicates if vendor schema was used


class VendorAwareLogParser:
    """
    Enhanced parser that uses vendor schemas for accurate field extraction.
    Falls back to structural parsing if vendor schema not available.
    """
    
    def __init__(self):
        """Initialize the parser."""
        self.cef_pattern = re.compile(r'^CEF:\d+\|')
        self.leef_pattern = re.compile(r'^LEEF:\d+\.\d+\|')
        self.syslog_pattern = re.compile(
            r'^(?:<\d+>)?(?:\d )?(?:\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})'
        )
        self.kv_pattern = re.compile(r'(\w+)=["\']?([^"\'\s,]+)["\']?')
    
    def parse_with_vendor_schema(
        self,
        content: bytes,
        filename: str,
        vendor_schema
    ) -> ParsedLog:
        """
        Parse logs using learned vendor schema for accurate field names.
        
        Args:
            content: Log file content
            filename: Original filename
            vendor_schema: VendorLogSchema object from vendor_schema_learner
            
        Returns:
            ParsedLog with vendor-accurate field names
        """
        try:
            text = content.decode('utf-8', errors='ignore')
        except Exception:
            text = content.decode('latin-1', errors='ignore')
        
        lines = [l.strip() for l in text.split('\n') if l.strip()]
        
        if vendor_schema.format_type == 'csv' or vendor_schema.format_type == 'positional_csv':
            return self._parse_with_csv_schema(lines, vendor_schema)
        elif vendor_schema.format_type == 'json':
            return self._parse_with_json_schema(lines, vendor_schema)
        elif vendor_schema.format_type == 'syslog':
            return self._parse_with_syslog_schema(lines, vendor_schema)
        else:
            # Fallback to structural parsing
            from utils.cim.log_parser import LogParser
            parser = LogParser()
            return parser.parse_file(content, filename)
    
    def _parse_with_csv_schema(self, lines: List[str], schema) -> ParsedLog:
        """Parse CSV logs using vendor field schema."""
        result = ParsedLog(
            format=LogFormat.CSV,
            vendor=schema.vendor,
            product=schema.product,
            confidence=0.95,  # High confidence with vendor schema
            schema_used=True
        )
        
        fields = {}
        delimiter = schema.delimiter or ','
        
        # Create field name mapping from schema
        field_map = {f.position: f.name for f in schema.fields if f.position is not None}
        
        try:
            reader = csv.reader(StringIO('\n'.join(lines)), delimiter=delimiter)
            rows = list(reader)
            
            # Determine if first row is header
            has_header = False
            if rows and rows[0]:
                # Check if first row matches schema field names
                first_row_lower = [cell.lower().strip() for cell in rows[0]]
                schema_names_lower = [f.name.lower() for f in schema.fields]
                
                # If >50% match, it's likely a header
                matches = sum(1 for cell in first_row_lower if cell in schema_names_lower)
                has_header = matches > len(first_row_lower) * 0.5
            
            start_row = 1 if has_header else 0
            result.has_header = has_header
            
            # Initialize fields from schema
            for field_def in schema.fields:
                if field_def.name:
                    fields[field_def.name] = []
            
            # Parse data rows using schema positions
            for row in rows[start_row:min(start_row + 100, len(rows))]:  # Sample up to 100 rows
                for field_def in schema.fields:
                    if field_def.position is not None and field_def.position < len(row):
                        value = row[field_def.position].strip()
                        if field_def.name in fields:
                            fields[field_def.name].append(value)
            
            result.fields = fields
            result.sample_events = lines[:5]
            
            return result
            
        except Exception as e:
            print(f"CSV schema parsing error: {e}")
            # Fallback to basic CSV parsing
            from utils.cim.log_parser import LogParser
            parser = LogParser()
            return parser._parse_csv(lines)
    
    def _parse_with_json_schema(self, lines: List[str], schema) -> ParsedLog:
        """Parse JSON logs using vendor field schema."""
        result = ParsedLog(
            format=LogFormat.JSON,
            vendor=schema.vendor,
            product=schema.product,
            confidence=0.95,
            schema_used=True
        )
        
        fields = {}
        
        # Initialize fields from schema
        for field_def in schema.fields:
            fields[field_def.name] = []
        
        for line in lines[:100]:
            try:
                obj = json.loads(line)
                
                # Extract fields using schema paths
                for field_def in schema.fields:
                    value = self._extract_json_path(obj, field_def.name)
                    if value is not None:
                        fields[field_def.name].append(str(value))
                        
            except json.JSONDecodeError:
                continue
        
        result.fields = fields
        result.sample_events = lines[:5]
        return result
    
    def _extract_json_path(self, obj: dict, path: str) -> any:
        """Extract value from nested JSON using dot notation path."""
        parts = path.split('.')
        current = obj
        
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        
        return current
    
    def _parse_with_syslog_schema(self, lines: List[str], schema) -> ParsedLog:
        """Parse syslog using vendor schema patterns."""
        # Use standard syslog parsing first
        from utils.cim.log_parser import LogParser
        parser = LogParser()
        result = parser._parse_syslog(lines)
        result.vendor = schema.vendor
        result.product = schema.product
        result.confidence = 0.8
        result.schema_used = True
        
        return result


def create_vendor_aware_parser() -> VendorAwareLogParser:
    """Factory function to create vendor-aware parser."""
    return VendorAwareLogParser()
