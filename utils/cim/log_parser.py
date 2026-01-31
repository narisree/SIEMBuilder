"""
Log Parser Module
Detects log format and extracts fields from various log formats.
Properly handles CSV with headers, ensuring field NAMES are extracted, not values.
"""
import re
import json
import csv
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
    field_positions: Dict[str, int] = field(default_factory=dict)  # Field name to CSV column position
    sample_events: List[str] = field(default_factory=list)
    raw_headers: List[str] = field(default_factory=list)  # Original CSV headers
    vendor: Optional[str] = None
    product: Optional[str] = None
    confidence: float = 0.0
    has_header: bool = True  # Whether CSV has a header row


class LogParser:
    """Intelligent log format detection and field extraction."""
    
    def __init__(self):
        self.cef_pattern = re.compile(r'^CEF:\d+\|')
        self.leef_pattern = re.compile(r'^LEEF:\d+\.\d+\|')
        self.syslog_pattern = re.compile(
            r'^(?:<\d+>)?(?:\d )?(?:\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})'
        )
        self.kv_pattern = re.compile(r'(\w+)=["\']?([^"\'\s,]+)["\']?')
    
    def parse_file(self, content: bytes, filename: str = "") -> ParsedLog:
        """Parse uploaded file content and detect format."""
        try:
            text = content.decode('utf-8', errors='ignore')
        except Exception:
            text = content.decode('latin-1', errors='ignore')
        
        lines = [l.strip() for l in text.split('\n') if l.strip()]
        if not lines:
            return ParsedLog(format=LogFormat.UNKNOWN, confidence=0.0)
        
        # Detect format based on content
        format_type, confidence = self._detect_format(lines, filename)
        
        # Parse based on detected format
        result = self._parse_by_format(lines, format_type)
        result.confidence = confidence
        result.sample_events = lines[:5]  # Keep first 5 as samples
        
        return result
    
    def _detect_format(self, lines: List[str], filename: str) -> Tuple[LogFormat, float]:
        """Detect log format with confidence score."""
        first_line = lines[0]
        
        # Check file extension first
        if filename.lower().endswith('.json'):
            return LogFormat.JSON, 0.9
        elif filename.lower().endswith('.csv'):
            return LogFormat.CSV, 0.9
        elif filename.lower().endswith('.xml'):
            return LogFormat.XML, 0.9
        
        # Try JSON
        try:
            json.loads(first_line)
            return LogFormat.JSON, 0.95
        except json.JSONDecodeError:
            pass
        
        # Check for JSON array
        if first_line.startswith('['):
            try:
                json.loads('\n'.join(lines))
                return LogFormat.JSON, 0.9
            except json.JSONDecodeError:
                pass
        
        # Check CEF
        if self.cef_pattern.match(first_line):
            return LogFormat.CEF, 0.95
        
        # Check LEEF
        if self.leef_pattern.match(first_line):
            return LogFormat.LEEF, 0.95
        
        # Check XML
        if first_line.startswith('<?xml') or first_line.startswith('<'):
            return LogFormat.XML, 0.85
        
        # Check CSV (has commas and consistent field count)
        if ',' in first_line:
            try:
                reader = csv.reader(StringIO('\n'.join(lines[:10])))
                rows = list(reader)
                if len(rows) > 1:
                    field_counts = [len(row) for row in rows]
                    if len(set(field_counts)) <= 2 and field_counts[0] > 3:
                        return LogFormat.CSV, 0.8
            except csv.Error:
                pass
        
        # Check Key-Value
        kv_matches = self.kv_pattern.findall(first_line)
        if len(kv_matches) >= 3:
            return LogFormat.KEY_VALUE, 0.8
        
        # Check Syslog
        if self.syslog_pattern.match(first_line):
            return LogFormat.SYSLOG, 0.7
        
        return LogFormat.UNKNOWN, 0.3
    
    def _parse_by_format(self, lines: List[str], format_type: LogFormat) -> ParsedLog:
        """Parse lines based on detected format."""
        if format_type == LogFormat.JSON:
            return self._parse_json(lines)
        elif format_type == LogFormat.CSV:
            return self._parse_csv(lines)
        elif format_type == LogFormat.CEF:
            return self._parse_cef(lines)
        elif format_type == LogFormat.LEEF:
            return self._parse_leef(lines)
        elif format_type == LogFormat.XML:
            return self._parse_xml(lines)
        elif format_type == LogFormat.KEY_VALUE:
            return self._parse_key_value(lines)
        elif format_type == LogFormat.SYSLOG:
            return self._parse_syslog(lines)
        else:
            return self._parse_generic(lines)
    
    def _parse_json(self, lines: List[str]) -> ParsedLog:
        """Parse JSON logs."""
        result = ParsedLog(format=LogFormat.JSON)
        fields = {}
        
        for line in lines[:100]:
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    self._extract_json_fields(obj, fields, prefix="")
            except json.JSONDecodeError:
                continue
        
        # Try parsing as JSON array
        if not fields:
            try:
                data = json.loads('\n'.join(lines))
                if isinstance(data, list):
                    for item in data[:100]:
                        if isinstance(item, dict):
                            self._extract_json_fields(item, fields, prefix="")
            except json.JSONDecodeError:
                pass
        
        result.fields = fields
        return result
    
    def _extract_json_fields(self, obj: dict, fields: dict, prefix: str = ""):
        """Recursively extract fields from JSON object."""
        for key, value in obj.items():
            field_name = f"{prefix}{key}" if prefix else key
            
            if isinstance(value, dict):
                self._extract_json_fields(value, fields, f"{field_name}.")
            elif isinstance(value, list):
                if value and not isinstance(value[0], (dict, list)):
                    if field_name not in fields:
                        fields[field_name] = []
                    fields[field_name].extend([str(v) for v in value[:5]])
            else:
                if field_name not in fields:
                    fields[field_name] = []
                fields[field_name].append(str(value) if value is not None else "")
    
    def _parse_csv(self, lines: List[str]) -> ParsedLog:
        """Parse CSV logs - properly extracting field NAMES from header row."""
        result = ParsedLog(format=LogFormat.CSV)
        fields = {}
        field_positions = {}
        
        try:
            reader = csv.reader(StringIO('\n'.join(lines)))
            rows = list(reader)
            
            if len(rows) > 0:
                # First row is header - these are the FIELD NAMES
                raw_headers = rows[0]
                result.raw_headers = raw_headers
                result.has_header = True
                
                # Check if first row looks like a header (not all numeric/IP-like values)
                header_looks_valid = self._validate_header_row(raw_headers)
                
                if header_looks_valid and len(rows) > 1:
                    # Process headers to create clean field names
                    for i, header in enumerate(raw_headers):
                        # Clean up header name
                        clean_header = self._clean_field_name(header)
                        if clean_header:
                            field_positions[clean_header] = i
                            fields[clean_header] = []
                            
                            # Collect sample values from data rows
                            for row in rows[1:min(51, len(rows))]:  # Sample up to 50 data rows
                                if i < len(row):
                                    fields[clean_header].append(row[i].strip())
                else:
                    # No valid header - generate generic field names
                    result.has_header = False
                    num_cols = len(rows[0])
                    for i in range(num_cols):
                        field_name = f"field{i+1}"
                        field_positions[field_name] = i
                        fields[field_name] = []
                        for row in rows[:50]:
                            if i < len(row):
                                fields[field_name].append(row[i].strip())
        
        except csv.Error as e:
            # Fallback for malformed CSV
            pass
        
        result.fields = fields
        result.field_positions = field_positions
        return result
    
    def _validate_header_row(self, headers: List[str]) -> bool:
        """Check if a row looks like a header row (field names) vs data row."""
        if not headers:
            return False
        
        # Patterns that suggest this is data, not headers
        ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        date_pattern = re.compile(r'^\d{4}[-/]\d{2}[-/]\d{2}')
        pure_number = re.compile(r'^\d+$')
        
        data_like_count = 0
        for h in headers:
            h = h.strip()
            if ip_pattern.match(h) or date_pattern.match(h) or pure_number.match(h):
                data_like_count += 1
            # Also check for very long values (unlikely to be field names)
            if len(h) > 50:
                data_like_count += 1
        
        # If more than 30% look like data values, probably not a header row
        return data_like_count / len(headers) < 0.3
    
    def _clean_field_name(self, header: str) -> str:
        """Clean a CSV header to create a valid field name."""
        if not header:
            return ""
        
        # Strip whitespace
        name = header.strip()
        
        # Remove surrounding quotes
        if (name.startswith('"') and name.endswith('"')) or \
           (name.startswith("'") and name.endswith("'")):
            name = name[1:-1]
        
        # Replace spaces and special chars with underscores
        name = re.sub(r'[^\w]', '_', name)
        
        # Remove leading/trailing underscores
        name = name.strip('_')
        
        # Collapse multiple underscores
        name = re.sub(r'_+', '_', name)
        
        # Convert to lowercase for consistency
        name = name.lower()
        
        return name
    
    def _parse_cef(self, lines: List[str]) -> ParsedLog:
        """Parse CEF (Common Event Format) logs."""
        result = ParsedLog(format=LogFormat.CEF)
        fields = {}
        
        for line in lines[:100]:
            if not self.cef_pattern.match(line):
                continue
            
            # Parse CEF header: CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|Extension
            parts = line.split('|', 7)
            if len(parts) >= 7:
                if result.vendor is None:
                    result.vendor = parts[1]
                    result.product = parts[2]
                
                # Add header fields
                header_fields = ['cef_version', 'device_vendor', 'device_product', 
                               'device_version', 'signature_id', 'name', 'severity']
                for i, fname in enumerate(header_fields):
                    if fname not in fields:
                        fields[fname] = []
                    if i < len(parts):
                        value = parts[i].replace('CEF:', '') if i == 0 else parts[i]
                        fields[fname].append(value)
                
                # Parse extension (key=value pairs)
                if len(parts) > 7:
                    extension = parts[7]
                    kv_pairs = self._parse_cef_extension(extension)
                    for k, v in kv_pairs.items():
                        if k not in fields:
                            fields[k] = []
                        fields[k].append(v)
        
        result.fields = fields
        return result
    
    def _parse_cef_extension(self, extension: str) -> Dict[str, str]:
        """Parse CEF extension field."""
        result = {}
        # CEF extension format: key=value key2=value2
        pattern = re.compile(r'(\w+)=((?:[^=](?!(?:\s\w+=)))*)')
        matches = pattern.findall(extension)
        for key, value in matches:
            result[key.strip()] = value.strip()
        return result
    
    def _parse_leef(self, lines: List[str]) -> ParsedLog:
        """Parse LEEF (Log Event Extended Format) logs."""
        result = ParsedLog(format=LogFormat.LEEF)
        fields = {}
        
        for line in lines[:100]:
            if not self.leef_pattern.match(line):
                continue
            
            # Parse LEEF header: LEEF:Version|Vendor|Product|Version|EventID|
            parts = line.split('|', 5)
            if len(parts) >= 5:
                if result.vendor is None:
                    result.vendor = parts[1]
                    result.product = parts[2]
                
                header_fields = ['leef_version', 'vendor', 'product', 'version', 'event_id']
                for i, fname in enumerate(header_fields):
                    if fname not in fields:
                        fields[fname] = []
                    if i < len(parts):
                        value = parts[i].replace('LEEF:', '') if i == 0 else parts[i]
                        fields[fname].append(value)
                
                # Parse extension (tab or custom delimiter separated key=value)
                if len(parts) > 5:
                    extension = parts[5]
                    # Check for delimiter definition
                    if extension.startswith('devTime=') or '\t' in extension:
                        kv_pairs = self.kv_pattern.findall(extension)
                        for k, v in kv_pairs:
                            if k not in fields:
                                fields[k] = []
                            fields[k].append(v)
        
        result.fields = fields
        return result
    
    def _parse_xml(self, lines: List[str]) -> ParsedLog:
        """Parse XML logs."""
        result = ParsedLog(format=LogFormat.XML)
        fields = {}
        
        # Simple XML parsing using regex (avoiding full XML parser for robustness)
        content = '\n'.join(lines)
        tag_pattern = re.compile(r'<(\w+)[^>]*>([^<]+)</\1>')
        attr_pattern = re.compile(r'(\w+)=["\']([^"\']+)["\']')
        
        for match in tag_pattern.finditer(content):
            tag_name, tag_value = match.groups()
            if tag_name not in fields:
                fields[tag_name] = []
            fields[tag_name].append(tag_value.strip())
        
        for match in attr_pattern.finditer(content):
            attr_name, attr_value = match.groups()
            if attr_name not in fields:
                fields[attr_name] = []
            fields[attr_name].append(attr_value)
        
        result.fields = fields
        return result
    
    def _parse_key_value(self, lines: List[str]) -> ParsedLog:
        """Parse key-value format logs."""
        result = ParsedLog(format=LogFormat.KEY_VALUE)
        fields = {}
        
        for line in lines[:100]:
            matches = self.kv_pattern.findall(line)
            for key, value in matches:
                if key not in fields:
                    fields[key] = []
                fields[key].append(value)
        
        result.fields = fields
        return result
    
    def _parse_syslog(self, lines: List[str]) -> ParsedLog:
        """Parse syslog format logs."""
        result = ParsedLog(format=LogFormat.SYSLOG)
        fields = {
            'timestamp': [],
            'hostname': [],
            'program': [],
            'message': []
        }
        
        syslog_re = re.compile(
            r'^(?:<(\d+)>)?(?:(\d) )?(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^\s]*)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$'
        )
        
        for line in lines[:100]:
            match = syslog_re.match(line)
            if match:
                groups = match.groups()
                fields['timestamp'].append(groups[2] or '')
                fields['hostname'].append(groups[3] or '')
                fields['program'].append(groups[4] or '')
                fields['message'].append(groups[6] or '')
                
                # Try to parse key-value pairs in message
                kv_matches = self.kv_pattern.findall(groups[6] or '')
                for k, v in kv_matches:
                    if k not in fields:
                        fields[k] = []
                    fields[k].append(v)
        
        result.fields = fields
        return result
    
    def _parse_generic(self, lines: List[str]) -> ParsedLog:
        """Generic parsing for unknown formats."""
        result = ParsedLog(format=LogFormat.UNKNOWN)
        fields = {}
        
        # Try key-value extraction
        for line in lines[:100]:
            kv_matches = self.kv_pattern.findall(line)
            for k, v in kv_matches:
                if k not in fields:
                    fields[k] = []
                fields[k].append(v)
        
        result.fields = fields
        return result
