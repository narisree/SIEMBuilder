"""
Vendor Schema Learner Module
Fetches vendor documentation from URLs and uses AI to extract log field schemas.
Caches learned schemas for performance.
"""

import requests
from bs4 import BeautifulSoup
import json
import hashlib
import re
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, field
import datetime


@dataclass
class FieldDefinition:
    """Vendor field definition learned from documentation."""
    position: Optional[int]  # For positional formats (CSV)
    name: str
    data_type: str  # string, int, ip, timestamp
    description: str
    example_value: str
    is_required: bool
    cim_hint: Optional[str] = None  # Suggested CIM field


@dataclass
class VendorLogSchema:
    """Complete log schema learned from vendor docs."""
    vendor: str
    product: str
    log_type: str
    format_type: str  # csv, json, syslog, kv
    delimiter: Optional[str]  # For CSV
    fields: List[FieldDefinition] = field(default_factory=list)
    parsing_notes: str = ""
    doc_url: str = ""
    learned_at: str = ""


class VendorSchemaLearner:
    """Learns log schemas from vendor documentation using AI."""
    
    SYSTEM_PROMPT = """# Vendor Log Field Schema Extractor

You are an expert at analyzing vendor security product documentation and extracting precise log field definitions.

## Your Task
Analyze the provided vendor documentation and extract the complete field schema including:
1. Field names (exact as vendor specifies)
2. Field positions (for positional/CSV formats) - CRITICAL for Palo Alto and similar vendors
3. Data types (string, integer, IP address, timestamp, etc.)
4. Field descriptions
5. Example values
6. Whether fields are required or optional

## Output Format
Provide the schema as a JSON object with this structure:

```json
{
  "format_type": "csv|json|syslog|kv",
  "delimiter": "," (if CSV),
  "fields": [
    {
      "position": 0,
      "name": "receive_time",
      "data_type": "timestamp",
      "description": "Time the log was received at the management plane",
      "example_value": "2024-01-15 10:30:00",
      "is_required": true,
      "cim_hint": "_time"
    }
  ],
  "parsing_notes": "Any special parsing considerations"
}
```

## Critical Rules
1. Extract EXACT field names as vendor specifies (case-sensitive)
2. For positional formats (Palo Alto, Cisco ASA CSV), **field position is CRITICAL**
3. Position numbering starts at 0
4. Note if fields are vendor-specific vs standard
5. Identify nested JSON paths (e.g., "properties.userPrincipalName")
6. Flag calculated vs extracted fields where evident

## Focus Areas for Positional Formats (CSV/Comma-delimited)
- **MOST IMPORTANT**: Determine the exact position/column number for each field
- Field ordering is critical - position 0, 1, 2, 3... must be accurate
- Note if delimiter is comma, pipe, tab, or custom
- Identify if first row is a header or data

## Example: Palo Alto Traffic Log
If documentation shows:
"Traffic logs are comma-delimited with the following fields in order:
1. Receive Time
2. Serial Number  
3. Type
4. Subtype
5. Generated Time
6. Source IP
..."

Output should be:
```json
{
  "format_type": "csv",
  "delimiter": ",",
  "fields": [
    {"position": 0, "name": "receive_time", "data_type": "timestamp", ...},
    {"position": 1, "name": "serial_number", "data_type": "string", ...},
    {"position": 2, "name": "type", "data_type": "string", ...},
    {"position": 3, "name": "subtype", "data_type": "string", ...},
    {"position": 4, "name": "generated_time", "data_type": "timestamp", ...},
    {"position": 5, "name": "source_ip", "data_type": "ip", ...}
  ]
}
```
"""

    def __init__(self, ai_client, cache_dir="data/vendor_schemas"):
        self.ai_client = ai_client
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
    
    def learn_schema(
        self, 
        vendor: str, 
        product: str, 
        log_type: str,
        doc_url: str,
        force_refresh: bool = False
    ) -> VendorLogSchema:
        """
        Learn log schema from vendor documentation.
        
        Args:
            vendor: Vendor name (e.g., "Palo Alto")
            product: Product name (e.g., "Firewall")
            log_type: Log type (e.g., "Traffic")
            doc_url: URL to vendor documentation
            force_refresh: Skip cache and re-learn
            
        Returns:
            VendorLogSchema with learned field definitions
        """
        # Check cache first
        if not force_refresh:
            cached = self._load_from_cache(vendor, product, log_type)
            if cached:
                return cached
        
        # Fetch documentation
        doc_content = self._fetch_documentation(doc_url)
        if not doc_content:
            return self._create_empty_schema(
                vendor, product, log_type, 
                f"Failed to fetch documentation from {doc_url}"
            )
        
        # Use AI to extract schema
        schema = self._extract_schema_with_ai(
            vendor, product, log_type, doc_content, doc_url
        )
        
        # Cache the result
        if schema and schema.fields:
            self._save_to_cache(schema)
        
        return schema
    
    def _fetch_documentation(self, url: str) -> Optional[str]:
        """Fetch and extract text from vendor documentation URL."""
        try:
            response = requests.get(url, timeout=30, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            response.raise_for_status()
            
            # Parse HTML and extract text
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Remove script and style elements
            for script in soup(["script", "style"]):
                script.decompose()
            
            # Get text
            text = soup.get_text()
            
            # Clean up whitespace
            lines = (line.strip() for line in text.splitlines())
            chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
            text = '\n'.join(chunk for chunk in chunks if chunk)
            
            return text
            
        except Exception as e:
            print(f"Error fetching documentation from {url}: {e}")
            return None
    
    def _extract_schema_with_ai(
        self,
        vendor: str,
        product: str,
        log_type: str,
        doc_content: str,
        doc_url: str
    ) -> VendorLogSchema:
        """Use AI to extract schema from documentation."""
        
        # Truncate if too long
        if len(doc_content) > 30000:
            doc_content = doc_content[:30000] + "\n\n[... documentation truncated ...]"
        
        prompt = f"""# Schema Extraction Request

**Vendor:** {vendor}
**Product:** {product}
**Log Type:** {log_type}
**Documentation URL:** {doc_url}

## Vendor Documentation Content

{doc_content}

---

## Instructions

Extract the complete field schema from the above documentation. Focus on:
1. **EXACT field names and their order/position** (CRITICAL for CSV/positional formats)
2. Data types and formats
3. Field descriptions
4. Example values if provided
5. Any parsing notes or special considerations

**IMPORTANT for Positional Formats:**
- If this is a comma-delimited, pipe-delimited, or positional format, the position number is CRITICAL
- Position 0 = first field, position 1 = second field, etc.
- Be precise about field ordering

Provide your response ONLY as valid JSON following the schema format specified in the system prompt.
"""

        try:
            response = self.ai_client.get_response(
                question=prompt,
                kb_content=self.SYSTEM_PROMPT,
                source_name="Vendor Schema Learner",
                chat_history=[]
            )
            
            if not response.get('success'):
                return self._create_empty_schema(
                    vendor, product, log_type, 
                    response.get('message', 'AI extraction failed')
                )
            
            # Parse AI response
            ai_response = response.get('response', '')
            
            # Extract JSON from markdown code blocks if present
            json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', ai_response, re.DOTALL)
            if json_match:
                json_str = json_match.group(1)
            else:
                # Try to find JSON object in response
                json_match = re.search(r'\{.*\}', ai_response, re.DOTALL)
                if json_match:
                    json_str = json_match.group(0)
                else:
                    return self._create_empty_schema(
                        vendor, product, log_type, 
                        "No JSON found in AI response"
                    )
            
            # Parse JSON
            schema_data = json.loads(json_str)
            
            # Create VendorLogSchema
            schema = VendorLogSchema(
                vendor=vendor,
                product=product,
                log_type=log_type,
                format_type=schema_data.get('format_type', 'unknown'),
                delimiter=schema_data.get('delimiter'),
                parsing_notes=schema_data.get('parsing_notes', ''),
                doc_url=doc_url,
                learned_at=datetime.datetime.now().isoformat()
            )
            
            # Parse fields
            for field_data in schema_data.get('fields', []):
                field = FieldDefinition(
                    position=field_data.get('position'),
                    name=field_data['name'],
                    data_type=field_data.get('data_type', 'string'),
                    description=field_data.get('description', ''),
                    example_value=field_data.get('example_value', ''),
                    is_required=field_data.get('is_required', False),
                    cim_hint=field_data.get('cim_hint')
                )
                schema.fields.append(field)
            
            return schema
            
        except json.JSONDecodeError as e:
            return self._create_empty_schema(
                vendor, product, log_type, 
                f"JSON parse error: {e}"
            )
        except Exception as e:
            return self._create_empty_schema(
                vendor, product, log_type, 
                f"Schema extraction failed: {e}"
            )
    
    def _create_empty_schema(
        self, 
        vendor: str, 
        product: str, 
        log_type: str, 
        error: str
    ) -> VendorLogSchema:
        """Create an empty schema with error message."""
        return VendorLogSchema(
            vendor=vendor,
            product=product,
            log_type=log_type,
            format_type="unknown",
            parsing_notes=f"ERROR: {error}",
            doc_url=""
        )
    
    def _get_cache_key(self, vendor: str, product: str, log_type: str) -> str:
        """Generate cache key."""
        key = f"{vendor}_{product}_{log_type}".lower().replace(' ', '_')
        return hashlib.md5(key.encode()).hexdigest()
    
    def _load_from_cache(
        self, 
        vendor: str, 
        product: str, 
        log_type: str
    ) -> Optional[VendorLogSchema]:
        """Load schema from cache."""
        cache_key = self._get_cache_key(vendor, product, log_type)
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        if not cache_file.exists():
            return None
        
        try:
            with open(cache_file, 'r') as f:
                data = json.load(f)
            
            schema = VendorLogSchema(
                vendor=data['vendor'],
                product=data['product'],
                log_type=data['log_type'],
                format_type=data['format_type'],
                delimiter=data.get('delimiter'),
                parsing_notes=data.get('parsing_notes', ''),
                doc_url=data.get('doc_url', ''),
                learned_at=data.get('learned_at', '')
            )
            
            for field_data in data.get('fields', []):
                field = FieldDefinition(**field_data)
                schema.fields.append(field)
            
            return schema
            
        except Exception as e:
            print(f"Cache load error: {e}")
            return None
    
    def _save_to_cache(self, schema: VendorLogSchema):
        """Save schema to cache."""
        cache_key = self._get_cache_key(schema.vendor, schema.product, schema.log_type)
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        try:
            data = {
                'vendor': schema.vendor,
                'product': schema.product,
                'log_type': schema.log_type,
                'format_type': schema.format_type,
                'delimiter': schema.delimiter,
                'parsing_notes': schema.parsing_notes,
                'doc_url': schema.doc_url,
                'learned_at': schema.learned_at,
                'fields': [
                    {
                        'position': f.position,
                        'name': f.name,
                        'data_type': f.data_type,
                        'description': f.description,
                        'example_value': f.example_value,
                        'is_required': f.is_required,
                        'cim_hint': f.cim_hint
                    }
                    for f in schema.fields
                ]
            }
            
            with open(cache_file, 'w') as f:
                json.dump(data, f, indent=2)
                
        except Exception as e:
            print(f"Cache save error: {e}")


def create_vendor_schema_learner(ai_client) -> VendorSchemaLearner:
    """Factory function to create vendor schema learner."""
    return VendorSchemaLearner(ai_client)
