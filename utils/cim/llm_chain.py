"""
LLM Chain for CIM Mapping
Uses the configured AI provider to map log fields to Splunk CIM data models.
Implements strict anti-hallucination rules and proper field flag handling.

Enhanced with AI-based field parsing and vendor documentation support for
improved semantic understanding and mapping accuracy.
"""
import re
from typing import Dict, List, Optional, Any, TYPE_CHECKING
from dataclasses import dataclass

# Type hints for optional dependencies
if TYPE_CHECKING:
    from .ai_field_parser import AIFieldParseResult
    from .vendor_doc_loader import VendorDocResult


# System prompt based on the CIM Mapping System Prompt specification
SYSTEM_PROMPT = """# Splunk CIM Mapping Assistant

## Role & Objective
You are a Senior Cyber Security Engineer specializing in Splunk Data Normalization and Splunk Common Information Model (CIM) mapping.

Your objective is to map raw log source field NAMES to the correct Splunk CIM Data Model fields with high accuracy and no assumptions.

## Environment Constraint
The activity will be performed in **Splunk Cloud**.
- All configuration must be done using **Splunk Web (GUI) only**
- No backend file edits (props.conf, transforms.conf, etc.) - but we will generate them for reference

## CRITICAL: Field Flag Rules

**ALWAYS check and respect field flags from the CIM data model:**

### Field Flags
- **`flag: "inherited"`** = System fields (_time, host, source, sourcetype) - **DO NOT MAP, NO ACTION NEEDED**
- **`flag: "calculated"`** = Use **Calculated Fields** with EVAL expressions - **NEVER use Field Alias**
- **`flag: "extracted"`** = Use **Field Aliases** for direct mapping - **NEVER use Calculated Field**

### Common Mistakes to AVOID
❌ **INCORRECT:** Using Field Aliases for fields marked as `flag: "calculated"` (like `action`, `src`, `dest`)
❌ **INCORRECT:** Mapping data VALUES instead of field NAMES (e.g., "192.168.1.50" instead of "src_ip_raw")
❌ **INCORRECT:** Creating calculated fields for `flag: "extracted"` fields

✅ **CORRECT:**
- `flag: "calculated"` → Calculated Field (EVAL expression)
- `flag: "extracted"` → Field Alias (raw_field AS cim_field)

## Strict Accuracy Constraints (Anti-Hallucination Rules)

### CRITICAL: Only Map Field NAMES, Not Values
- The user provides field NAMES like: src_ip, dest_port, action, user
- These are column headers or field identifiers from the log
- NEVER map IP addresses (192.168.1.50), port numbers (443), or other DATA values
- The mapping should be: raw_field_name AS cim_field_name

### Do Not Guess
- Never invent field names, sourcetypes, or CIM mappings
- If unsure, state: "I do not have enough information to map this field accurately"

### Verifiable Output Only
Every mapping must specify:
1. The exact CIM Data Model (e.g., Authentication, Network_Traffic)
2. The exact CIM Dataset within that model
3. The field flag (calculated or extracted) - CHECK THE CIM SPECIFICATION
4. The transformation method based on the flag

## Response Format

When given a list of field names and their sample values, respond with:

### 1. Data Model Identification

**Data Model:** [Name]
**Dataset:** [Dataset name]
**Confidence:** [High/Medium/Low]
**Justification:** [Why this data model applies]

### 2. Field Mapping Table

| Raw Field Name | CIM Field Name | Field Flag | Transformation | CIM Requirement | Notes |
|----------------|----------------|------------|----------------|-----------------|-------|

**Columns:**
- **Raw Field Name:** The ACTUAL field name from the source (NOT the value)
- **CIM Field Name:** Target CIM field
- **Field Flag:** "calculated" or "extracted" (from CIM spec)
- **Transformation:** 
  - For "extracted": `Field Alias: raw_field AS cim_field`
  - For "calculated": `Calculated Field: EVAL expression`
- **CIM Requirement:** Required / Recommended / Optional
- **Notes:** Any special handling

### 3. Field Name Collision Handling

If any raw field names conflict with CIM calculated field names:
- Rename extracted field with `_raw` suffix during extraction
- Create calculated field with the CIM name
- Example: If raw log has "action" field but CIM "action" is calculated:
  - Extract as: action_raw
  - Calculate: action = case(action_raw="allow", "allowed", action_raw="deny", "blocked", 1=1, action_raw)

### 4. Required Tags
```
tag1
tag2
```

### 5. Calculated Fields (for flag: "calculated" ONLY)
```
EVAL-cim_field = expression
```

### 6. Field Aliases (for flag: "extracted" ONLY)
```
raw_field AS cim_field
```

## CIM Field Flag Reference (Common Fields)

### Network_Traffic Data Model - Key Fields
- **action** - flag: "calculated" - Values: allowed, blocked, dropped, teardown
- **src** - flag: "calculated" - Source IP, use coalesce(src_ip, src_host)
- **dest** - flag: "calculated" - Destination IP, use coalesce(dest_ip, dest_host)
- **src_ip** - flag: "extracted" - Source IP address (Field Alias OK)
- **dest_ip** - flag: "extracted" - Destination IP address (Field Alias OK)
- **src_port** - flag: "calculated" - Use tonumber(src_port_raw)
- **dest_port** - flag: "calculated" - Use tonumber(dest_port_raw)
- **bytes** - flag: "calculated" - Usually bytes_in + bytes_out
- **bytes_in** - flag: "calculated" - Use tonumber()
- **bytes_out** - flag: "calculated" - Use tonumber()
- **transport** - flag: "calculated" - lower(protocol)
- **protocol** - flag: "extracted" - Field Alias OK
- **app** - flag: "extracted" - Application name
- **user** - flag: "calculated" - Extracted from domain\\user if needed

### Authentication Data Model - Key Fields
- **action** - flag: "calculated" - Values: success, failure, error
- **src** - flag: "calculated"
- **dest** - flag: "calculated"
- **user** - flag: "calculated" - Extract username from domain\\user
- **src_user** - flag: "extracted" - Field Alias OK
- **authentication_method** - flag: "extracted"

### Change Data Model - Key Fields
- **action** - flag: "calculated" - Values: created, deleted, modified
- **object** - flag: "extracted"
- **object_category** - flag: "extracted"
- **user** - flag: "calculated"

## Calculated Field Best Practices

### Action Field Normalization (ALWAYS use Calculated Field)
```
case(
  action_raw=="allow" OR action_raw=="permit", "allowed",
  action_raw=="deny" OR action_raw=="block", "blocked",
  action_raw=="drop", "dropped",
  action_raw=="reset" OR action_raw=="reset-both", "blocked",
  1=1, lower(action_raw)
)
```

### Numeric Type Conversion (ports, bytes)
```
tonumber(src_port_raw)
```

### User Extraction (from domain\\username)
```
if(isnotnull(src_user_raw) AND match(src_user_raw, "\\\\"), 
   mvindex(split(src_user_raw, "\\\\"), -1), 
   src_user_raw)
```

### Coalesce for Fallback
```
coalesce(src_ip, src_host, src_nt_host)
```

## IMPORTANT REMINDERS

⚠️ **Map field NAMES, not data VALUES** - "src_ip" not "192.168.1.50"
⚠️ **Check field flags** - calculated vs extracted determines the method
⚠️ **action, src, dest, user are almost ALWAYS calculated fields**
⚠️ **Port fields (src_port, dest_port) need tonumber() - calculated**
⚠️ **Never use Field Alias for calculated fields**
⚠️ **Handle field name collisions with _raw suffix**
"""


@dataclass
class CIMMappingResult:
    """Result of CIM mapping analysis."""
    success: bool
    data_model: str
    dataset: str
    confidence: float
    mapping: str
    error: Optional[str] = None


class CIMMappingChain:
    """Chain for analyzing logs and generating CIM mappings using AI.

    Enhanced with support for:
    - AI-based semantic field parsing
    - Vendor documentation context
    - Improved field mapping accuracy
    """

    def __init__(self, vector_store, ai_client):
        """Initialize with vector store and AI client."""
        self.vector_store = vector_store
        self.ai_client = ai_client
        self._ai_field_result = None
        self._vendor_doc_result = None

    def analyze(
        self,
        parsed_log,
        ai_field_result: Optional['AIFieldParseResult'] = None,
        vendor_doc_content: Optional[str] = None
    ) -> Dict[str, Any]:
        """Analyze parsed log and generate CIM mapping.

        Args:
            parsed_log: ParsedLog object from LogParser
            ai_field_result: Optional AIFieldParseResult with enriched field info
            vendor_doc_content: Optional vendor documentation context string

        Returns:
            Dict with mapping results
        """
        # Store for use in helper methods
        self._ai_field_result = ai_field_result
        self._vendor_doc_content = vendor_doc_content

        # Prepare field information - enhanced with AI parsing if available
        if ai_field_result and ai_field_result.success:
            field_info = self._prepare_enhanced_field_info(parsed_log, ai_field_result)
        else:
            field_info = self._prepare_field_info(parsed_log)

        # Get relevant CIM context from vector store
        cim_context = self._get_cim_context(list(parsed_log.fields.keys()))

        # Build the user prompt with all available context
        user_prompt = self._build_user_prompt(
            parsed_log,
            field_info,
            cim_context,
            ai_field_result,
            vendor_doc_content
        )

        # Call AI provider
        try:
            response = self._call_ai(user_prompt)

            if response.get('success'):
                mapping_text = response.get('response', '')

                # Extract data model and dataset
                data_model = self._extract_data_model(mapping_text)
                dataset = self._extract_dataset(mapping_text)
                confidence = self._extract_confidence(mapping_text)

                # Boost confidence if we had AI field analysis
                if ai_field_result and ai_field_result.success:
                    confidence = min(confidence + 0.05, 0.98)

                # Boost confidence if we had vendor docs
                if vendor_doc_content:
                    confidence = min(confidence + 0.05, 0.98)

                return {
                    'success': True,
                    'data_model': data_model,
                    'dataset': dataset,
                    'confidence': confidence,
                    'mapping': mapping_text,
                    'ai_field_analysis_used': ai_field_result is not None and ai_field_result.success,
                    'vendor_docs_used': vendor_doc_content is not None
                }
            else:
                return {
                    'success': False,
                    'error': response.get('message', 'AI call failed'),
                    'data_model': 'Unknown',
                    'dataset': 'Unknown',
                    'confidence': 0.0,
                    'mapping': ''
                }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'data_model': 'Unknown',
                'dataset': 'Unknown',
                'confidence': 0.0,
                'mapping': ''
            }

    def _prepare_enhanced_field_info(
        self,
        parsed_log,
        ai_result: 'AIFieldParseResult'
    ) -> str:
        """Prepare field information enhanced with AI semantic analysis."""
        lines = []
        lines.append("## Detected Fields (AI-Enhanced Analysis)")
        lines.append("")

        # Add overall analysis if available
        if ai_result.log_category:
            lines.append(f"**Log Category:** {ai_result.log_category}")
        if ai_result.vendor_detected:
            lines.append(f"**Vendor:** {ai_result.vendor_detected}")
        if ai_result.product_detected:
            lines.append(f"**Product:** {ai_result.product_detected}")
        lines.append("")

        lines.append("| # | Field Name | Semantic Category | Sample Values | AI Suggested CIM | Mapping Type |")
        lines.append("|---|------------|-------------------|---------------|------------------|--------------|")

        for i, (field_name, values) in enumerate(parsed_log.fields.items(), 1):
            # Get AI enrichment if available
            enriched = ai_result.enriched_fields.get(field_name)

            # Get unique sample values (limit to 3)
            unique_values = list(set(str(v) for v in values if v))[:3]
            sample_str = ", ".join(unique_values) if unique_values else "(empty)"

            # Truncate if too long
            if len(sample_str) > 40:
                sample_str = sample_str[:37] + "..."

            if enriched:
                category = enriched.semantic_category or "unknown"
                suggested_cim = enriched.suggested_cim_field or "-"
                mapping_type = enriched.mapping_type or "-"

                # Add review flag if needed
                if enriched.needs_review:
                    category += " (!)"
            else:
                category = self._infer_field_type(values)
                suggested_cim = "-"
                mapping_type = "-"

            lines.append(f"| {i} | `{field_name}` | {category} | {sample_str} | {suggested_cim} | {mapping_type} |")

        lines.append("")
        lines.append("*Note: Fields marked with (!) may need manual review*")

        return "\n".join(lines)
    
    def _prepare_field_info(self, parsed_log) -> str:
        """Prepare field information showing NAMES and sample values."""
        lines = []
        lines.append("## Detected Fields (Field Name → Sample Values)")
        lines.append("")
        lines.append("| # | Field Name | Sample Values | Inferred Type |")
        lines.append("|---|------------|---------------|---------------|")
        
        for i, (field_name, values) in enumerate(parsed_log.fields.items(), 1):
            # Get unique sample values (limit to 3)
            unique_values = list(set(str(v) for v in values if v))[:3]
            sample_str = ", ".join(unique_values) if unique_values else "(empty)"
            
            # Truncate if too long
            if len(sample_str) > 50:
                sample_str = sample_str[:47] + "..."
            
            # Infer type from values
            inferred_type = self._infer_field_type(values)
            
            lines.append(f"| {i} | `{field_name}` | {sample_str} | {inferred_type} |")
        
        return "\n".join(lines)
    
    def _infer_field_type(self, values: List[str]) -> str:
        """Infer the type of a field from its values."""
        if not values:
            return "unknown"
        
        sample = str(values[0]).strip()
        
        # Check for IP addresses
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', sample):
            return "IP address"
        
        # Check for ports (numeric 1-65535)
        if sample.isdigit() and 1 <= int(sample) <= 65535:
            return "port/number"
        
        # Check for timestamps
        if re.match(r'^\d{4}[-/]\d{2}[-/]\d{2}', sample):
            return "timestamp"
        
        # Check for domain\\user format
        if '\\' in sample:
            return "domain\\user"
        
        # Check for action-like values
        action_words = ['allow', 'deny', 'block', 'drop', 'permit', 'accept', 'reject', 'success', 'failure']
        if sample.lower() in action_words:
            return "action"
        
        # Check for protocol
        protocol_words = ['tcp', 'udp', 'icmp', 'http', 'https', 'dns', 'ssh', 'ftp']
        if sample.lower() in protocol_words:
            return "protocol"
        
        return "string"
    
    def _get_cim_context(self, field_names: List[str]) -> str:
        """Get relevant CIM context from vector store."""
        if not self.vector_store or not self.vector_store.available:
            return "No CIM context available."
        
        # Search for similar CIM fields
        relevant_info = []
        seen_fields = set()
        
        for field_name in field_names[:20]:  # Limit to first 20 fields
            results = self.vector_store.search_similar_fields(field_name, n_results=3)
            for result in results:
                field_key = f"{result.get('data_model', '')}.{result.get('cim_field', '')}"
                if field_key not in seen_fields:
                    seen_fields.add(field_key)
                    relevant_info.append(result)
        
        if not relevant_info:
            return "No matching CIM fields found in knowledge base."
        
        # Format CIM context
        lines = ["## Relevant CIM Field Reference", ""]
        lines.append("| CIM Field | Data Model | Dataset | Flag | Description |")
        lines.append("|-----------|------------|---------|------|-------------|")
        
        for info in relevant_info[:30]:  # Limit output
            cim_field = info.get('cim_field', 'N/A')
            data_model = info.get('data_model', 'N/A')
            dataset = info.get('dataset', 'N/A')
            flag = info.get('flag', 'N/A')
            description = info.get('description', '')[:50]
            
            lines.append(f"| {cim_field} | {data_model} | {dataset} | **{flag}** | {description} |")
        
        return "\n".join(lines)
    
    def _build_user_prompt(
        self,
        parsed_log,
        field_info: str,
        cim_context: str,
        ai_field_result: Optional['AIFieldParseResult'] = None,
        vendor_doc_content: Optional[str] = None
    ) -> str:
        """Build the user prompt for CIM mapping.

        Args:
            parsed_log: ParsedLog object
            field_info: Formatted field information string
            cim_context: CIM context from vector store
            ai_field_result: Optional AI field analysis results
            vendor_doc_content: Optional vendor documentation context

        Returns:
            Complete user prompt for CIM mapping
        """
        prompt_parts = [
            f"# Log Source Analysis Request",
            f"",
            f"## Log Format: {parsed_log.format.value.upper()}",
            f"## Total Fields Detected: {len(parsed_log.fields)}",
        ]

        # Add vendor/product info from parsed log or AI analysis
        vendor = parsed_log.vendor
        product = parsed_log.product

        if ai_field_result and ai_field_result.success:
            if ai_field_result.vendor_detected:
                vendor = ai_field_result.vendor_detected
            if ai_field_result.product_detected:
                product = ai_field_result.product_detected

        if vendor:
            prompt_parts.append(f"## Vendor: {vendor}")
        if product:
            prompt_parts.append(f"## Product: {product}")

        # Add log category if detected by AI
        if ai_field_result and ai_field_result.log_category:
            prompt_parts.append(f"## Detected Log Category: {ai_field_result.log_category}")

        prompt_parts.append("")
        prompt_parts.append(field_info)
        prompt_parts.append("")
        prompt_parts.append("---")
        prompt_parts.append("")

        # Add vendor documentation context if available
        if vendor_doc_content:
            prompt_parts.append("## Vendor Documentation Reference")
            prompt_parts.append("")
            # Truncate vendor docs if too long
            if len(vendor_doc_content) > 4000:
                prompt_parts.append(vendor_doc_content[:4000])
                prompt_parts.append("")
                prompt_parts.append("*[Vendor documentation truncated]*")
            else:
                prompt_parts.append(vendor_doc_content)
            prompt_parts.append("")
            prompt_parts.append("---")
            prompt_parts.append("")

        # Add AI analysis summary if available
        if ai_field_result and ai_field_result.success and ai_field_result.overall_analysis:
            prompt_parts.append("## AI Field Semantic Analysis Summary")
            prompt_parts.append("")
            # Add a condensed version of the AI analysis
            analysis_summary = ai_field_result.overall_analysis[:2000]
            if len(ai_field_result.overall_analysis) > 2000:
                # Try to end at a sentence
                last_period = analysis_summary.rfind('.')
                if last_period > 1500:
                    analysis_summary = analysis_summary[:last_period + 1]
            prompt_parts.append(analysis_summary)
            prompt_parts.append("")
            prompt_parts.append("---")
            prompt_parts.append("")

        prompt_parts.append(cim_context)
        prompt_parts.append("")
        prompt_parts.append("---")
        prompt_parts.append("")
        prompt_parts.append("## Sample Log Events")
        prompt_parts.append("```")
        for event in parsed_log.sample_events[:3]:
            prompt_parts.append(event[:500])  # Truncate long events
        prompt_parts.append("```")
        prompt_parts.append("")
        prompt_parts.append("---")
        prompt_parts.append("")
        prompt_parts.append("## Task")
        prompt_parts.append("")
        prompt_parts.append("Please analyze these log fields and provide:")
        prompt_parts.append("1. The most appropriate CIM Data Model and Dataset")
        prompt_parts.append("2. Complete field mapping table with proper field flags")
        prompt_parts.append("3. Calculated field expressions (for flag: calculated)")
        prompt_parts.append("4. Field aliases (for flag: extracted)")
        prompt_parts.append("5. Required tags for CIM compliance")
        prompt_parts.append("")

        # Enhanced instructions when AI analysis is available
        if ai_field_result and ai_field_result.success:
            prompt_parts.append("**CONTEXT:** AI semantic analysis has been performed on these fields.")
            prompt_parts.append("Use the suggested CIM fields and mapping types as guidance, but verify against CIM specifications.")
            prompt_parts.append("")

        if vendor_doc_content:
            prompt_parts.append("**CONTEXT:** Vendor documentation has been provided.")
            prompt_parts.append("Use field definitions from the documentation for accurate value interpretation.")
            prompt_parts.append("")

        prompt_parts.append("**IMPORTANT:** Map the FIELD NAMES shown in the table above, NOT the sample values.")
        prompt_parts.append("**IMPORTANT:** Check field flags - use Calculated Fields for 'calculated' flags, Field Aliases for 'extracted' flags.")

        return "\n".join(prompt_parts)
    
    def _call_ai(self, user_prompt: str) -> Dict[str, Any]:
        """Call the AI provider with the prompt."""
        # Use the AI client's get_response method
        return self.ai_client.get_response(
            question=user_prompt,
            kb_content=SYSTEM_PROMPT,
            source_name="CIM Mapping Assistant",
            chat_history=[]
        )
    
    def _extract_data_model(self, mapping_text: str) -> str:
        """Extract data model name from mapping result."""
        patterns = [
            r'\*\*Data Model:\*\*\s*([A-Za-z_]+)',
            r'Data Model:\s*([A-Za-z_]+)',
            r'data model[:\s]+([A-Za-z_]+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, mapping_text, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        
        # Try to detect from common keywords
        model_keywords = {
            'Network_Traffic': ['traffic', 'firewall', 'network', 'connection'],
            'Authentication': ['authentication', 'login', 'logon', 'auth'],
            'Change': ['change', 'audit', 'modification'],
            'Web': ['web', 'http', 'url', 'proxy'],
            'Malware': ['malware', 'virus', 'threat', 'antivirus'],
            'Email': ['email', 'mail', 'smtp'],
            'Endpoint': ['endpoint', 'process', 'registry'],
            'Intrusion_Detection': ['intrusion', 'ids', 'ips', 'alert'],
        }
        
        text_lower = mapping_text.lower()
        for model, keywords in model_keywords.items():
            if any(kw in text_lower for kw in keywords):
                return model
        
        return "Unknown"
    
    def _extract_dataset(self, mapping_text: str) -> str:
        """Extract dataset name from mapping result."""
        patterns = [
            r'\*\*Dataset:\*\*\s*([A-Za-z_]+)',
            r'Dataset:\s*([A-Za-z_]+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, mapping_text, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        
        return "All_Traffic"  # Default for Network_Traffic
    
    def _extract_confidence(self, mapping_text: str) -> float:
        """Extract confidence level from mapping result."""
        patterns = [
            r'\*\*Confidence:\*\*\s*(\w+)',
            r'Confidence:\s*(\w+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, mapping_text, re.IGNORECASE)
            if match:
                level = match.group(1).lower()
                if level == 'high':
                    return 0.9
                elif level == 'medium':
                    return 0.7
                elif level == 'low':
                    return 0.5
        
        return 0.7  # Default medium confidence


def create_mapping_chain(vector_store, ai_client) -> CIMMappingChain:
    """Factory function to create a CIM mapping chain."""
    return CIMMappingChain(vector_store, ai_client)
