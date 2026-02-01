"""
AI Field Parser Module
Uses AI to semantically analyze and enrich log fields beyond basic pattern detection.
This provides deeper understanding of field meanings, vendor-specific conventions,
and value interpretations that programmatic parsing cannot achieve.
"""
import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field


# System prompt for AI field analysis
FIELD_ANALYSIS_SYSTEM_PROMPT = """# Log Field Semantic Analyzer

## Role
You are an expert log analyst specializing in security log formats from various vendors.
Your task is to semantically analyze log fields to understand their true meaning and purpose.

## Capabilities
- Deep understanding of vendor-specific field naming conventions
- Knowledge of common log formats (CEF, LEEF, Syslog, JSON, etc.)
- Ability to infer field semantics from field names and sample values
- Understanding of security-relevant fields and their CIM mapping implications

## Analysis Guidelines

### Field Name Analysis
For each field, determine:
1. **Semantic Category**: What type of information does this field represent?
   - Identity fields (user, account, domain)
   - Network fields (IP, port, protocol, hostname)
   - Action/Event fields (action, status, result, event type)
   - Temporal fields (timestamp, duration, time)
   - Metadata fields (severity, priority, category)
   - Data fields (bytes, packets, size, count)
   - Security fields (threat, signature, CVE, malware)
   - Resource fields (file, path, URL, process)

2. **Vendor Convention**: Is this a vendor-specific naming convention?
   - Palo Alto: Uses 'src' prefix, 'srcloc' for location, 'vsys' for virtual system
   - Cisco: Uses 'Xlate' for translation, 'ACL' for access lists
   - Windows: Uses EventID, TargetUserName, SubjectLogonId patterns
   - Azure AD: Uses camelCase, 'properties.' prefix for nested fields
   - CrowdStrike: Uses 'aid' for agent ID, 'cid' for customer ID

3. **Value Interpretation**: What do the sample values tell us?
   - Numeric codes that may need lookup (action=0 vs action=1)
   - Encoded values (base64, hex, URL-encoded)
   - Concatenated values that may need parsing (domain\\user)
   - Normalized vs raw values

### CIM Mapping Hints
Provide hints for CIM mapping:
- Which CIM field this likely maps to
- Whether it needs transformation (calculated) or direct mapping (extracted)
- Common EVAL expressions needed

## Response Format

For each field, provide analysis in this structured format:

### Field: `field_name`
- **Semantic Category**: [category]
- **Description**: [what this field represents]
- **Vendor Context**: [vendor-specific notes if applicable]
- **Value Analysis**: [interpretation of sample values]
- **CIM Hint**:
  - Target Field: [suggested CIM field]
  - Mapping Type: [calculated/extracted]
  - Transformation: [if calculated, suggested EVAL]
- **Confidence**: [high/medium/low]
- **Notes**: [any special considerations]

## Important Rules
1. Base analysis on BOTH field names AND sample values
2. Consider vendor documentation context if provided
3. Flag ambiguous fields that need human review
4. Identify fields that may contain sensitive data
5. Note any potential data quality issues observed
"""


@dataclass
class EnrichedField:
    """Enriched field information from AI analysis."""
    name: str
    sample_values: List[str] = field(default_factory=list)

    # AI-derived enrichments
    semantic_category: str = "unknown"
    description: str = ""
    vendor_context: str = ""
    value_analysis: str = ""

    # CIM mapping hints
    suggested_cim_field: str = ""
    mapping_type: str = ""  # "calculated" or "extracted"
    suggested_transformation: str = ""

    # Metadata
    confidence: float = 0.5
    notes: str = ""
    needs_review: bool = False


@dataclass
class AIFieldParseResult:
    """Result of AI field parsing."""
    success: bool
    enriched_fields: Dict[str, EnrichedField] = field(default_factory=dict)
    vendor_detected: Optional[str] = None
    product_detected: Optional[str] = None
    log_category: str = ""  # "firewall", "authentication", "endpoint", etc.
    overall_analysis: str = ""
    error: Optional[str] = None


class AIFieldParser:
    """Uses AI to semantically analyze and enrich log fields."""

    def __init__(self, ai_client):
        """Initialize with an AI client."""
        self.ai_client = ai_client

    def analyze_fields(
        self,
        parsed_log,
        vendor_doc_content: Optional[str] = None
    ) -> AIFieldParseResult:
        """
        Analyze parsed log fields using AI for semantic understanding.

        Args:
            parsed_log: ParsedLog object from LogParser
            vendor_doc_content: Optional vendor documentation for context

        Returns:
            AIFieldParseResult with enriched field information
        """
        if not self.ai_client:
            return AIFieldParseResult(
                success=False,
                error="No AI client configured"
            )

        # Build the analysis prompt
        prompt = self._build_analysis_prompt(parsed_log, vendor_doc_content)

        # Call AI for analysis
        try:
            response = self.ai_client.get_response(
                question=prompt,
                kb_content=FIELD_ANALYSIS_SYSTEM_PROMPT,
                source_name="Field Semantic Analyzer",
                chat_history=[]
            )

            if response.get('success'):
                # Parse the AI response
                return self._parse_ai_response(
                    response.get('response', ''),
                    parsed_log
                )
            else:
                return AIFieldParseResult(
                    success=False,
                    error=response.get('message', 'AI analysis failed')
                )

        except Exception as e:
            return AIFieldParseResult(
                success=False,
                error=str(e)
            )

    def _build_analysis_prompt(
        self,
        parsed_log,
        vendor_doc_content: Optional[str] = None
    ) -> str:
        """Build the prompt for AI field analysis."""

        prompt_parts = [
            "# Log Field Analysis Request",
            "",
            f"## Log Format: {parsed_log.format.value.upper()}",
        ]

        if parsed_log.vendor:
            prompt_parts.append(f"## Detected Vendor: {parsed_log.vendor}")
        if parsed_log.product:
            prompt_parts.append(f"## Detected Product: {parsed_log.product}")

        prompt_parts.append("")
        prompt_parts.append("## Sample Log Events")
        prompt_parts.append("```")
        for event in parsed_log.sample_events[:5]:
            # Truncate very long events
            if len(event) > 500:
                prompt_parts.append(event[:500] + "...")
            else:
                prompt_parts.append(event)
        prompt_parts.append("```")
        prompt_parts.append("")

        # Field information
        prompt_parts.append("## Fields to Analyze")
        prompt_parts.append("")
        prompt_parts.append("| # | Field Name | Sample Values |")
        prompt_parts.append("|---|------------|---------------|")

        for i, (field_name, values) in enumerate(parsed_log.fields.items(), 1):
            # Get unique sample values
            unique_values = list(set(str(v) for v in values if v))[:5]
            sample_str = ", ".join(unique_values) if unique_values else "(empty)"

            # Truncate if too long
            if len(sample_str) > 60:
                sample_str = sample_str[:57] + "..."

            prompt_parts.append(f"| {i} | `{field_name}` | {sample_str} |")

        prompt_parts.append("")

        # Add vendor documentation context if provided
        if vendor_doc_content:
            prompt_parts.append("---")
            prompt_parts.append("")
            prompt_parts.append("## Vendor Documentation Context")
            prompt_parts.append("")
            # Truncate vendor docs if too long
            if len(vendor_doc_content) > 8000:
                prompt_parts.append(vendor_doc_content[:8000])
                prompt_parts.append("")
                prompt_parts.append("*[Documentation truncated for length]*")
            else:
                prompt_parts.append(vendor_doc_content)
            prompt_parts.append("")

        prompt_parts.append("---")
        prompt_parts.append("")
        prompt_parts.append("## Analysis Request")
        prompt_parts.append("")
        prompt_parts.append("Please analyze each field and provide:")
        prompt_parts.append("1. **Semantic category** and description of what the field represents")
        prompt_parts.append("2. **Vendor-specific context** if you recognize the naming convention")
        prompt_parts.append("3. **Value interpretation** - what do the sample values mean?")
        prompt_parts.append("4. **CIM mapping hints** - which CIM field, calculated vs extracted")
        prompt_parts.append("5. **Overall log category** - what type of log is this (firewall, auth, etc.)?")
        prompt_parts.append("")
        prompt_parts.append("Start with an overall analysis of the log source, then analyze each field.")

        return "\n".join(prompt_parts)

    def _parse_ai_response(
        self,
        response_text: str,
        parsed_log
    ) -> AIFieldParseResult:
        """Parse the AI response and extract structured field information."""

        result = AIFieldParseResult(success=True)
        result.overall_analysis = response_text

        # Extract vendor/product if mentioned
        vendor_match = re.search(
            r'(?:vendor|manufacturer)[:\s]+([A-Za-z0-9\s]+)',
            response_text,
            re.IGNORECASE
        )
        if vendor_match:
            result.vendor_detected = vendor_match.group(1).strip()
        elif parsed_log.vendor:
            result.vendor_detected = parsed_log.vendor

        product_match = re.search(
            r'(?:product|device)[:\s]+([A-Za-z0-9\s]+)',
            response_text,
            re.IGNORECASE
        )
        if product_match:
            result.product_detected = product_match.group(1).strip()
        elif parsed_log.product:
            result.product_detected = parsed_log.product

        # Extract log category
        category_patterns = [
            (r'(?:firewall|network traffic)', 'network_traffic'),
            (r'(?:authentication|login|logon|auth)', 'authentication'),
            (r'(?:endpoint|process|file)', 'endpoint'),
            (r'(?:web|http|proxy|url)', 'web'),
            (r'(?:email|mail|smtp)', 'email'),
            (r'(?:dns|resolution)', 'dns'),
            (r'(?:change|audit|modification)', 'change'),
            (r'(?:malware|threat|antivirus)', 'malware'),
            (r'(?:intrusion|ids|ips)', 'intrusion_detection'),
        ]

        response_lower = response_text.lower()
        for pattern, category in category_patterns:
            if re.search(pattern, response_lower):
                result.log_category = category
                break

        # Parse individual field analyses
        for field_name, values in parsed_log.fields.items():
            enriched = self._extract_field_analysis(
                field_name,
                values,
                response_text
            )
            result.enriched_fields[field_name] = enriched

        return result

    def _extract_field_analysis(
        self,
        field_name: str,
        sample_values: List[str],
        response_text: str
    ) -> EnrichedField:
        """Extract analysis for a specific field from the AI response."""

        enriched = EnrichedField(
            name=field_name,
            sample_values=list(set(str(v) for v in sample_values if v))[:5]
        )

        # Try to find field-specific section in response
        # Look for patterns like "### Field: `field_name`" or "**field_name**"
        field_patterns = [
            rf'###\s*Field:\s*`?{re.escape(field_name)}`?(.+?)(?=###\s*Field:|$)',
            rf'\*\*{re.escape(field_name)}\*\*(.+?)(?=\*\*[a-zA-Z_]+\*\*|$)',
            rf'`{re.escape(field_name)}`[:\s]*(.+?)(?=`[a-zA-Z_]+`[:\s]|$)',
        ]

        field_section = ""
        for pattern in field_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE | re.DOTALL)
            if match:
                field_section = match.group(1)
                break

        if field_section:
            # Extract semantic category
            cat_match = re.search(
                r'(?:semantic\s*category|category)[:\s]*([^\n]+)',
                field_section,
                re.IGNORECASE
            )
            if cat_match:
                enriched.semantic_category = cat_match.group(1).strip().strip('*').strip()

            # Extract description
            desc_match = re.search(
                r'(?:description)[:\s]*([^\n]+)',
                field_section,
                re.IGNORECASE
            )
            if desc_match:
                enriched.description = desc_match.group(1).strip().strip('*').strip()

            # Extract vendor context
            vendor_match = re.search(
                r'(?:vendor\s*context)[:\s]*([^\n]+)',
                field_section,
                re.IGNORECASE
            )
            if vendor_match:
                enriched.vendor_context = vendor_match.group(1).strip().strip('*').strip()

            # Extract CIM hints
            cim_field_match = re.search(
                r'(?:target\s*field|cim\s*field|maps?\s*to)[:\s]*`?([a-zA-Z_]+)`?',
                field_section,
                re.IGNORECASE
            )
            if cim_field_match:
                enriched.suggested_cim_field = cim_field_match.group(1).strip()

            # Extract mapping type
            if re.search(r'calculated', field_section, re.IGNORECASE):
                enriched.mapping_type = "calculated"
            elif re.search(r'extracted|alias', field_section, re.IGNORECASE):
                enriched.mapping_type = "extracted"

            # Extract transformation
            transform_match = re.search(
                r'(?:transformation|eval)[:\s]*`?([^`\n]+)`?',
                field_section,
                re.IGNORECASE
            )
            if transform_match:
                enriched.suggested_transformation = transform_match.group(1).strip()

            # Extract confidence
            if re.search(r'confidence[:\s]*high', field_section, re.IGNORECASE):
                enriched.confidence = 0.9
            elif re.search(r'confidence[:\s]*medium', field_section, re.IGNORECASE):
                enriched.confidence = 0.7
            elif re.search(r'confidence[:\s]*low', field_section, re.IGNORECASE):
                enriched.confidence = 0.5

            # Check if needs review
            if re.search(r'(?:needs?\s*review|ambiguous|unclear)', field_section, re.IGNORECASE):
                enriched.needs_review = True
        else:
            # Fallback: Try to infer from field name and values
            enriched = self._fallback_field_analysis(field_name, sample_values)

        return enriched

    def _fallback_field_analysis(
        self,
        field_name: str,
        sample_values: List[str]
    ) -> EnrichedField:
        """Fallback analysis using heuristics when AI parsing fails."""

        enriched = EnrichedField(
            name=field_name,
            sample_values=list(set(str(v) for v in sample_values if v))[:5]
        )

        field_lower = field_name.lower()

        # Infer category from field name
        if any(x in field_lower for x in ['src', 'source', 'origin']):
            if 'ip' in field_lower or 'addr' in field_lower:
                enriched.semantic_category = "source_ip"
                enriched.suggested_cim_field = "src_ip"
                enriched.mapping_type = "extracted"
            elif 'port' in field_lower:
                enriched.semantic_category = "source_port"
                enriched.suggested_cim_field = "src_port"
                enriched.mapping_type = "calculated"
                enriched.suggested_transformation = f"tonumber({field_name})"
            elif 'user' in field_lower:
                enriched.semantic_category = "source_user"
                enriched.suggested_cim_field = "src_user"
                enriched.mapping_type = "extracted"
            else:
                enriched.semantic_category = "source"
                enriched.suggested_cim_field = "src"
                enriched.mapping_type = "calculated"

        elif any(x in field_lower for x in ['dst', 'dest', 'target']):
            if 'ip' in field_lower or 'addr' in field_lower:
                enriched.semantic_category = "destination_ip"
                enriched.suggested_cim_field = "dest_ip"
                enriched.mapping_type = "extracted"
            elif 'port' in field_lower:
                enriched.semantic_category = "destination_port"
                enriched.suggested_cim_field = "dest_port"
                enriched.mapping_type = "calculated"
                enriched.suggested_transformation = f"tonumber({field_name})"
            elif 'user' in field_lower:
                enriched.semantic_category = "destination_user"
                enriched.suggested_cim_field = "dest_user"
                enriched.mapping_type = "extracted"
            else:
                enriched.semantic_category = "destination"
                enriched.suggested_cim_field = "dest"
                enriched.mapping_type = "calculated"

        elif 'action' in field_lower or 'result' in field_lower or 'status' in field_lower:
            enriched.semantic_category = "action"
            enriched.suggested_cim_field = "action"
            enriched.mapping_type = "calculated"

        elif any(x in field_lower for x in ['user', 'account', 'login']):
            enriched.semantic_category = "user"
            enriched.suggested_cim_field = "user"
            enriched.mapping_type = "calculated"

        elif any(x in field_lower for x in ['proto', 'protocol']):
            enriched.semantic_category = "protocol"
            enriched.suggested_cim_field = "transport"
            enriched.mapping_type = "calculated"
            enriched.suggested_transformation = f"lower({field_name})"

        elif any(x in field_lower for x in ['byte', 'size', 'length']):
            enriched.semantic_category = "bytes"
            if 'in' in field_lower or 'recv' in field_lower:
                enriched.suggested_cim_field = "bytes_in"
            elif 'out' in field_lower or 'sent' in field_lower:
                enriched.suggested_cim_field = "bytes_out"
            else:
                enriched.suggested_cim_field = "bytes"
            enriched.mapping_type = "calculated"
            enriched.suggested_transformation = f"tonumber({field_name})"

        elif any(x in field_lower for x in ['time', 'date', 'timestamp']):
            enriched.semantic_category = "timestamp"
            enriched.mapping_type = "extracted"

        elif any(x in field_lower for x in ['app', 'application', 'service']):
            enriched.semantic_category = "application"
            enriched.suggested_cim_field = "app"
            enriched.mapping_type = "extracted"

        else:
            enriched.semantic_category = "unknown"
            enriched.confidence = 0.3
            enriched.needs_review = True

        return enriched


def create_ai_field_parser(ai_client) -> AIFieldParser:
    """Factory function to create an AI field parser."""
    return AIFieldParser(ai_client)
