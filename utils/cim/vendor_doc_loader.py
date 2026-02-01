"""
Vendor Documentation Loader Module
Handles loading and processing of optional vendor documentation to enhance
AI field parsing and CIM mapping accuracy.

Supports:
- PDF files (requires pypdf or PyPDF2)
- Markdown files (.md)
- Text files (.txt)
- HTML files (.html) - basic text extraction
"""
import re
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass, field


@dataclass
class VendorDocResult:
    """Result of vendor documentation processing."""
    success: bool
    content: str = ""
    doc_type: str = ""  # "pdf", "markdown", "text", "html"
    sections: List[Dict[str, str]] = field(default_factory=list)
    field_definitions: Dict[str, str] = field(default_factory=dict)
    extracted_vendor: Optional[str] = None
    extracted_product: Optional[str] = None
    error: Optional[str] = None


class VendorDocLoader:
    """
    Loads and processes vendor documentation to extract field definitions
    and context for improved AI field parsing.
    """

    # Common field definition patterns in vendor docs
    FIELD_PATTERNS = [
        # Pattern: "field_name: description" or "field_name - description"
        r'^[\s*-]*`?(\w+)`?[:\s-]+(.+?)(?:\.|$)',
        # Pattern: table format "| field_name | description |"
        r'\|\s*`?(\w+)`?\s*\|\s*(.+?)\s*\|',
        # Pattern: "field_name (type) - description"
        r'^[\s*-]*`?(\w+)`?\s*\([^)]+\)[:\s-]+(.+?)(?:\.|$)',
    ]

    # Patterns to identify field definition sections
    SECTION_PATTERNS = [
        r'(?:field|column|attribute|parameter)\s*(?:definition|description|reference)',
        r'(?:log|event)\s*(?:field|format|schema)',
        r'(?:data|output)\s*(?:field|dictionary)',
        r'field\s*name.*description',
    ]

    def load_document(self, content: bytes, filename: str) -> VendorDocResult:
        """
        Load and process a vendor documentation file.

        Args:
            content: Raw file content as bytes
            filename: Original filename (used for type detection)

        Returns:
            VendorDocResult with extracted content and field definitions
        """
        filename_lower = filename.lower()

        try:
            if filename_lower.endswith('.pdf'):
                return self._load_pdf(content)
            elif filename_lower.endswith('.md'):
                return self._load_markdown(content)
            elif filename_lower.endswith('.txt'):
                return self._load_text(content)
            elif filename_lower.endswith('.html') or filename_lower.endswith('.htm'):
                return self._load_html(content)
            else:
                # Try to decode as text by default
                return self._load_text(content)
        except Exception as e:
            return VendorDocResult(
                success=False,
                error=f"Failed to load document: {str(e)}"
            )

    def _load_pdf(self, content: bytes) -> VendorDocResult:
        """Load and extract text from PDF document."""
        try:
            # Try pypdf first (newer)
            try:
                from pypdf import PdfReader
                from io import BytesIO

                reader = PdfReader(BytesIO(content))
                text_parts = []

                for page in reader.pages:
                    text = page.extract_text()
                    if text:
                        text_parts.append(text)

                full_text = "\n\n".join(text_parts)

            except ImportError:
                # Fallback to PyPDF2
                try:
                    from PyPDF2 import PdfReader
                    from io import BytesIO

                    reader = PdfReader(BytesIO(content))
                    text_parts = []

                    for page in reader.pages:
                        text = page.extract_text()
                        if text:
                            text_parts.append(text)

                    full_text = "\n\n".join(text_parts)

                except ImportError:
                    return VendorDocResult(
                        success=False,
                        error="PDF support requires 'pypdf' or 'PyPDF2'. Install with: pip install pypdf"
                    )

            result = VendorDocResult(
                success=True,
                content=full_text,
                doc_type="pdf"
            )

            # Extract field definitions
            self._extract_field_definitions(result)
            self._extract_vendor_product(result)

            return result

        except Exception as e:
            return VendorDocResult(
                success=False,
                error=f"PDF parsing failed: {str(e)}"
            )

    def _load_markdown(self, content: bytes) -> VendorDocResult:
        """Load and process Markdown document."""
        try:
            text = content.decode('utf-8', errors='ignore')

            result = VendorDocResult(
                success=True,
                content=text,
                doc_type="markdown"
            )

            # Extract sections from markdown headers
            result.sections = self._extract_markdown_sections(text)

            # Extract field definitions
            self._extract_field_definitions(result)
            self._extract_vendor_product(result)

            return result

        except Exception as e:
            return VendorDocResult(
                success=False,
                error=f"Markdown parsing failed: {str(e)}"
            )

    def _load_text(self, content: bytes) -> VendorDocResult:
        """Load plain text document."""
        try:
            # Try UTF-8 first, then fall back to latin-1
            try:
                text = content.decode('utf-8')
            except UnicodeDecodeError:
                text = content.decode('latin-1', errors='ignore')

            result = VendorDocResult(
                success=True,
                content=text,
                doc_type="text"
            )

            # Extract field definitions
            self._extract_field_definitions(result)
            self._extract_vendor_product(result)

            return result

        except Exception as e:
            return VendorDocResult(
                success=False,
                error=f"Text parsing failed: {str(e)}"
            )

    def _load_html(self, content: bytes) -> VendorDocResult:
        """Load and extract text from HTML document."""
        try:
            text = content.decode('utf-8', errors='ignore')

            # Basic HTML tag stripping
            # Remove script and style elements
            text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.DOTALL | re.IGNORECASE)
            text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.DOTALL | re.IGNORECASE)

            # Remove HTML tags
            text = re.sub(r'<[^>]+>', ' ', text)

            # Decode HTML entities
            text = text.replace('&nbsp;', ' ')
            text = text.replace('&lt;', '<')
            text = text.replace('&gt;', '>')
            text = text.replace('&amp;', '&')
            text = text.replace('&quot;', '"')

            # Clean up whitespace
            text = re.sub(r'\s+', ' ', text)
            text = re.sub(r'\n\s*\n', '\n\n', text)

            result = VendorDocResult(
                success=True,
                content=text.strip(),
                doc_type="html"
            )

            # Extract field definitions
            self._extract_field_definitions(result)
            self._extract_vendor_product(result)

            return result

        except Exception as e:
            return VendorDocResult(
                success=False,
                error=f"HTML parsing failed: {str(e)}"
            )

    def _extract_markdown_sections(self, text: str) -> List[Dict[str, str]]:
        """Extract sections from markdown headers."""
        sections = []
        current_section = {"title": "", "content": "", "level": 0}

        lines = text.split('\n')
        content_buffer = []

        for line in lines:
            # Check for headers
            header_match = re.match(r'^(#{1,6})\s+(.+)$', line)
            if header_match:
                # Save previous section
                if current_section["title"]:
                    current_section["content"] = '\n'.join(content_buffer).strip()
                    sections.append(current_section.copy())

                # Start new section
                level = len(header_match.group(1))
                current_section = {
                    "title": header_match.group(2),
                    "content": "",
                    "level": level
                }
                content_buffer = []
            else:
                content_buffer.append(line)

        # Don't forget the last section
        if current_section["title"]:
            current_section["content"] = '\n'.join(content_buffer).strip()
            sections.append(current_section)

        return sections

    def _extract_field_definitions(self, result: VendorDocResult) -> None:
        """Extract field definitions from document content."""
        content = result.content
        field_defs = {}

        # Find field definition sections
        relevant_sections = self._find_field_sections(content, result.sections)

        # Search in relevant sections first
        for section in relevant_sections:
            section_text = section.get("content", "")
            self._extract_fields_from_text(section_text, field_defs)

        # Also search full content for any missed definitions
        self._extract_fields_from_text(content, field_defs)

        result.field_definitions = field_defs

    def _find_field_sections(
        self,
        content: str,
        sections: List[Dict[str, str]]
    ) -> List[Dict[str, str]]:
        """Find sections that likely contain field definitions."""
        relevant = []

        for section in sections:
            title = section.get("title", "").lower()
            for pattern in self.SECTION_PATTERNS:
                if re.search(pattern, title, re.IGNORECASE):
                    relevant.append(section)
                    break

        # If no sections found, check full content for field areas
        if not relevant and sections:
            # Return sections that have table-like content
            for section in sections:
                content_sample = section.get("content", "")[:500]
                if '|' in content_sample or ':' in content_sample:
                    relevant.append(section)

        return relevant

    def _extract_fields_from_text(
        self,
        text: str,
        field_defs: Dict[str, str]
    ) -> None:
        """Extract field definitions from text using patterns."""

        # Look for table-style definitions (common in docs)
        # Pattern: | field_name | type | description |
        table_pattern = r'\|\s*`?(\w{2,50})`?\s*\|\s*(?:\w+\s*\|)?\s*(.{10,200}?)\s*\|'
        for match in re.finditer(table_pattern, text):
            field_name = match.group(1).strip()
            description = match.group(2).strip()
            if field_name and description and field_name not in field_defs:
                # Skip if it looks like a header row
                if description.lower() not in ['description', 'type', 'value', 'format']:
                    field_defs[field_name] = description

        # Look for definition list style
        # Pattern: **field_name** - description
        deflist_pattern = r'\*\*(\w{2,50})\*\*\s*[-:]\s*(.{10,200}?)(?:\n|$)'
        for match in re.finditer(deflist_pattern, text):
            field_name = match.group(1).strip()
            description = match.group(2).strip()
            if field_name and description and field_name not in field_defs:
                field_defs[field_name] = description

        # Look for backtick field names
        # Pattern: `field_name`: description
        backtick_pattern = r'`(\w{2,50})`\s*[-:]\s*(.{10,200}?)(?:\n|$)'
        for match in re.finditer(backtick_pattern, text):
            field_name = match.group(1).strip()
            description = match.group(2).strip()
            if field_name and description and field_name not in field_defs:
                field_defs[field_name] = description

    def _extract_vendor_product(self, result: VendorDocResult) -> None:
        """Try to extract vendor and product names from document."""
        content = result.content[:2000]  # Check first part of doc

        # Common vendor patterns
        vendor_patterns = [
            r'(?:palo\s*alto|pan(?:os)?)',
            r'(?:cisco|ios)',
            r'(?:microsoft|windows|azure)',
            r'(?:crowdstrike|falcon)',
            r'(?:fortinet|fortigate)',
            r'(?:check\s*point)',
            r'(?:zscaler)',
            r'(?:proofpoint)',
            r'(?:symantec|broadcom)',
            r'(?:splunk)',
            r'(?:aws|amazon)',
            r'(?:google|gcp)',
        ]

        content_lower = content.lower()
        for pattern in vendor_patterns:
            match = re.search(pattern, content_lower)
            if match:
                result.extracted_vendor = match.group(0).title()
                break

        # Product patterns
        product_patterns = [
            (r'(?:ngfw|firewall)', 'Firewall'),
            (r'(?:proxy|web\s*gateway)', 'Proxy'),
            (r'(?:edr|endpoint)', 'EDR'),
            (r'(?:email\s*security|email\s*gateway)', 'Email Security'),
            (r'(?:siem|security\s*information)', 'SIEM'),
            (r'(?:asa|firepower)', 'ASA'),
            (r'(?:active\s*directory|ad)', 'Active Directory'),
            (r'(?:office\s*365|o365)', 'Office 365'),
        ]

        for pattern, product in product_patterns:
            if re.search(pattern, content_lower):
                result.extracted_product = product
                break

    def get_context_for_ai(
        self,
        result: VendorDocResult,
        max_length: int = 10000
    ) -> str:
        """
        Format vendor documentation for AI consumption.

        Args:
            result: VendorDocResult from document loading
            max_length: Maximum character length for output

        Returns:
            Formatted string optimized for AI field parsing
        """
        if not result.success:
            return ""

        parts = []

        # Header
        if result.extracted_vendor or result.extracted_product:
            parts.append("## Vendor Documentation Reference")
            if result.extracted_vendor:
                parts.append(f"**Vendor:** {result.extracted_vendor}")
            if result.extracted_product:
                parts.append(f"**Product:** {result.extracted_product}")
            parts.append("")

        # Field definitions (prioritize these)
        if result.field_definitions:
            parts.append("### Field Definitions from Documentation")
            parts.append("")
            parts.append("| Field Name | Description |")
            parts.append("|------------|-------------|")

            for field_name, description in list(result.field_definitions.items())[:50]:
                # Truncate long descriptions
                desc = description[:100] + "..." if len(description) > 100 else description
                parts.append(f"| `{field_name}` | {desc} |")

            parts.append("")

        # Add relevant content sections
        current_length = len('\n'.join(parts))
        remaining_length = max_length - current_length

        if remaining_length > 500:
            parts.append("### Additional Documentation Context")
            parts.append("")

            # Prioritize sections with field-related content
            content_to_add = result.content[:remaining_length - 200]

            # Try to end at a paragraph break
            last_break = content_to_add.rfind('\n\n')
            if last_break > remaining_length * 0.7:
                content_to_add = content_to_add[:last_break]

            parts.append(content_to_add)

            if len(result.content) > remaining_length:
                parts.append("")
                parts.append("*[Documentation truncated for length]*")

        return '\n'.join(parts)


def create_vendor_doc_loader() -> VendorDocLoader:
    """Factory function to create a vendor document loader."""
    return VendorDocLoader()
