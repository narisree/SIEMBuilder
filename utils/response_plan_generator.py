"""
Response Plan Generator
Generates detection-specific response plans using AI, with disk caching.
Implements Layer 1 (Use Case Response Plans) and Layer 2 (Escalation Bridge).
"""

import os
import re
import hashlib
from pathlib import Path
from typing import Dict, List, Optional


class ResponsePlanGenerator:
    """Generates and caches detection-specific response plans."""
    
    def __init__(self, cache_dir: str = "response_plans", playbooks_path: str = "Playbooks"):
        """
        Initialize the generator.
        
        Args:
            cache_dir: Directory to store generated response plan markdown files
            playbooks_path: Directory containing IRP markdown files
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.playbooks_path = Path(playbooks_path)
    
    def _make_slug(self, use_case_name: str) -> str:
        """Create a filesystem-safe slug from a use case name."""
        # Lowercase, replace non-alphanumeric with underscore, collapse multiples
        slug = re.sub(r'[^a-z0-9]+', '_', use_case_name.lower()).strip('_')
        # Truncate to reasonable length
        if len(slug) > 80:
            slug = slug[:80].rstrip('_')
        return slug
    
    def _get_cache_path(self, use_case_name: str) -> Path:
        """Get the cache file path for a use case."""
        slug = self._make_slug(use_case_name)
        return self.cache_dir / f"{slug}.md"
    
    def get_cached_plan(self, use_case_name: str) -> Optional[str]:
        """
        Check if a response plan is already cached on disk.
        
        Returns:
            Cached markdown content, or None if not cached
        """
        cache_path = self._get_cache_path(use_case_name)
        if cache_path.exists():
            try:
                with open(cache_path, 'r', encoding='utf-8') as f:
                    return f.read()
            except Exception:
                return None
        return None
    
    def _save_to_cache(self, use_case_name: str, content: str) -> bool:
        """Save generated plan to disk cache."""
        cache_path = self._get_cache_path(use_case_name)
        try:
            with open(cache_path, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        except Exception:
            return False
    
    def get_all_cached_plans(self) -> List[Dict]:
        """List all cached response plans."""
        plans = []
        if self.cache_dir.exists():
            for f in sorted(self.cache_dir.glob("*.md")):
                # Read first line to get the title
                try:
                    with open(f, 'r', encoding='utf-8') as fh:
                        first_line = fh.readline().strip()
                        title = first_line.lstrip('# ').strip() if first_line.startswith('#') else f.stem
                except Exception:
                    title = f.stem
                plans.append({
                    "filename": f.name,
                    "title": title,
                    "path": str(f)
                })
        return plans
    
    def _load_irp_summary(self, irp_filename: str) -> str:
        """Load a condensed version of an IRP for prompt context."""
        filepath = self.playbooks_path / irp_filename
        if not filepath.exists():
            return ""
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Extract just the scope and severity sections to keep prompt size manageable
            lines = content.split('\n')
            summary_lines = []
            include = False
            section_count = 0
            
            for line in lines:
                if line.startswith('# '):
                    summary_lines.append(line)
                    include = True
                    continue
                if line.startswith('## Scope'):
                    include = True
                elif line.startswith('## 2. Detection'):
                    include = True
                elif line.startswith('## 4. Contain'):
                    include = True
                elif line.startswith('## ') and include:
                    section_count += 1
                    if section_count > 3:
                        include = False
                        continue
                
                if include:
                    summary_lines.append(line)
            
            return '\n'.join(summary_lines[:150])  # Cap at ~150 lines
        except Exception:
            return ""
    
    def _build_generation_prompt(self, use_case: Dict, irp_keys: List[str]) -> str:
        """Build the system prompt for response plan generation."""
        
        # Load relevant IRP summaries
        from utils.irp_loader import IRPLoader
        irp_loader = IRPLoader(str(self.playbooks_path))
        
        irp_context = ""
        for key in irp_keys[:2]:  # Max 2 IRPs to keep prompt size down
            info = irp_loader.IRP_CATALOG.get(key, {})
            filename = info.get("filename", "")
            summary = self._load_irp_summary(filename)
            if summary:
                irp_context += f"\n### {info.get('display_name', key)} IRP (Escalation Target)\n{summary}\n"
        
        system_prompt = f"""You are a senior SOC detection engineer creating a Use Case Response Plan (a detection-specific runbook for L1/L2 analysts).

## Output Format
Generate a markdown response plan with EXACTLY these sections:

# Response Plan: [Use Case Name]

## Overview
| Field | Value |
|-------|-------|
| **Use Case** | [name] |
| **MITRE Tactic** | [tactic] |
| **MITRE Technique** | [technique] |
| **Severity** | [Low/Medium/High/Critical] |
| **Log Source** | [source] |
| **Escalation IRP** | [which IRP(s) to escalate to] |

## What This Detects
2-3 sentences explaining what this detection identifies and why it matters, written for an L1 analyst.

## Triage Steps
Numbered steps (5-8) that an L1 analyst should follow when this alert fires. Be specific — reference actual field names from the SPL query where possible.

## True Positive Indicators
Bullet list of 3-5 signs that confirm this is a real threat.

## False Positive Scenarios
Bullet list of 3-5 common benign explanations for this alert firing.

## Containment Actions
Numbered steps (3-5) for immediate containment if confirmed malicious.

## Escalation Path
- When to escalate and to which IRP
- Specific conditions that trigger escalation
- What information to include in the escalation

## Reference SPL
The original detection query in a code block.

## IMPORTANT RULES:
- Write for an L1/L2 SOC analyst, not a senior engineer
- Be specific and actionable, not generic
- Reference field names from the actual SPL query
- Keep the total response under 400 lines
- Do NOT include mermaid diagrams
- Do NOT include generic boilerplate — every line should be specific to THIS detection

{irp_context}"""
        
        return system_prompt
    
    def _build_user_message(self, use_case: Dict) -> str:
        """Build the user message containing the use case details."""
        name = use_case.get('Use case Name', 'Unknown')
        description = use_case.get('Description', 'N/A')
        log_source = use_case.get('Log Source', 'N/A')
        tactics = use_case.get('MITRE Tactics', 'N/A')
        technique = use_case.get('MITRE Technique', 'N/A')
        spl = use_case.get('SPL', use_case.get('SPL ', 'N/A'))
        
        return f"""Generate a response plan for this detection use case:

**Use Case Name:** {name}
**Description:** {description}
**Log Source:** {log_source}
**MITRE Tactics:** {tactics}
**MITRE Technique:** {technique}
**SPL Query:**
```spl
{spl}
```

Generate the complete response plan now."""
    
    def generate_plan(self, use_case: Dict, ai_client, irp_keys: List[str] = None) -> Dict:
        """
        Generate a response plan for a use case.
        
        Args:
            use_case: Use case dictionary with standard fields
            ai_client: An AI client instance (ClaudeClient, GroqClient, etc.)
            irp_keys: List of relevant IRP keys for escalation context
            
        Returns:
            Dict with 'success', 'content', 'message', 'cached' keys
        """
        name = use_case.get('Use case Name', '')
        if not name:
            return {"success": False, "content": "", "message": "Use case has no name", "cached": False}
        
        # Check cache first
        cached = self.get_cached_plan(name)
        if cached:
            return {"success": True, "content": cached, "message": "Loaded from cache", "cached": True}
        
        # Generate using AI
        if irp_keys is None:
            from utils.irp_loader import IRPLoader
            irp_loader = IRPLoader(str(self.playbooks_path))
            irp_keys = irp_loader.get_irps_for_tactic(use_case.get('MITRE Tactics', ''))
        
        system_prompt = self._build_generation_prompt(use_case, irp_keys)
        user_message = self._build_user_message(use_case)
        
        try:
            # Use the ai_client's get_response method
            # We pass the system prompt as kb_content and source_name contextually
            response = ai_client.get_response(
                question=user_message,
                kb_content=system_prompt,  # System prompt goes via kb_content path
                source_name="Response Plan Generator",
                chat_history=None
            )
            
            if response.get("success"):
                content = response["response"]
                # Save to cache
                self._save_to_cache(name, content)
                return {
                    "success": True,
                    "content": content,
                    "message": f"Generated using {ai_client.get_provider_name() if hasattr(ai_client, 'get_provider_name') else 'AI'}",
                    "cached": False
                }
            else:
                return {
                    "success": False,
                    "content": "",
                    "message": response.get("message", "Generation failed"),
                    "cached": False
                }
        except Exception as e:
            return {
                "success": False,
                "content": "",
                "message": f"Error generating plan: {str(e)}",
                "cached": False
            }
    
    def delete_cached_plan(self, use_case_name: str) -> bool:
        """Delete a cached plan to force regeneration."""
        cache_path = self._get_cache_path(use_case_name)
        try:
            if cache_path.exists():
                cache_path.unlink()
                return True
            return False
        except Exception:
            return False
