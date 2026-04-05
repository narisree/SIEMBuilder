"""
Onboarding Agent - Tier 2 Hybrid Agent for SIEM Log Source Onboarding
Replaces the basic chat tab with a guided, step-aware conversational agent.

Architecture:
- Pre-built structure: Steps extracted from KB section headings
- Claude handles: Conversational layer, environment-specific adaptation, follow-ups
- Only the relevant KB section is sent per step (not the full file) to cut token cost
- Falls back to full-KB freeform chat if no steps are detected

Zero changes to: kb_loader.py, ai_client.py, or any other existing module.
"""

import re
from typing import Dict, List, Optional, Tuple


# ============================================
# KB Section Parser
# ============================================

def extract_kb_sections(kb_content: str) -> List[Dict]:
    """
    Parse a KB markdown file into structured sections.
    
    Each section gets:
      - title: The heading text
      - level: 2 for ##, 3 for ###, etc.
      - content: Full text under that heading (until next same-or-higher heading)
      - index: Position in the list
    
    Returns:
        List of section dicts, ordered as they appear in the KB.
    """
    if not kb_content:
        return []

    sections = []
    lines = kb_content.split('\n')
    current_section = None
    content_lines = []

    for line in lines:
        heading_match = re.match(r'^(#{1,4})\s+(.+)$', line)
        if heading_match:
            # Save previous section
            if current_section is not None:
                current_section['content'] = '\n'.join(content_lines).strip()
                sections.append(current_section)
            
            level = len(heading_match.group(1))
            title = heading_match.group(2).strip()
            current_section = {
                'title': title,
                'level': level,
                'content': '',
                'index': len(sections)
            }
            content_lines = []
        else:
            content_lines.append(line)

    # Don't forget the last section
    if current_section is not None:
        current_section['content'] = '\n'.join(content_lines).strip()
        sections.append(current_section)

    return sections


def get_top_level_steps(sections: List[Dict]) -> List[Dict]:
    """
    Extract top-level (## heading) sections as onboarding 'steps'.
    Sub-sections (###) are included in their parent's content.
    
    Returns:
        List of step dicts with title, content, and index.
    """
    steps = []
    for i, section in enumerate(sections):
        if section['level'] == 2:
            # Gather all content until the next level-2 section
            full_content = section['content']
            # Also include any sub-sections
            for j in range(i + 1, len(sections)):
                if sections[j]['level'] <= 2:
                    break
                full_content += f"\n\n### {sections[j]['title']}\n{sections[j]['content']}"
            
            steps.append({
                'title': section['title'],
                'content': full_content.strip(),
                'index': len(steps),
                'status': 'pending'
            })
    return steps


def get_section_by_title(sections: List[Dict], title_fragment: str) -> Optional[str]:
    """
    Find a section whose title contains the given fragment (case-insensitive).
    Returns the section content or None.
    """
    title_lower = title_fragment.lower()
    for section in sections:
        if title_lower in section['title'].lower():
            return section['content']
    return None


# ============================================
# Agent System Prompt Builder
# ============================================

AGENT_SYSTEM_PROMPT_TEMPLATE = """You are a senior SIEM/Splunk integration specialist acting as an **onboarding agent**.
You are guiding a Security Engineer through onboarding **{source_name}** into Splunk, step by step.

## Your Behavior
- You are conversational but precise. Ask clarifying questions about the engineer's environment.
- Walk through one step at a time. Don't dump the entire guide at once.
- Adapt your guidance based on what the engineer tells you (their Splunk version, deployment type, network layout).
- When generating config snippets, fill in any values the engineer has provided (IPs, index names, ports).
- If the engineer asks a question outside the current step, answer it, then return to the workflow.
- Track progress: remind the engineer which step they're on and what comes next.

## Current Onboarding State
- **Current Step ({current_step_num}/{total_steps}):** {current_step_title}
- **Steps Completed:** {completed_steps}
- **Steps Remaining:** {remaining_steps}

## Environment Context (from conversation so far)
{environment_context}

## KB Content for Current Step
The following is the relevant KB documentation for the current step. Base your guidance on this:

---
{step_kb_content}
---

## Full Step Outline
{step_outline}

## Response Guidelines
1. **Stay grounded** in the KB content. If it doesn't cover something, say so and suggest what to add.
2. **Be practical** — give step-by-step commands, config snippets, and UI navigation paths.
3. **State assumptions** clearly (Splunk version, OS, network topology).
4. **Security first** — flag any security implications.
5. **Splunk-specific** — use proper terminology (inputs.conf, props.conf, outputs.conf, server classes, etc.).
6. **Concise** — no filler paragraphs. Engineers want actionable guidance.
7. When a step is complete, summarize what was done and preview the next step."""


def build_agent_system_prompt(
    source_name: str,
    steps: List[Dict],
    current_step_index: int,
    completed_indices: List[int],
    environment_context: str = "No environment details gathered yet."
) -> str:
    """
    Build the agent system prompt with current step context.
    Only includes the KB content for the current step (not the full file).
    
    Args:
        source_name: Display name of the log source
        steps: List of step dicts from get_top_level_steps()
        current_step_index: Index of the active step
        completed_indices: List of completed step indices
        environment_context: Collected environment info from conversation
    
    Returns:
        Formatted system prompt string
    """
    if not steps:
        return _build_freeform_prompt(source_name, "")

    # Clamp index
    current_step_index = max(0, min(current_step_index, len(steps) - 1))
    current_step = steps[current_step_index]

    # Build step outline
    outline_lines = []
    for i, step in enumerate(steps):
        if i in completed_indices:
            marker = "✅"
        elif i == current_step_index:
            marker = "👉"
        else:
            marker = "⬜"
        outline_lines.append(f"{marker} Step {i + 1}: {step['title']}")

    completed_names = [steps[i]['title'] for i in completed_indices if i < len(steps)]
    remaining = [s['title'] for i, s in enumerate(steps) if i not in completed_indices and i != current_step_index]

    return AGENT_SYSTEM_PROMPT_TEMPLATE.format(
        source_name=source_name,
        current_step_num=current_step_index + 1,
        total_steps=len(steps),
        current_step_title=current_step['title'],
        completed_steps=', '.join(completed_names) if completed_names else 'None yet',
        remaining_steps=', '.join(remaining) if remaining else 'None — this is the last step!',
        environment_context=environment_context,
        step_kb_content=current_step['content'][:8000],  # Hard cap per step
        step_outline='\n'.join(outline_lines)
    )


def _build_freeform_prompt(source_name: str, kb_content: str) -> str:
    """Fallback prompt when no steps can be extracted (e.g., stub KB)."""
    return f"""You are a senior SIEM/Splunk integration specialist assistant.
You are helping with the integration of: **{source_name}**

The KB for this source is limited. Answer questions based on your expertise and clearly
state when you're going beyond what the KB covers.

## KB Content
---
{kb_content[:16000]}
---

Provide practical, step-by-step Splunk integration guidance."""


# ============================================
# Agent State Manager
# ============================================

class OnboardingAgentState:
    """
    Manages agent state within st.session_state.
    All keys are namespaced with 'agent_' to avoid collisions.
    """

    @staticmethod
    def init_state(session_state, source_slug: str, steps: List[Dict]):
        """Initialize or reset agent state for a source."""
        session_state['agent_source'] = source_slug
        session_state['agent_steps'] = steps
        session_state['agent_current_step'] = 0
        session_state['agent_completed'] = []
        session_state['agent_environment'] = {}
        session_state['agent_messages'] = []
        session_state['agent_mode'] = 'guided' if steps else 'freeform'

    @staticmethod
    def needs_reset(session_state, source_slug: str) -> bool:
        """Check if agent state needs to be (re)initialized for a different source."""
        return session_state.get('agent_source') != source_slug

    @staticmethod
    def get_steps(session_state) -> List[Dict]:
        return session_state.get('agent_steps', [])

    @staticmethod
    def get_current_step(session_state) -> int:
        return session_state.get('agent_current_step', 0)

    @staticmethod
    def set_current_step(session_state, index: int):
        session_state['agent_current_step'] = index

    @staticmethod
    def get_completed(session_state) -> List[int]:
        return session_state.get('agent_completed', [])

    @staticmethod
    def mark_step_complete(session_state, index: int):
        completed = session_state.get('agent_completed', [])
        if index not in completed:
            completed.append(index)
            session_state['agent_completed'] = completed

    @staticmethod
    def unmark_step_complete(session_state, index: int):
        completed = session_state.get('agent_completed', [])
        if index in completed:
            completed.remove(index)
            session_state['agent_completed'] = completed

    @staticmethod
    def toggle_step(session_state, index: int):
        completed = session_state.get('agent_completed', [])
        if index in completed:
            completed.remove(index)
        else:
            completed.append(index)
        session_state['agent_completed'] = completed

    @staticmethod
    def get_messages(session_state) -> List[Dict]:
        return session_state.get('agent_messages', [])

    @staticmethod
    def add_message(session_state, role: str, content: str):
        messages = session_state.get('agent_messages', [])
        messages.append({"role": role, "content": content})
        session_state['agent_messages'] = messages

    @staticmethod
    def get_environment(session_state) -> Dict:
        return session_state.get('agent_environment', {})

    @staticmethod
    def update_environment(session_state, key: str, value: str):
        env = session_state.get('agent_environment', {})
        env[key] = value
        session_state['agent_environment'] = env

    @staticmethod
    def get_mode(session_state) -> str:
        return session_state.get('agent_mode', 'freeform')

    @staticmethod
    def format_environment_context(session_state) -> str:
        """Format collected environment details into a string for the prompt."""
        env = session_state.get('agent_environment', {})
        if not env:
            return "No environment details gathered yet."
        lines = [f"- {k}: {v}" for k, v in env.items()]
        return '\n'.join(lines)

    @staticmethod
    def advance_to_next_step(session_state):
        """Move to the next incomplete step."""
        steps = session_state.get('agent_steps', [])
        current = session_state.get('agent_current_step', 0)
        completed = session_state.get('agent_completed', [])
        
        # Try next step
        for i in range(current + 1, len(steps)):
            if i not in completed:
                session_state['agent_current_step'] = i
                return i
        
        # If all remaining are done, stay on current
        return current
