"""
Agent Chat Tab Renderer (v2 — Side-Panel Layout)
Clean chat bubble interface with contextual side panel.
No step checklist inside the chat — just a progress bar + quick reference + log types.
"""

import re
import streamlit as st
from typing import Optional
from utils.onboarding_agent import (
    extract_kb_sections,
    get_top_level_steps,
    build_agent_system_prompt,
    OnboardingAgentState
)


# ============================================
# Log type mapping per source (for side panel)
# ============================================

SOURCE_LOG_TYPES = {
    "palo_alto": ["Traffic", "Threat", "URL Filtering", "Authentication", "GlobalProtect", "Config"],
    "windows_events": ["Security", "Application", "System"],
    "sysmon_windows": ["Process Create", "Network Connect", "File Create", "Registry", "DNS Query"],
    "powershell_scriptblock": ["Script Block", "Module Logging", "Transcription"],
    "aws_cloudtrail": ["Management Events", "Data Events", "Insights"],
    "sysmon_linux": ["Process Create", "Network Connect", "File Create"],
    "okta": ["Authentication", "Admin", "System", "User Lifecycle"],
    "cisco_ftd": ["Connection", "Intrusion", "File/Malware", "Security Intelligence"],
    "suricata": ["Alert", "HTTP", "DNS", "TLS", "Flow"],
    "kubernetes": ["API Audit", "Container", "Node", "Pod"],
    "vmware_esxi": ["Hostd", "Vpxa", "Vobd", "Shell"],
    "github": ["Audit", "Git", "Webhook"],
    "nginx": ["Access", "Error"],
    "linux": ["auth.log", "syslog", "audit.log", "kern.log"],
    "azure_ad": ["Sign-in", "Audit", "Provisioning", "Risk Events"],
    "cisco_asa": ["Firewall", "VPN", "NAT", "ACL"],
    "checkpoint": ["Firewall", "VPN", "IPS", "URL Filtering"],
    "crowdstrike_edr": ["Detection", "Incident", "Audit"],
    "o365": ["Exchange", "SharePoint", "Azure AD", "DLP"],
    "proofpoint": ["Message", "Click", "URL Defense"],
    "zscaler_proxy": ["Web", "Firewall", "DNS"],
}


def _get_port_info(source_slug: str) -> str:
    """Derive port info from source slug."""
    port_map = {
        "palo_alto": "UDP 514/515",
        "windows_events": "TCP 9997",
        "sysmon_windows": "TCP 9997",
        "powershell_scriptblock": "TCP 9997",
        "linux": "TCP 9997 / UDP 514",
        "cisco_asa": "UDP 514",
        "checkpoint": "TCP 18184 / UDP 514",
        "cisco_ftd": "UDP 514",
        "suricata": "TCP 9997",
        "vmware_esxi": "UDP 514",
        "nginx": "TCP 9997",
        "azure_ad": "HTTPS 443",
        "crowdstrike_edr": "HTTPS 443",
        "o365": "HTTPS 443",
        "okta": "HTTPS 443",
        "aws_cloudtrail": "HTTPS 443",
        "proofpoint": "UDP 514 / HTTPS 443",
        "zscaler_proxy": "TCP 9997",
        "github": "HTTPS 443",
        "kubernetes": "HTTPS 443 / TCP 9997",
        "sysmon_linux": "TCP 9997",
    }
    return port_map.get(source_slug, "—")


def _md_to_safe_html(text: str) -> str:
    """
    Convert markdown text to safe HTML for chat bubbles.
    Handles: bold, italic, code blocks, inline code, line breaks, lists.
    """
    # Escape HTML entities first
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    # Code blocks (``` ... ```)
    def _code_block(match):
        code = match.group(1).strip()
        return (
            f'<pre style="background:#1e293b;color:#e2e8f0;padding:12px 16px;'
            f'border-radius:8px;font-size:12px;overflow-x:auto;'
            f"font-family:'SF Mono','Consolas',monospace;margin:8px 0;\">"
            f'<code>{code}</code></pre>'
        )
    text = re.sub(r'```(?:\w*)\n?(.*?)```', _code_block, text, flags=re.DOTALL)

    # Inline code (`...`)
    text = re.sub(
        r'`([^`]+)`',
        r"<code style=\"background:#e5e7eb;padding:2px 6px;border-radius:4px;"
        r"font-size:12px;font-family:'SF Mono','Consolas',monospace;\">\1</code>",
        text
    )

    # Bold (**...**)
    text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)

    # Italic (*...*)
    text = re.sub(r'(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)', r'<em>\1</em>', text)

    # Bullet lists
    lines = text.split('\n')
    result_lines = []
    in_ul = False
    in_ol = False
    for line in lines:
        stripped = line.strip()
        is_bullet = bool(re.match(r'^[-*•]\s+', stripped))
        is_numbered = bool(re.match(r'^\d+\.\s+', stripped))

        if is_bullet:
            if not in_ul:
                if in_ol:
                    result_lines.append('</ol>')
                    in_ol = False
                result_lines.append('<ul style="margin:6px 0;padding-left:20px;">')
                in_ul = True
            item = re.sub(r'^[-*•]\s+', '', stripped)
            result_lines.append(f'<li style="margin:3px 0;font-size:14px;">{item}</li>')
        elif is_numbered:
            if not in_ol:
                if in_ul:
                    result_lines.append('</ul>')
                    in_ul = False
                result_lines.append('<ol style="margin:6px 0;padding-left:20px;">')
                in_ol = True
            item = re.sub(r'^\d+\.\s+', '', stripped)
            result_lines.append(f'<li style="margin:3px 0;font-size:14px;">{item}</li>')
        else:
            if in_ul:
                result_lines.append('</ul>')
                in_ul = False
            if in_ol:
                result_lines.append('</ol>')
                in_ol = False
            result_lines.append(line)

    if in_ul:
        result_lines.append('</ul>')
    if in_ol:
        result_lines.append('</ol>')
    text = '\n'.join(result_lines)

    # Paragraphs (double newlines)
    text = re.sub(
        r'\n\n+',
        '</p><p style="margin:8px 0;font-size:14px;line-height:1.7;">',
        text
    )

    # Single newlines → <br>
    text = text.replace('\n', '<br>')

    # Wrap in paragraph
    text = f'<p style="margin:8px 0;font-size:14px;line-height:1.7;">{text}</p>'

    return text


# ============================================
# Main renderer
# ============================================

def render_agent_chat_tab(
    selected_source: str,
    source_display_name: str,
    kb_loader,
    has_api_key: bool,
    api_key: Optional[str],
    has_groq_key: bool,
    groq_key: Optional[str]
):
    """
    Render the Agent Chat tab with side-panel layout.
    Chat bubbles on the left, context panel on the right.
    """

    # ── Load KB and extract steps ──
    kb_content = kb_loader.load_kb_content(selected_source) or ""
    sections = extract_kb_sections(kb_content)
    steps = get_top_level_steps(sections)

    # ── Initialize / reset agent state if source changed ──
    if OnboardingAgentState.needs_reset(st.session_state, selected_source):
        OnboardingAgentState.init_state(st.session_state, selected_source, steps)

    agent_mode = OnboardingAgentState.get_mode(st.session_state)
    current_steps = OnboardingAgentState.get_steps(st.session_state)
    current_step_idx = OnboardingAgentState.get_current_step(st.session_state)
    completed = OnboardingAgentState.get_completed(st.session_state)
    messages = OnboardingAgentState.get_messages(st.session_state)

    # ── Source metadata ──
    source_meta = kb_loader.get_source_metadata(selected_source) or {}
    log_types = SOURCE_LOG_TYPES.get(selected_source, [])

    # ============================================
    # CUSTOM CSS
    # ============================================
    st.markdown("""
    <style>
    .agent-bubble {
        background-color: #f0f2f6;
        border-radius: 16px 16px 16px 4px;
        padding: 16px 20px;
        margin-bottom: 12px;
        max-width: 100%;
        border: 1px solid #e0e3e8;
    }
    .agent-label {
        font-size: 11px;
        font-weight: 700;
        color: #3b82f6;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-bottom: 6px;
    }
    .user-bubble {
        background: linear-gradient(135deg, #3b82f6, #2563eb);
        color: white !important;
        border-radius: 16px 16px 4px 16px;
        padding: 14px 20px;
        margin-bottom: 12px;
        margin-left: 15%;
        max-width: 85%;
        text-align: left;
    }
    .user-bubble p, .user-bubble li, .user-bubble code,
    .user-bubble strong, .user-bubble em {
        color: white !important;
    }
    .panel-card {
        background-color: #f8f9fb;
        border: 1px solid #e5e7eb;
        border-radius: 12px;
        padding: 16px 18px;
        margin-bottom: 14px;
    }
    .panel-title {
        font-size: 12px;
        font-weight: 700;
        color: #6b7280;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        margin-bottom: 12px;
    }
    .ref-row {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 6px 0;
        border-bottom: 1px solid #f0f1f3;
    }
    .ref-row:last-child { border-bottom: none; }
    .ref-label { font-size: 13px; color: #6b7280; }
    .ref-value {
        font-size: 13px;
        font-family: 'SF Mono', 'Consolas', monospace;
        color: #3b82f6;
        font-weight: 600;
    }
    .log-tag {
        display: inline-block;
        background-color: #ecfdf5;
        color: #059669;
        font-size: 12px;
        font-weight: 500;
        padding: 3px 10px;
        border-radius: 6px;
        border: 1px solid #a7f3d0;
        margin: 3px 4px 3px 0;
    }
    </style>
    """, unsafe_allow_html=True)

    # ============================================
    # TWO-COLUMN LAYOUT
    # ============================================
    chat_col, panel_col = st.columns([7, 3])

    # ============================================
    # RIGHT PANEL
    # ============================================
    with panel_col:

        # ── Onboarding Progress ──
        if agent_mode == 'guided' and current_steps:
            progress_pct = len(completed) / len(current_steps)
            st.markdown(f"""
            <div class="panel-card">
                <div class="panel-title">Onboarding Progress</div>
                <div style="background:#e5e7eb;border-radius:6px;height:8px;overflow:hidden;margin-bottom:6px;">
                    <div style="width:{progress_pct*100:.0f}%;height:100%;background:linear-gradient(90deg,#10b981,#06b6d4);border-radius:6px;transition:width 0.5s;"></div>
                </div>
                <div style="text-align:right;font-size:12px;color:#6b7280;">{len(completed)}/{len(current_steps)} steps complete</div>
            </div>
            """, unsafe_allow_html=True)

        # ── Quick Reference ──
        index_val = source_meta.get('primary_index', '—')
        sourcetype_val = source_meta.get('primary_sourcetype', '—')
        addon_val = source_meta.get('splunk_addon', '—')
        port_val = _get_port_info(selected_source)
        method_val = source_meta.get('collection_method', '—')

        st.markdown(f"""
        <div class="panel-card">
            <div class="panel-title">Quick Reference</div>
            <div class="ref-row"><span class="ref-label">Index</span><span class="ref-value">{index_val}</span></div>
            <div class="ref-row"><span class="ref-label">Sourcetype</span><span class="ref-value">{sourcetype_val}</span></div>
            <div class="ref-row"><span class="ref-label">Add-on</span><span class="ref-value">{addon_val}</span></div>
            <div class="ref-row"><span class="ref-label">Port</span><span class="ref-value">{port_val}</span></div>
            <div class="ref-row"><span class="ref-label">Method</span><span class="ref-value">{method_val}</span></div>
        </div>
        """, unsafe_allow_html=True)

        # ── Log Types ──
        if log_types:
            tags_html = ''.join([f'<span class="log-tag">{lt}</span>' for lt in log_types])
            st.markdown(f"""
            <div class="panel-card">
                <div class="panel-title">Log Types</div>
                <div>{tags_html}</div>
            </div>
            """, unsafe_allow_html=True)

        # ── Compact step navigation ──
        if agent_mode == 'guided' and current_steps:
            st.markdown("---")
            st.caption(f"📍 **Step {current_step_idx + 1}/{len(current_steps)}:** {current_steps[current_step_idx]['title']}")

            nav1, nav2 = st.columns(2)
            with nav1:
                if current_step_idx > 0:
                    if st.button("⬅️ Prev", key="agent_prev", use_container_width=True):
                        OnboardingAgentState.set_current_step(st.session_state, current_step_idx - 1)
                        prev_title = current_steps[current_step_idx - 1]['title']
                        OnboardingAgentState.add_message(
                            st.session_state, "assistant",
                            f"↩️ Going back to **Step {current_step_idx}: {prev_title}**. What do you need help with?"
                        )
                        st.rerun()
            with nav2:
                if current_step_idx < len(current_steps) - 1:
                    if st.button("Next ➡️", key="agent_next", use_container_width=True):
                        next_idx = current_step_idx + 1
                        OnboardingAgentState.set_current_step(st.session_state, next_idx)
                        next_title = current_steps[next_idx]['title']
                        OnboardingAgentState.add_message(
                            st.session_state, "assistant",
                            f"➡️ Moving to **Step {next_idx + 1}: {next_title}**. Let me know how I can help."
                        )
                        st.rerun()

            if current_step_idx not in completed:
                if st.button("✅ Mark Complete", key="agent_mark_done", use_container_width=True, type="primary"):
                    OnboardingAgentState.mark_step_complete(st.session_state, current_step_idx)
                    next_idx = OnboardingAgentState.advance_to_next_step(st.session_state)
                    if next_idx != current_step_idx and next_idx < len(current_steps):
                        next_title = current_steps[next_idx]['title']
                        OnboardingAgentState.add_message(
                            st.session_state, "assistant",
                            f"✅ **Step {current_step_idx + 1}** complete! Moving to **Step {next_idx + 1}: {next_title}**."
                        )
                    else:
                        OnboardingAgentState.add_message(
                            st.session_state, "assistant",
                            f"✅ **Step {current_step_idx + 1}** complete! 🎉 All steps done! "
                            f"{source_display_name} onboarding is complete. You can still ask questions."
                        )
                    st.rerun()
            else:
                st.success("✓ Step complete")

    # ============================================
    # LEFT COLUMN — Chat Bubbles
    # ============================================
    with chat_col:

        # ── API key check ──
        if not has_api_key and not has_groq_key:
            st.info("""
            🔐 **AI API Required**
            
            Add an API key to `.streamlit/secrets.toml` or Streamlit Cloud secrets.
            
            **Free:** `GROQ_API_KEY = "gsk_..."`  |  **Paid:** `ANTHROPIC_API_KEY = "sk-ant-..."`
            """)
            if agent_mode == 'guided' and current_steps:
                st.markdown(f"### 📖 Step {current_step_idx + 1}: {current_steps[current_step_idx]['title']}")
                st.markdown(current_steps[current_step_idx]['content'])
            return

        # ── Auto-greeting on first visit ──
        if not messages:
            if agent_mode == 'guided' and current_steps:
                greeting = (
                    f"👋 I'm your onboarding agent for **{source_display_name}**. "
                    f"I've identified **{len(current_steps)} steps** from the integration guide.\n\n"
                    f"We're starting with **Step 1: {current_steps[0]['title']}**.\n\n"
                    f"Before we begin — can you tell me about your environment? "
                    f"For example: Splunk version, deployment type (on-prem/cloud), "
                    f"and any specific constraints?"
                )
            else:
                greeting = (
                    f"👋 I'm your AI assistant for **{source_display_name}**. "
                    f"Ask me anything about integrating this log source into Splunk."
                )
            OnboardingAgentState.add_message(st.session_state, "assistant", greeting)
            st.rerun()

        # ── Render chat bubbles ──
        for msg in messages:
            if msg["role"] == "user":
                st.markdown(
                    f'<div class="user-bubble">{_md_to_safe_html(msg["content"])}</div>',
                    unsafe_allow_html=True
                )
            else:
                st.markdown(
                    f'<div class="agent-bubble">'
                    f'<div class="agent-label">SIEM Agent</div>'
                    f'{_md_to_safe_html(msg["content"])}'
                    f'</div>',
                    unsafe_allow_html=True
                )

        # ── Chat input ──
        if prompt := st.chat_input("Ask a question or describe your environment..."):
            OnboardingAgentState.add_message(st.session_state, "user", prompt)

            # Build context-aware system prompt
            if agent_mode == 'guided' and current_steps:
                system_prompt_content = build_agent_system_prompt(
                    source_name=source_display_name,
                    steps=current_steps,
                    current_step_index=current_step_idx,
                    completed_indices=completed,
                    environment_context=OnboardingAgentState.format_environment_context(st.session_state)
                )
            else:
                system_prompt_content = kb_content

            # Get AI response
            with st.spinner("Agent is thinking..."):
                try:
                    if has_api_key:
                        from utils.ai_client import ClaudeClient as AIClaude
                        ai_chat = AIClaude(api_key)
                    else:
                        from utils.ai_client import GroqClient
                        ai_chat = GroqClient(groq_key)

                    response_data = ai_chat.get_response(
                        question=prompt,
                        kb_content=system_prompt_content,
                        source_name=source_display_name,
                        chat_history=OnboardingAgentState.get_messages(st.session_state)[:-1]
                    )

                    if response_data["success"]:
                        OnboardingAgentState.add_message(
                            st.session_state, "assistant", response_data["response"]
                        )
                    else:
                        OnboardingAgentState.add_message(
                            st.session_state, "assistant",
                            f"⚠️ Error: {response_data['message']}"
                        )
                except Exception as e:
                    OnboardingAgentState.add_message(
                        st.session_state, "assistant", f"⚠️ Error: {str(e)}"
                    )

            st.rerun()
