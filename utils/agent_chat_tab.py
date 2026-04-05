"""
Agent Chat Tab Renderer

Layout:
  ┌─────────────────────────┬──────────────┐
  │  Chat messages (left)   │  Info panel  │
  │  – agent / user bubbles │  – Progress  │
  │                         │  – Quick ref │
  └─────────────────────────┴──────────────┘
  [  Chat input  –  full width at bottom   ]

Key design decisions:
  - No step navigator expander, no nav buttons.
    The agent guides the user through steps conversationally.
  - Progress is tracked silently and displayed in the right panel only.
  - st.chat_input() is placed OUTSIDE the columns block (Streamlit constraint)
    so it renders full-width below both columns.
  - Submissions add both user and AI messages to state then call st.rerun(),
    so new messages always appear in the messages loop (above the input),
    never below it.
"""

import streamlit as st
from typing import Optional
from utils.onboarding_agent import (
    extract_kb_sections,
    get_top_level_steps,
    build_agent_system_prompt,
    OnboardingAgentState
)


def _get_ai_response(prompt, system_prompt_content, source_display_name,
                     chat_history, has_api_key, api_key, has_groq_key, groq_key):
    """Call the configured AI backend. Returns (success: bool, text: str)."""
    try:
        if has_api_key:
            from utils.ai_client import ClaudeClient as AIClaude
            client = AIClaude(api_key)
        else:
            from utils.ai_client import GroqClient
            client = GroqClient(groq_key)

        result = client.get_response(
            question=prompt,
            kb_content=system_prompt_content,
            source_name=source_display_name,
            chat_history=chat_history
        )
        if result["success"]:
            return True, result["response"]
        return False, result.get("message", "Unknown error")
    except Exception as e:
        return False, str(e)


def _render_info_panel(agent_mode, current_steps, completed, source_meta):
    """Render the right-hand info panel (progress + quick reference)."""

    # ── Onboarding Progress ──────────────────────────────────────────────
    if agent_mode == 'guided' and current_steps:
        st.markdown(
            "<p style='font-size:0.75rem;letter-spacing:0.08em;color:#8b9ab1;"
            "text-transform:uppercase;margin-bottom:4px'>Onboarding Progress</p>",
            unsafe_allow_html=True
        )
        progress = len(completed) / len(current_steps) if current_steps else 0
        st.progress(progress)
        done_count = len(completed)
        total = len(current_steps)
        st.caption(f"{done_count}/{total} steps complete")

        st.divider()

    # ── Quick Reference ──────────────────────────────────────────────────
    if source_meta:
        st.markdown(
            "<p style='font-size:0.75rem;letter-spacing:0.08em;color:#8b9ab1;"
            "text-transform:uppercase;margin-bottom:8px'>Quick Reference</p>",
            unsafe_allow_html=True
        )

        fields = [
            ("Index",       source_meta.get("primary_index",      "—")),
            ("Sourcetype",  source_meta.get("primary_sourcetype", "—")),
            ("Add-on",      source_meta.get("splunk_addon",       "—")),
            ("Method",      source_meta.get("collection_method",  "—")),
        ]
        for label, value in fields:
            lc, rc = st.columns([1, 1.4])
            with lc:
                st.caption(label)
            with rc:
                st.markdown(f"`{value}`")

        # Category badge as a subtle extra
        cat = source_meta.get("category")
        if cat:
            st.divider()
            st.caption(f"**Category:** {cat}")
            complexity = source_meta.get("complexity")
            if complexity:
                st.caption(f"**Complexity:** {complexity}")


def render_agent_chat_tab(
    selected_source: str,
    source_display_name: str,
    kb_loader,
    has_api_key: bool,
    api_key: Optional[str],
    has_groq_key: bool,
    groq_key: Optional[str],
    source_meta: Optional[dict] = None
):
    """
    Render the Agent Chat tab.

    Args:
        selected_source:      Source slug (e.g., 'palo_alto')
        source_display_name:  Human-readable name (e.g., 'Palo Alto Firewall')
        kb_loader:            KBLoader instance
        has_api_key:          Whether Anthropic key is available
        api_key:              Anthropic API key or None
        has_groq_key:         Whether Groq key is available
        groq_key:             Groq API key or None
        source_meta:          Dict from sources_catalog.json (optional)
    """

    # ── Load KB and extract steps ──────────────────────────────────────────
    kb_content = kb_loader.load_kb_content(selected_source) or ""
    sections   = extract_kb_sections(kb_content)
    steps      = get_top_level_steps(sections)

    # ── Initialise / reset state when source changes ───────────────────────
    if OnboardingAgentState.needs_reset(st.session_state, selected_source):
        OnboardingAgentState.init_state(st.session_state, selected_source, steps)

    agent_mode       = OnboardingAgentState.get_mode(st.session_state)
    current_steps    = OnboardingAgentState.get_steps(st.session_state)
    current_step_idx = OnboardingAgentState.get_current_step(st.session_state)
    completed        = OnboardingAgentState.get_completed(st.session_state)
    messages         = OnboardingAgentState.get_messages(st.session_state)

    # ── No API key — show notice and static step content ──────────────────
    if not has_api_key and not has_groq_key:
        chat_col, info_col = st.columns([3, 1.2])
        with info_col:
            _render_info_panel(agent_mode, current_steps, completed, source_meta)
        with chat_col:
            st.info("""
            🔐 **AI API Required**

            Add an API key to `.streamlit/secrets.toml` to enable the agent.

            **Free option:** `GROQ_API_KEY = "gsk_..."`
            **Paid option:** `ANTHROPIC_API_KEY = "sk-ant-..."`
            """)
            if agent_mode == 'guided' and current_steps:
                cur = current_steps[current_step_idx]
                st.subheader(f"Step {current_step_idx + 1}: {cur['title']}")
                st.markdown(cur['content'])
        return

    # ── Auto-greeting on first visit ───────────────────────────────────────
    if agent_mode == 'guided' and not messages and current_steps:
        greeting = (
            f"👋 I'm your onboarding agent for **{source_display_name}**. "
            f"I've identified **{len(current_steps)} steps** from the integration guide.\n\n"
            f"We're starting with **Step 1: {current_steps[0]['title']}**.\n\n"
            f"Before we begin — can you tell me about your environment? "
            f"For example: Splunk version, deployment type (on-prem/cloud), "
            f"and any specific constraints?"
        )
        OnboardingAgentState.add_message(st.session_state, "assistant", greeting)
        st.rerun()

    # ── Main layout: chat (left) + info panel (right) ─────────────────────
    # st.chat_input() cannot live inside st.columns(), so it is rendered
    # AFTER this block at full width.
    chat_col, info_col = st.columns([3, 1.2])

    with info_col:
        _render_info_panel(agent_mode, current_steps, completed, source_meta)

    with chat_col:
        # Render all stored messages
        for msg in messages:
            with st.chat_message(msg["role"]):
                st.markdown(msg["content"])

    # ── Chat input — full width, always below the two columns ─────────────
    prompt = st.chat_input("Ask a question or describe your environment...")

    # ── Handle submission ──────────────────────────────────────────────────
    if prompt:
        OnboardingAgentState.add_message(st.session_state, "user", prompt)

        # Build system prompt
        if agent_mode == 'guided' and current_steps:
            system_prompt_content = build_agent_system_prompt(
                source_name=source_display_name,
                steps=current_steps,
                current_step_index=current_step_idx,
                completed_indices=completed,
                environment_context=OnboardingAgentState.format_environment_context(
                    st.session_state
                )
            )
        else:
            system_prompt_content = kb_content

        with st.spinner("Agent is thinking..."):
            success, response_text = _get_ai_response(
                prompt=prompt,
                system_prompt_content=system_prompt_content,
                source_display_name=source_display_name,
                chat_history=OnboardingAgentState.get_messages(st.session_state)[:-1],
                has_api_key=has_api_key,
                api_key=api_key,
                has_groq_key=has_groq_key,
                groq_key=groq_key
            )

        if success:
            OnboardingAgentState.add_message(st.session_state, "assistant", response_text)
        else:
            OnboardingAgentState.add_message(
                st.session_state, "assistant",
                f"⚠️ Error getting response: {response_text}"
            )

        st.rerun()
