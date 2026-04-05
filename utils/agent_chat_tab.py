"""
Agent Chat Tab Renderer
Drop-in replacement for the '# --- Tab 3: Chat (unchanged) ---' section in app.py.

This replaces the freeform chatbot with a Tier 2 Hybrid Agent that:
1. Extracts onboarding steps from the KB markdown
2. Shows a progress sidebar with clickable steps
3. Sends only the current step's KB content to the AI (saves tokens)
4. Tracks environment details gathered from conversation
5. Falls back to freeform chat if KB has no extractable steps

INTEGRATION:
  1. Add `from utils.onboarding_agent import ...` to app.py imports
  2. Replace the `with tab3:` block with `render_agent_chat_tab(...)`
  3. No other files change.

See INSTALL_GUIDE below for exact copy-paste instructions.
"""

# ============================================
# INSTALL GUIDE — Read this, then apply
# ============================================
#
# STEP 1: Add this import near the top of app.py (with the other utils imports):
#
#   from utils.onboarding_agent import (
#       extract_kb_sections,
#       get_top_level_steps,
#       build_agent_system_prompt,
#       OnboardingAgentState
#   )
#
# STEP 2: Find this block in app.py:
#
#   # --- Tab 3: Chat (unchanged) ---
#   with tab3:
#       st.header("Chat with AI Assistant")
#       ...everything until the next tab block...
#
# STEP 3: Replace that ENTIRE block with:
#
#   # --- Tab 3: AI Agent (upgraded from basic chat) ---
#   with tab3:
#       render_agent_chat_tab(
#           selected_source=selected_source,
#           source_display_name=get_display_name(selected_source),
#           kb_loader=kb_loader,
#           has_api_key=has_api_key,
#           api_key=api_key,
#           has_groq_key=has_groq_key,
#           groq_key=groq_key
#       )
#
# That's it. All other tabs, modules, and logic remain untouched.
# ============================================


import streamlit as st
from typing import Optional
from utils.onboarding_agent import (
    extract_kb_sections,
    get_top_level_steps,
    build_agent_system_prompt,
    OnboardingAgentState
)


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
    Render the Agent Chat tab. Drop-in replacement for the old chat tab.
    
    Args:
        selected_source: Source slug (e.g., 'palo_alto')
        source_display_name: Human-readable name (e.g., 'Palo Alto Firewall')
        kb_loader: KBLoader instance
        has_api_key: Whether Anthropic key is available
        api_key: Anthropic API key or None
        has_groq_key: Whether Groq key is available
        groq_key: Groq API key or None
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

    # ── Header ──
    if agent_mode == 'guided':
        st.header("🤖 Onboarding Agent")
        st.caption(
            f"Guided onboarding for **{source_display_name}** — "
            f"Step {current_step_idx + 1} of {len(current_steps)} · "
            f"{len(completed)}/{len(current_steps)} complete"
        )
    else:
        st.header("💬 AI Assistant")
        st.caption(f"Ask questions about **{source_display_name}** integration")

    # ── Progress & Step Navigation (guided mode only) ──
    if agent_mode == 'guided' and current_steps:
        # Progress bar
        progress = len(completed) / len(current_steps) if current_steps else 0
        st.progress(progress, text=f"{len(completed)}/{len(current_steps)} steps complete")

        # Step navigator
        with st.expander("📋 Onboarding Steps", expanded=True):
            for i, step in enumerate(current_steps):
                col1, col2, col3 = st.columns([0.5, 8, 1.5])
                
                with col1:
                    is_done = i in completed
                    if st.checkbox(
                        "done",
                        value=is_done,
                        key=f"agent_step_check_{i}",
                        label_visibility="collapsed"
                    ):
                        if i not in completed:
                            OnboardingAgentState.mark_step_complete(st.session_state, i)
                            st.rerun()
                    else:
                        if i in completed:
                            OnboardingAgentState.unmark_step_complete(st.session_state, i)
                            st.rerun()

                with col2:
                    is_current = (i == current_step_idx)
                    prefix = "👉 " if is_current else ""
                    style = "**" if is_current else ""
                    done_strike = "~~" if i in completed else ""
                    st.markdown(
                        f"{prefix}{style}{done_strike}Step {i + 1}: {step['title']}{done_strike}{style}"
                    )

                with col3:
                    if i != current_step_idx:
                        if st.button("Go", key=f"agent_goto_{i}", help=f"Jump to Step {i + 1}"):
                            OnboardingAgentState.set_current_step(st.session_state, i)
                            st.rerun()
                    else:
                        st.markdown("*active*")

        st.markdown("---")

    # ── API key check ──
    if not has_api_key and not has_groq_key:
        st.info("""
        🔐 **AI API Required**
        
        Add an API key to `.streamlit/secrets.toml` or Streamlit Cloud secrets to enable the agent.
        
        **Free option:** `GROQ_API_KEY = "gsk_..."`  
        **Paid option:** `ANTHROPIC_API_KEY = "sk-ant-..."`
        """)
        
        # Still show the step content even without AI
        if agent_mode == 'guided' and current_steps:
            st.subheader(f"📖 Step {current_step_idx + 1}: {current_steps[current_step_idx]['title']}")
            st.markdown(current_steps[current_step_idx]['content'])
        return

    # ── Chat messages ──
    for msg in messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    # ── Auto-greeting on first visit (guided mode) ──
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

    # ── Chat input ──
    if prompt := st.chat_input("Ask a question or describe your environment..."):
        # Add user message
        OnboardingAgentState.add_message(st.session_state, "user", prompt)
        with st.chat_message("user"):
            st.markdown(prompt)

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
        with st.chat_message("assistant"):
            with st.spinner("Agent is thinking..."):
                try:
                    if has_api_key:
                        from utils.ai_client import ClaudeClient as AIClaude
                        ai_chat = AIClaude(api_key)
                    else:
                        from utils.ai_client import GroqClient
                        ai_chat = GroqClient(groq_key)

                    # Use the existing get_response interface
                    # For guided mode, we pass the agent system prompt via kb_content
                    # The ai_client._build_system_prompt will wrap it appropriately
                    response_data = ai_chat.get_response(
                        question=prompt,
                        kb_content=system_prompt_content,
                        source_name=source_display_name,
                        chat_history=OnboardingAgentState.get_messages(st.session_state)[:-1]
                    )

                    if response_data["success"]:
                        response_text = response_data["response"]
                        st.markdown(response_text)
                        OnboardingAgentState.add_message(
                            st.session_state, "assistant", response_text
                        )
                    else:
                        st.error(f"Error: {response_data['message']}")

                except Exception as e:
                    st.error(f"Error: {str(e)}")

    # ── Step navigation buttons (guided mode) ──
    if agent_mode == 'guided' and current_steps:
        st.markdown("---")
        nav1, nav2, nav3 = st.columns([1, 1, 1])

        with nav1:
            if current_step_idx > 0:
                if st.button("⬅️ Previous Step", use_container_width=True):
                    OnboardingAgentState.set_current_step(
                        st.session_state, current_step_idx - 1
                    )
                    # Add navigation message
                    prev_title = current_steps[current_step_idx - 1]['title']
                    OnboardingAgentState.add_message(
                        st.session_state, "assistant",
                        f"↩️ Going back to **Step {current_step_idx}: {prev_title}**. What do you need help with here?"
                    )
                    st.rerun()

        with nav2:
            if current_step_idx not in completed:
                if st.button("✅ Mark Step Complete", use_container_width=True, type="primary"):
                    OnboardingAgentState.mark_step_complete(
                        st.session_state, current_step_idx
                    )
                    # Auto-advance
                    next_idx = OnboardingAgentState.advance_to_next_step(st.session_state)
                    if next_idx != current_step_idx and next_idx < len(current_steps):
                        next_title = current_steps[next_idx]['title']
                        OnboardingAgentState.add_message(
                            st.session_state, "assistant",
                            f"✅ **Step {current_step_idx + 1}: {current_steps[current_step_idx]['title']}** — complete!\n\n"
                            f"Moving to **Step {next_idx + 1}: {next_title}**. "
                            f"Here's what we need to do next."
                        )
                    else:
                        OnboardingAgentState.add_message(
                            st.session_state, "assistant",
                            f"✅ **Step {current_step_idx + 1}: {current_steps[current_step_idx]['title']}** — complete!\n\n"
                            f"🎉 **All steps are done!** The {source_display_name} integration is complete. "
                            f"You can still ask questions or revisit any step."
                        )
                    st.rerun()

        with nav3:
            if current_step_idx < len(current_steps) - 1:
                if st.button("Next Step ➡️", use_container_width=True):
                    next_idx = current_step_idx + 1
                    OnboardingAgentState.set_current_step(st.session_state, next_idx)
                    next_title = current_steps[next_idx]['title']
                    OnboardingAgentState.add_message(
                        st.session_state, "assistant",
                        f"➡️ Jumping to **Step {next_idx + 1}: {next_title}**. Let me know how I can help."
                    )
                    st.rerun()
