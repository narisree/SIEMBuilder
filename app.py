import streamlit as st
import json
from utils.kb_loader import KBLoader
from utils.claude_client import ClaudeClient
from utils.usecase_loader import UseCaseLoader
from utils.splunk_public_usecase_loader import SplunkPublicUseCaseLoader
from utils.irp_loader import IRPLoader
from utils.response_plan_generator import ResponsePlanGenerator
from utils.mermaid_renderer import render_markdown_with_mermaid

st.set_page_config(
    page_title="SIEM Log Source Onboarding Assistant",
    page_icon="🔒",
    layout="wide"
)

kb_loader = KBLoader()
usecase_loader = UseCaseLoader()
splunk_public_loader = SplunkPublicUseCaseLoader()
irp_loader = IRPLoader()
response_plan_gen = ResponsePlanGenerator()

LOG_SOURCE_DISPLAY_NAMES = {
    "palo_alto": "Palo Alto Firewall",
    "windows_events": "Windows Events",
    "linux": "Linux",
    "azure_ad": "Azure AD (Microsoft Entra ID)",
    "cisco_asa": "Cisco ASA",
    "checkpoint": "Check Point Firewall",
    "crowdstrike_edr": "CrowdStrike EDR",
    "o365": "Office 365 (Microsoft 365)",
    "proofpoint": "Proofpoint",
    "zscaler_proxy": "Zscaler Proxy"
}

def get_display_name(slug):
    return LOG_SOURCE_DISPLAY_NAMES.get(slug, slug.replace("_", " ").title())

# ============================================
# Sidebar
# ============================================

st.sidebar.title("🔒 SIEM Assistant")
st.sidebar.markdown("---")

try:
    api_key = st.secrets["ANTHROPIC_API_KEY"]
    has_api_key = True
except:
    api_key = None
    has_api_key = False

# Check for Groq key as fallback
try:
    groq_key = st.secrets["GROQ_API_KEY"]
    has_groq_key = True
except:
    groq_key = None
    has_groq_key = False

st.sidebar.header("⚙️ Settings")

if has_api_key:
    st.sidebar.success("🔐 Claude API: Connected ✓")
elif has_groq_key:
    st.sidebar.success("🔐 Groq API: Connected ✓")
else:
    st.sidebar.warning("🔐 AI API: Not configured")
    st.sidebar.caption("Chat & Response Plan generation disabled")

st.sidebar.markdown("---")

# --- Navigation Mode ---
st.sidebar.header("📍 Navigation")
nav_mode = st.sidebar.radio(
    "Select View",
    ["📊 Dashboard", "📘 Log Source Onboarding", "🛡️ Incident Response Playbooks"],
    index=0,
    label_visibility="collapsed"
)

st.sidebar.markdown("---")


# ============================================
# Helper: Build dashboard coverage data
# ============================================

def build_dashboard_data():
    """Build coverage data for all log sources for the dashboard view."""
    catalog = kb_loader.get_full_catalog()
    rows = []
    
    total_internal_uc = 0
    total_splunk_uc = 0
    total_cached_plans = 0
    sources_with_kb = 0
    
    for slug, meta in catalog.items():
        # KB status
        has_kb = kb_loader.kb_file_exists(slug)
        if has_kb:
            sources_with_kb += 1
        
        # Use case counts
        internal_uc = usecase_loader.get_use_case_count(slug)
        splunk_uc = splunk_public_loader.get_count_for_source(slug) if splunk_public_loader.is_available() else 0
        total_uc = internal_uc + splunk_uc
        total_internal_uc += internal_uc
        total_splunk_uc += splunk_uc
        
        # References status
        refs = kb_loader.get_references(slug)
        has_refs = refs["success"]
        
        # Cached response plans count for this source
        cached_plans = 0
        all_uc_for_source = []
        int_uc = usecase_loader.get_use_cases_for_source(slug)
        if int_uc:
            all_uc_for_source.extend(int_uc)
        if splunk_public_loader.is_available():
            spl_uc = splunk_public_loader.get_use_cases_for_source(slug)
            if spl_uc:
                all_uc_for_source.extend(spl_uc)
        for uc in all_uc_for_source:
            uc_name = uc.get('Use case Name', '')
            if uc_name and response_plan_gen.get_cached_plan(uc_name):
                cached_plans += 1
        total_cached_plans += cached_plans
        
        rows.append({
            "slug": slug,
            "icon": meta.get("icon", "📦"),
            "display_name": meta.get("display_name", slug),
            "category": meta.get("category", "—"),
            "vendor": meta.get("vendor", "—"),
            "collection_method": meta.get("collection_method", "—"),
            "complexity": meta.get("complexity", "—"),
            "splunk_addon": meta.get("splunk_addon", "—"),
            "primary_index": meta.get("primary_index", "—"),
            "primary_sourcetype": meta.get("primary_sourcetype", "—"),
            "estimated_eps": meta.get("estimated_eps", "—"),
            "has_kb": has_kb,
            "has_refs": has_refs,
            "internal_uc": internal_uc,
            "splunk_uc": splunk_uc,
            "total_uc": total_uc,
            "cached_plans": cached_plans,
        })
    
    irp_catalog = irp_loader.get_available_irps()
    
    summary = {
        "total_sources": len(catalog),
        "sources_with_kb": sources_with_kb,
        "total_internal_uc": total_internal_uc,
        "total_splunk_uc": total_splunk_uc,
        "total_uc": total_internal_uc + total_splunk_uc,
        "total_irps": len(irp_catalog),
        "total_cached_plans": total_cached_plans,
    }
    
    return rows, summary


# ============================================
# View: Dashboard
# ============================================

if nav_mode == "📊 Dashboard":
    
    st.title("📊 SIEM Onboarding Dashboard")
    st.caption("Coverage overview across all log sources, use cases, and incident response playbooks.")
    
    rows, summary = build_dashboard_data()
    
    # --- Metric cards ---
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Log Sources", summary["total_sources"], help="Total sources in catalog")
    m2.metric("KB Guides", summary["sources_with_kb"], help="Sources with markdown KB files")
    m3.metric("Use Cases", summary["total_uc"], help="Internal + Splunk public use cases")
    m4.metric("IRPs", summary["total_irps"], help="Incident Response Playbooks")
    m5.metric("Response Plans", summary["total_cached_plans"], help="Cached AI-generated response plans")
    
    st.markdown("---")
    
    # --- Summary table ---
    st.subheader("Log Source Coverage")
    
    for row in rows:
        kb_badge = "✅" if row["has_kb"] else "❌"
        refs_badge = "✅" if row["has_refs"] else "❌"
        uc_badge = f"{row['total_uc']}" if row["total_uc"] > 0 else "—"
        plans_badge = f"{row['cached_plans']}" if row["cached_plans"] > 0 else "—"
        
        # Complexity color
        complexity = row["complexity"]
        if complexity == "Low":
            complexity_display = "🟢 Low"
        elif complexity == "Medium":
            complexity_display = "🟡 Medium"
        elif complexity == "High":
            complexity_display = "🔴 High"
        else:
            complexity_display = complexity
        
        with st.expander(f"{row['icon']} **{row['display_name']}** — {row['category']}  |  KB: {kb_badge}  |  Use Cases: {uc_badge}  |  Complexity: {complexity_display}"):
            
            # Source profile card
            pc1, pc2 = st.columns(2)
            
            with pc1:
                st.markdown(f"**Vendor:** {row['vendor']}")
                st.markdown(f"**Category:** {row['category']}")
                st.markdown(f"**Collection Method:** {row['collection_method']}")
                st.markdown(f"**Complexity:** {complexity_display}")
                st.markdown(f"**Estimated EPS:** {row['estimated_eps']}")
            
            with pc2:
                st.markdown(f"**Splunk Add-on:** `{row['splunk_addon']}`")
                st.markdown(f"**Primary Index:** `{row['primary_index']}`")
                st.markdown(f"**Primary Sourcetype:** `{row['primary_sourcetype']}`")
                st.markdown(f"**KB Guide:** {kb_badge}")
                st.markdown(f"**References:** {refs_badge}")
            
            # Coverage stats
            st.markdown("---")
            cs1, cs2, cs3 = st.columns(3)
            cs1.metric("Internal Use Cases", row["internal_uc"])
            cs2.metric("Splunk Public Use Cases", row["splunk_uc"])
            cs3.metric("Cached Response Plans", row["cached_plans"])
    
    st.markdown("---")
    
    # --- IRP coverage summary ---
    st.subheader("Incident Response Playbook Coverage")
    
    irp_catalog = irp_loader.get_available_irps()
    irp_cols = st.columns(len(irp_catalog))
    for i, (key, info) in enumerate(irp_catalog.items()):
        with irp_cols[i]:
            has_file = irp_loader.load_irp_content(key) is not None
            status = "✅" if has_file else "❌"
            st.markdown(f"**{info['icon']} {info['display_name']}**")
            st.caption(f"Status: {status}")
    
    st.markdown("---")
    st.caption("💡 Select **📘 Log Source Onboarding** in the sidebar to drill into a specific log source.")


# ============================================
# View: Incident Response Playbooks
# ============================================

elif nav_mode == "🛡️ Incident Response Playbooks":
    
    # IRP selector in sidebar
    irp_catalog = irp_loader.get_available_irps()
    irp_options = {f"{v['icon']} {v['display_name']}": k for k, v in irp_catalog.items()}
    
    selected_irp_display = st.sidebar.selectbox(
        "Select Playbook",
        options=list(irp_options.keys()),
        index=0
    )
    selected_irp_key = irp_options[selected_irp_display]
    selected_irp_info = irp_catalog[selected_irp_key]
    
    st.sidebar.markdown("---")
    st.sidebar.markdown("### All Playbooks")
    for k, v in irp_catalog.items():
        if k == selected_irp_key:
            st.sidebar.markdown(f"**{v['icon']} {v['display_name']}** ◀")
        else:
            st.sidebar.markdown(f"{v['icon']} {v['display_name']}")
    
    # Main content
    st.title(f"{selected_irp_info['icon']} {selected_irp_info['display_name']} Incident Response Playbook")
    st.caption(selected_irp_info['description'])
    
    irp_content = irp_loader.load_irp_content(selected_irp_key)
    
    if irp_content:
        render_markdown_with_mermaid(irp_content)
    else:
        st.error(f"Playbook file not found: {selected_irp_info['filename']}")
        st.info("Ensure the Playbooks/ directory contains the IRP markdown files.")


# ============================================
# View: Log Source Onboarding (existing)
# ============================================

else:
    # Log source selector in sidebar
    available_sources = kb_loader.get_available_sources()
    if not available_sources:
        st.error("No knowledge base files found. Please add KB markdown files to the /kb directory.")
        st.stop()

    source_options = {get_display_name(slug): slug for slug in available_sources}
    selected_display = st.sidebar.selectbox(
        "Select Log Source",
        options=list(source_options.keys()),
        index=0
    )
    selected_source = source_options[selected_display]

    st.sidebar.markdown("---")
    st.sidebar.markdown("### Quick Links")
    st.sidebar.markdown("- [Overview](#overview)")
    st.sidebar.markdown("- [Pre-requisites](#pre-requisites)")
    st.sidebar.markdown("- [Configuration](#log-collection-standard)")
    st.sidebar.markdown("- [Validation](#validation-troubleshooting)")

    # --- Source Profile Card (new - borrowed from Sentinel Ninja pattern) ---
    source_meta = kb_loader.get_source_metadata(selected_source)
    
    st.title(f"{source_meta.get('icon', '📦')} {get_display_name(selected_source)}")
    
    if source_meta:
        with st.container():
            pc1, pc2, pc3, pc4 = st.columns(4)
            pc1.markdown(f"**Vendor:** {source_meta.get('vendor', '—')}")
            pc2.markdown(f"**Method:** {source_meta.get('collection_method', '—')}")
            pc3.markdown(f"**Index:** `{source_meta.get('primary_index', '—')}`")
            pc4.markdown(f"**Add-on:** `{source_meta.get('splunk_addon', '—')}`")

    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "📖 Integration Guide", 
        "🔗 References", 
        "💬 Chat", 
        "📋 Use Cases",
        "📄 Response Plans"
    ])

    # --- Tab 1: Integration Guide (unchanged) ---
    with tab1:
        kb_content = kb_loader.load_kb_content(selected_source)
        
        if kb_content:
            st.markdown(kb_content)
        else:
            st.warning(f"Knowledge base file not found for {get_display_name(selected_source)}.")
            st.info("""
            **To add this log source:**
            1. Create a markdown file: `kb/{source_slug}.md`
            2. Follow the standard KB template structure
            3. Restart the application
            """)

    # --- Tab 2: References (unchanged) ---
    with tab2:
        st.header("References")
        
        references = kb_loader.get_references(selected_source)
        
        if references["success"]:
            ref_data = references["data"]
            
            st.subheader("📚 Official Documentation")
            if ref_data.get("official_docs"):
                for doc in ref_data["official_docs"]:
                    st.markdown(f"- [{doc['title']}]({doc['url']})")
            else:
                st.info("No official documentation links available.")
            
            st.subheader("🎥 YouTube Videos")
            if ref_data.get("youtube"):
                for video in ref_data["youtube"]:
                    st.markdown(f"- [{video['title']}]({video['url']})")
            else:
                st.info("No YouTube video links available.")
            
            if ref_data.get("blogs_optional"):
                st.subheader("📝 Blogs & Community")
                for blog in ref_data["blogs_optional"]:
                    st.markdown(f"- [{blog['title']}]({blog['url']})")
        else:
            st.warning(references["message"])
            st.info("""
            **To add references:**
            1. Edit `kb/references.json`
            2. Add an entry for this log source
            3. Restart the application
            """)

    # --- Tab 3: Chat (unchanged) ---
    with tab3:
        st.header("Chat with AI Assistant")
        
        if has_api_key or has_groq_key:
            if "messages" not in st.session_state:
                st.session_state.messages = []
            
            for message in st.session_state.messages:
                with st.chat_message(message["role"]):
                    st.markdown(message["content"])
            
            if prompt := st.chat_input("Ask a question about this log source..."):
                st.session_state.messages.append({"role": "user", "content": prompt})
                with st.chat_message("user"):
                    st.markdown(prompt)
                
                kb_content = kb_loader.load_kb_content(selected_source)
                
                with st.chat_message("assistant"):
                    with st.spinner("Thinking..."):
                        try:
                            if has_api_key:
                                from utils.ai_client import ClaudeClient as AIClaude
                                ai_chat = AIClaude(api_key)
                            else:
                                from utils.ai_client import GroqClient
                                ai_chat = GroqClient(groq_key)
                            
                            response_data = ai_chat.get_response(
                                question=prompt,
                                kb_content=kb_content or "",
                                source_name=get_display_name(selected_source),
                                chat_history=st.session_state.messages[:-1]
                            )
                            
                            if response_data["success"]:
                                st.markdown(response_data["response"])
                                st.session_state.messages.append({"role": "assistant", "content": response_data["response"]})
                            else:
                                st.error(f"Error: {response_data['message']}")
                        except Exception as e:
                            st.error(f"Error: {str(e)}")
        else:
            st.info("""
            🔐 **AI API Required to Ask Questions**
            
            Add an API key to `.streamlit/secrets.toml` or Streamlit Cloud secrets to enable chat.
            
            **Free option:** Add `GROQ_API_KEY = "gsk_..."` (get one at console.groq.com)
            """)

    # --- Tab 4: Use Cases (UPDATED - Removed L1 Guidance and Validation Steps) ---
    with tab4:
        st.header("Use Cases")
        
        # Helper function to render a use case in the standard format
        def render_use_case(use_case, idx, prefix=""):
            """Render a use case in the standard format."""
            name = use_case.get('Use case Name', 'Unnamed')
            technique = use_case.get('MITRE Technique', 'N/A')
            
            with st.expander(f"**{name}** - {technique}"):
                st.markdown(f"**MITRE Tactics:** {use_case.get('MITRE Tactics', 'N/A')}")
                st.markdown(f"**Description:** {use_case.get('Description', 'N/A')}")
                
                st.markdown("**SPL Query:**")
                # Handle both 'SPL ' (with space) and 'SPL' keys
                spl_query = use_case.get('SPL ', use_case.get('SPL', 'N/A'))
                st.code(spl_query, language='sql')
                
                # Escalation Path
                related_irps = irp_loader.get_irps_for_use_case(use_case)
                if related_irps:
                    st.markdown("**🛡️ Escalation Path:**")
                    for irp in related_irps:
                        st.markdown(f"- Escalate to **{irp['icon']} {irp['display_name']} IRP** if confirmed malicious")
        
        # Internal Library Section
        st.subheader("📚 Internal Library")
        internal_use_cases = usecase_loader.get_use_cases_for_source(selected_source)
        
        if internal_use_cases:
            st.success(f"Found **{len(internal_use_cases)}** internal use case(s)")
            
            for idx, use_case in enumerate(internal_use_cases):
                render_use_case(use_case, idx, "internal")
        else:
            st.info(f"No internal use cases available for {get_display_name(selected_source)}")
        
        st.markdown("---")
        
        # Splunk Public Use Cases Section
        st.subheader("🌐 Splunk Public Use Cases")
        
        if splunk_public_loader.is_available():
            splunk_use_cases = splunk_public_loader.get_use_cases_for_source(selected_source)
            
            if splunk_use_cases:
                st.success(f"Found **{len(splunk_use_cases)}** Splunk public use case(s)")
                
                for idx, use_case in enumerate(splunk_use_cases):
                    render_use_case(use_case, idx, "splunk")
            else:
                st.info(f"No Splunk public use cases available for {get_display_name(selected_source)}")
        else:
            st.warning("""
            **Splunk Public Use Cases file not found.**
            
            To enable Splunk public use cases:
            1. Place the `Splunk_Library_with_L1_Guidance.xlsx` file in the `kb/` directory
            2. Restart the application
            """)

    # --- Tab 5: Response Plans (unchanged) ---
    with tab5:
        st.header("Response Plans")
        st.caption("AI-generated detection-specific runbooks for L1/L2 analysts. Plans are cached after first generation.")
        
        # Gather all use cases for this source
        all_use_cases = []
        
        internal_uc = usecase_loader.get_use_cases_for_source(selected_source)
        if internal_uc:
            for uc in internal_uc:
                uc['_source_lib'] = 'Internal'
                all_use_cases.append(uc)
        
        if splunk_public_loader.is_available():
            splunk_uc = splunk_public_loader.get_use_cases_for_source(selected_source)
            if splunk_uc:
                for uc in splunk_uc:
                    uc['_source_lib'] = 'Splunk Public'
                    all_use_cases.append(uc)
        
        if not all_use_cases:
            st.info(f"No use cases available for {get_display_name(selected_source)}. Add use cases first to generate response plans.")
        else:
            # Show use case selector
            uc_names = [uc.get('Use case Name', f'Unnamed-{i}') for i, uc in enumerate(all_use_cases)]
            
            selected_uc_name = st.selectbox(
                "Select a use case to view/generate its response plan:",
                options=uc_names,
                index=0
            )
            
            # Find the selected use case
            selected_uc = None
            for uc in all_use_cases:
                if uc.get('Use case Name', '') == selected_uc_name:
                    selected_uc = uc
                    break
            
            if selected_uc:
                # Show use case summary
                with st.expander("📋 Use Case Details", expanded=False):
                    st.markdown(f"**MITRE Tactics:** {selected_uc.get('MITRE Tactics', 'N/A')}")
                    st.markdown(f"**MITRE Technique:** {selected_uc.get('MITRE Technique', 'N/A')}")
                    st.markdown(f"**Library:** {selected_uc.get('_source_lib', 'N/A')}")
                    st.markdown(f"**Description:** {selected_uc.get('Description', 'N/A')}")
                
                # Check cache
                cached_plan = response_plan_gen.get_cached_plan(selected_uc_name)
                
                if cached_plan:
                    st.success("✅ Response plan loaded from cache")
                    
                    col1, col2 = st.columns([6, 1])
                    with col2:
                        if st.button("🔄 Regenerate", key="regen_btn"):
                            response_plan_gen.delete_cached_plan(selected_uc_name)
                            st.rerun()
                    
                    st.markdown("---")
                    st.markdown(cached_plan)
                
                else:
                    # Not cached — offer generation
                    has_any_ai = has_api_key or has_groq_key
                    
                    if not has_any_ai:
                        st.warning("""
                        🔐 **AI API Required to Generate Response Plans**
                        
                        Configure an API key in `.streamlit/secrets.toml`:
                        - `ANTHROPIC_API_KEY` (recommended for quality)
                        - `GROQ_API_KEY` (free alternative)
                        """)
                    else:
                        # Show which AI will be used
                        if has_api_key:
                            ai_provider = "Claude Sonnet (Anthropic)"
                        else:
                            ai_provider = "Llama 4 Scout (Groq - Free)"
                        
                        st.info(f"No cached response plan found. Click below to generate using **{ai_provider}**.")
                        
                        # Show escalation targets
                        related_irps = irp_loader.get_irps_for_use_case(selected_uc)
                        if related_irps:
                            irp_names = ", ".join([f"{i['icon']} {i['display_name']}" for i in related_irps])
                            st.caption(f"Escalation targets: {irp_names}")
                        
                        if st.button("⚡ Generate Response Plan", key="gen_btn", type="primary"):
                            with st.spinner("Generating response plan... This may take 15-30 seconds."):
                                try:
                                    # Create AI client
                                    if has_api_key:
                                        from utils.ai_client import ClaudeClient as AIClaude
                                        ai_client = AIClaude(api_key)
                                    else:
                                        from utils.ai_client import GroqClient
                                        ai_client = GroqClient(groq_key)
                                    
                                    irp_keys = [i['key'] for i in related_irps] if related_irps else []
                                    
                                    result = response_plan_gen.generate_plan(
                                        use_case=selected_uc,
                                        ai_client=ai_client,
                                        irp_keys=irp_keys
                                    )
                                    
                                    if result["success"]:
                                        st.success(f"✅ Response plan generated ({result['message']})")
                                        st.markdown("---")
                                        st.markdown(result["content"])
                                    else:
                                        st.error(f"Generation failed: {result['message']}")
                                        
                                except Exception as e:
                                    st.error(f"Error: {str(e)}")

st.sidebar.markdown("---")
st.sidebar.caption("SIEM Log Source Onboarding Assistant v1.2")
