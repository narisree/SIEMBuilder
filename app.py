import streamlit as st
import json
from utils.kb_loader import KBLoader
from utils.claude_client import ClaudeClient
from utils.usecase_loader import UseCaseLoader
from utils.splunk_public_usecase_loader import SplunkPublicUseCaseLoader

st.set_page_config(
    page_title="SIEM Log Source Onboarding Assistant",
    page_icon="🔒",
    layout="wide"
)

kb_loader = KBLoader()
usecase_loader = UseCaseLoader()
splunk_public_loader = SplunkPublicUseCaseLoader()

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

st.sidebar.title("🔒 SIEM Assistant")
st.sidebar.markdown("---")

try:
    api_key = st.secrets["ANTHROPIC_API_KEY"]
    has_api_key = True
except:
    api_key = None
    has_api_key = False

st.sidebar.header("⚙️ Settings")

if has_api_key:
    st.sidebar.success("🔐 Claude API: Connected ✓")
else:
    st.sidebar.warning("🔐 Claude API: Not configured")
    st.sidebar.caption("Chat feature disabled")

st.sidebar.markdown("---")

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

st.title(f"{get_display_name(selected_source)} - Integration Guide")

tab1, tab2, tab3, tab4 = st.tabs(["📖 Integration Guide", "🔗 References", "💬 Chat", "📋 Use Cases"])

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

with tab3:
    st.header("Chat with Claude")
    
    if has_api_key:
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
                        claude = ClaudeClient(api_key)
                        response_data = claude.get_response(
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
        🔐 **Claude API Required to Ask Questions**
        
        Add API key to `.streamlit/secrets.toml` or Streamlit Cloud secrets to enable chat.
        """)

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
            
            if use_case.get('L1_What_It_Detects'):
                st.markdown("**What It Detects (L1 Guidance):**")
                st.info(use_case['L1_What_It_Detects'])
            
            if use_case.get('L1_Validation_Steps'):
                st.markdown("**Validation Steps:**")
                steps = use_case['L1_Validation_Steps']
                if isinstance(steps, list):
                    for step in steps:
                        st.markdown(f"- {step}")
                else:
                    st.markdown(f"- {steps}")
    
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

st.sidebar.markdown("---")
st.sidebar.caption("SIEM Log Source Onboarding Assistant v1.0")
