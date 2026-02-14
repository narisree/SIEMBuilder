import streamlit as st
import json
from utils.kb_loader import KBLoader
from utils.claude_client import ClaudeClient
from utils.usecase_loader import UseCaseLoader
from utils.splunk_usecase_downloader import UseCaseDownloader

st.set_page_config(
    page_title="SIEM Log Source Onboarding Assistant",
    page_icon="🔒",
    layout="wide"
)

kb_loader = KBLoader()
usecase_loader = UseCaseLoader()

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
        2. Include the following sections:
           - Overview
           - Pre-requisites
           - Network Connectivity Requirements
           - Logging Standard
           - Log Collection Standard
           - Required Add-on / Parser
           - Sample Configuration Snippets
           - Validation & Troubleshooting
           - Security Notes
        3. Add references to `kb/references.json`
        """)

with tab2:
    st.header("References")
    
    refs = kb_loader.get_references_for_source(selected_source)
    
    if not refs:
        st.warning(f"No references configured for {get_display_name(selected_source)}.")
        st.info("Add references to `kb/references.json` to display documentation links.")
    else:
        if "official_docs" in refs and refs["official_docs"]:
            st.subheader("📚 Official Documentation")
            for doc in refs["official_docs"]:
                st.markdown(f"- [{doc['title']}]({doc['url']})")
        
        if "youtube" in refs and refs["youtube"]:
            st.subheader("🎥 YouTube Videos")
            for video in refs["youtube"]:
                st.markdown(f"- [{video['title']}]({video['url']})")
        
        if "blogs_optional" in refs and refs["blogs_optional"]:
            st.subheader("📝 Blogs & Community")
            for blog in refs["blogs_optional"]:
                st.markdown(f"- [{blog['title']}]({blog['url']})")

with tab3:
    st.header("Chat with Claude")
    
    try:
        api_key = st.secrets["ANTHROPIC_API_KEY"]
    except:
        st.error("⚠️ Claude API key not configured.")
        st.info("""
        **To enable chat:**
        1. Add your Anthropic API key to Streamlit secrets
        2. For local development: Create `.streamlit/secrets.toml`
        3. For Streamlit Cloud: Add to app secrets in dashboard
        
        ```toml
        ANTHROPIC_API_KEY = "sk-ant-..."
        ```
        """)
        st.stop()
    
    if "messages" not in st.session_state:
        st.session_state.messages = []
    
    if "current_source" not in st.session_state:
        st.session_state.current_source = selected_source
    
    if st.session_state.current_source != selected_source:
        st.session_state.messages = []
        st.session_state.current_source = selected_source
    
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])
    
    if prompt := st.chat_input("Ask a question about this log source..."):
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)
        
        kb_content = kb_loader.load_kb_content(selected_source)
        
        system_prompt = f"""You are a SIEM/Splunk integration assistant specializing in log source onboarding.

You are currently helping with: {get_display_name(selected_source)}

Knowledge Base Context:
{kb_content[:8000] if kb_content else "No KB content available"}

Guidelines:
- Provide practical, step-by-step guidance
- Base answers on the Knowledge Base content when available
- If the KB lacks specific information, clearly state what's missing
- Include assumptions when making recommendations
- Focus on Splunk integration best practices
- Keep responses concise and actionable
"""
        
        messages = []
        for msg in st.session_state.messages:
            messages.append({
                "role": msg["role"],
                "content": msg["content"]
            })
        
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

with tab4:
    st.header("Use Cases")
    
    # Download button at the top
    col1, col2 = st.columns([3, 1])
    
    with col1:
        st.subheader("Security Detection Use Cases")
    
    with col2:
        # Initialize show_download if not present
        if "show_download" not in st.session_state:
            st.session_state.show_download = False
        
        if st.button("🔄 Download Splunk Use Cases", use_container_width=True):
            st.session_state.show_download = not st.session_state.show_download
            st.rerun()
    
    # Download section - only show if button was clicked
    if st.session_state.show_download:
        st.markdown("---")
        st.subheader("Download Splunk Public Use Cases")
        
        try:
            claude_key = st.secrets.get("ANTHROPIC_API_KEY", "")
            
            if not claude_key:
                st.error("⚠️ Claude API key not configured.")
                st.info("""
                **Required secret:**
                - ANTHROPIC_API_KEY
                
                Add to `.streamlit/secrets.toml` or Streamlit Cloud secrets.
                """)
            else:
                downloader = UseCaseDownloader(claude_key)
                
                update_info = downloader.check_for_updates()
                
                if not update_info.get("needs_update", False):
                    metadata = downloader._load_sync_metadata()
                    if metadata:
                        st.success("✓ Already up to date")
                        st.info(f"Last synced: {metadata['last_sync_timestamp']}")
                        st.info(f"Total detections: {metadata['total_detections']}")
                    
                    if st.button("Force Re-download"):
                        # Clear metadata to force re-download
                        import os
                        metadata_file = downloader.metadata_file
                        if metadata_file.exists():
                            os.remove(metadata_file)
                        st.rerun()
                
                else:
                    if update_info.get("error"):
                        st.error(f"Error checking updates: {update_info['error']}")
                    elif update_info.get("is_first_sync"):
                        st.info("📦 First-time sync - this will download all use cases from Splunk's security content repository.")
                        st.warning("Note: This may take 5-10 minutes and will use Claude API credits.")
                    else:
                        st.info(f"📦 Updates available:")
                        st.write(f"- {update_info.get('new_count', 0)} new detections")
                        st.write(f"- {update_info.get('modified_count', 0)} updated detections")
                    
                    if st.button("Start Download", type="primary"):
                        progress_bar = st.progress(0)
                        status_text = st.empty()
                        
                        def update_progress(current, total, message):
                            progress = int((current / total) * 100) if total > 0 else 0
                            progress_bar.progress(progress)
                            status_text.text(f"{message} ({current}/{total})")
                        
                        with st.spinner("Processing..."):
                            result = downloader.download_and_process(progress_callback=update_progress)
                        
                        if result["status"] == "success":
                            st.success("✓ Successfully downloaded and processed use cases!")
                            if result.get("is_first_sync"):
                                st.info(f"Total: {result['total_processed']} detections")
                            else:
                                st.info(f"Added: {result.get('new_count', 0)}, Updated: {result.get('modified_count', 0)}")
                            
                            st.session_state.show_download = False
                            st.rerun()
                        elif result["status"] == "error":
                            st.error(f"Error: {result['message']}")
        
        except Exception as e:
            st.error(f"Error: {str(e)}")
        
        st.markdown("---")
    
    # Internal Library Use Cases
    st.subheader("📚 Internal Library")
    internal_use_cases = usecase_loader.get_use_cases_for_source(selected_source)
    
    if internal_use_cases:
        st.success(f"Found **{len(internal_use_cases)}** internal use case(s)")
        
        for idx, use_case in enumerate(internal_use_cases):
            with st.expander(f"**{use_case.get('Use case Name', 'Unnamed')}** - {use_case.get('MITRE Technique', 'N/A')}"):
                st.markdown(f"**MITRE Tactics:** {use_case.get('MITRE Tactics', 'N/A')}")
                st.markdown(f"**Description:** {use_case.get('Description', 'N/A')}")
                
                st.markdown("**SPL Query:**")
                st.code(use_case.get('SPL ', use_case.get('SPL', 'N/A')), language='sql')
                
                if use_case.get('L1_What_It_Detects'):
                    st.markdown("**What It Detects (L1 Guidance):**")
                    st.info(use_case['L1_What_It_Detects'])
                
                if use_case.get('L1_Validation_Steps'):
                    st.markdown("**Validation Steps:**")
                    for step in use_case['L1_Validation_Steps']:
                        st.markdown(f"- {step}")
    else:
        st.info(f"No internal use cases available for {get_display_name(selected_source)}")
    
    st.markdown("---")
    
    # External Splunk Use Cases - NOW WITH SAME FORMAT AS INTERNAL
    st.subheader("🌐 Splunk Public Use Cases")
    use_cases_file = kb_loader.kb_path / f"{selected_source}_usecases.json"
    if use_cases_file.exists():
        with open(use_cases_file, 'r', encoding='utf-8') as f:
            external_use_cases = json.load(f)
    else:
        external_use_cases = []
    
    if external_use_cases:
        st.success(f"Found **{len(external_use_cases)}** Splunk public use case(s)")
        
        for idx, uc in enumerate(external_use_cases):
            with st.expander(f"**{uc.get('name', 'Unnamed Detection')}** - {uc.get('mitre_technique', 'N/A')}"):
                st.markdown(f"**MITRE Tactics:** {uc.get('mitre_tactics', 'N/A')}")
                st.markdown(f"**Description:** {uc.get('description', 'N/A')}")
                
                st.markdown("**SPL Query:**")
                st.code(uc.get('spl_query', 'N/A'), language='spl')
                
                # SAME FORMAT AS INTERNAL LIBRARY
                if uc.get('L1_What_It_Detects'):
                    st.markdown("**What It Detects (L1 Guidance):**")
                    st.info(uc['L1_What_It_Detects'])
                
                if uc.get('L1_Validation_Steps'):
                    st.markdown("**Validation Steps:**")
                    for step in uc['L1_Validation_Steps']:
                        st.markdown(f"- {step}")
    else:
        st.info(f"No Splunk public use cases downloaded yet. Click 'Download Splunk Use Cases' above to fetch them.")

st.sidebar.markdown("---")
st.sidebar.caption("SIEM Log Source Onboarding Assistant v1.0")
