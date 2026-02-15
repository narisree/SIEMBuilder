import streamlit as st
import json
from utils.kb_loader import KBLoader
from utils.claude_client import ClaudeClient
from utils.usecase_loader import UseCaseLoader
from utils.use_case_cache import UseCaseCache
from utils.github_use_case_fetcher import GitHubUseCaseFetcher
from utils.use_case_parser import UseCaseParser

st.set_page_config(
    page_title="SIEM Log Source Onboarding Assistant",
    page_icon="🔒",
    layout="wide"
)

kb_loader = KBLoader()
usecase_loader = UseCaseLoader()
cache_manager = UseCaseCache()

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
    
    test_mode = st.sidebar.checkbox(
        "🧪 Test Mode",
        value=False,
        help="Download only 3 random use cases for testing"
    )
else:
    st.sidebar.warning("🔐 Claude API: Not configured")
    st.sidebar.caption("Chat and Use Case downloads disabled")
    test_mode = False

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
    
    if has_api_key:
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
    else:
        st.info("""
        🔐 **Claude API Required to Ask Questions**
        
        Add API key to `.streamlit/secrets.toml` or Streamlit Cloud secrets to enable chat.
        
        You can still view cached use cases in the "Splunk Public Use Cases" tab.
        """)

with tab4:
    st.header("Use Cases")
    
    cached_count = cache_manager.get_cached_count()
    
    col1, col2 = st.columns([3, 1])
    
    with col1:
        st.subheader("Splunk Public Use Cases")
        if test_mode:
            st.info("🧪 **TEST MODE**: Will download 3 random use cases")
        st.metric("Cached Use Cases", cached_count)
    
    with col2:
        if has_api_key:
            if st.button("⬇️ Download Use Cases", use_container_width=True):
                with st.spinner("Fetching from GitHub..."):
                    try:
                        fetcher = GitHubUseCaseFetcher()
                        parser = UseCaseParser(api_key)
                        
                        all_files = fetcher.get_all_use_case_files()
                        downloaded_ids = cache_manager.get_downloaded_ids()
                        
                        if test_mode:
                            selected_files = fetcher.select_random_diverse(
                                all_files, 
                                count=3, 
                                exclude_ids=downloaded_ids
                            )
                            
                            if len(selected_files) == 0:
                                st.success("✅ All use cases already downloaded!")
                            else:
                                st.info(f"📥 Downloading {len(selected_files)} new use cases...")
                        else:
                            selected_files = [f for f in all_files if f["sha"] not in downloaded_ids]
                            selected_files = selected_files[:100]
                            
                            if len(selected_files) == 0:
                                st.success("✅ All use cases already downloaded!")
                            else:
                                st.info(f"📥 Downloading {len(selected_files)} new use cases (batch 1-100)...")
                        
                        if len(selected_files) > 0:
                            progress_bar = st.progress(0)
                            status_text = st.empty()
                            
                            yaml_files = []
                            for idx, file_info in enumerate(selected_files):
                                try:
                                    yaml_content = fetcher.download_yaml_content(file_info["download_url"])
                                    if yaml_content:
                                        yaml_files.append({
                                            "content": yaml_content,
                                            "path": file_info["path"],
                                            "sha": file_info["sha"]
                                        })
                                    
                                    progress = int(((idx + 1) / len(selected_files)) * 50)
                                    progress_bar.progress(progress)
                                    status_text.text(f"Downloaded {idx + 1}/{len(selected_files)} files...")
                                except:
                                    continue
                            
                            status_text.text("Processing with Claude...")
                            
                            batch_size = 3
                            all_parsed = []
                            
                            for i in range(0, len(yaml_files), batch_size):
                                batch = yaml_files[i:i+batch_size]
                                
                                try:
                                    parsed = parser.parse_batch(batch)
                                    all_parsed.extend(parsed)
                                    
                                    progress = 50 + int(((i + batch_size) / len(yaml_files)) * 50)
                                    progress_bar.progress(min(progress, 100))
                                    status_text.text(f"Parsed {min(i + batch_size, len(yaml_files))}/{len(yaml_files)} files...")
                                except:
                                    continue
                            
                            for use_case in all_parsed:
                                cache_manager.add_to_cache(use_case)
                            
                            cache_manager.export_to_json()
                            
                            progress_bar.progress(100)
                            st.success(f"✅ Successfully downloaded and cached {len(all_parsed)} use cases!")
                            st.rerun()
                    
                    except Exception as e:
                        st.error(f"Error: {str(e)}")
        else:
            st.info("🔐 Add API key to download")
    
    st.markdown("---")
    
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
    
    st.subheader("🌐 Cached Splunk Use Cases")
    cached_use_cases = cache_manager.get_for_source(selected_source)
    
    if cached_use_cases:
        st.success(f"Found **{len(cached_use_cases)}** cached use case(s)")
        
        for idx, uc in enumerate(cached_use_cases):
            with st.expander(f"**{uc.get('name', 'Unnamed Detection')}** - {uc.get('mitre_technique', 'N/A')}"):
                st.markdown(f"**MITRE Tactics:** {uc.get('mitre_tactics', 'N/A')}")
                st.markdown(f"**Description:** {uc.get('description', 'N/A')}")
                
                st.markdown("**SPL Query:**")
                st.code(uc.get('spl_query', 'N/A'), language='sql')
                
                if uc.get('L1_What_It_Detects'):
                    st.markdown("**What It Detects (L1 Guidance):**")
                    st.info(uc['L1_What_It_Detects'])
                
                if uc.get('L1_Validation_Steps'):
                    st.markdown("**Validation Steps:**")
                    for step in uc['L1_Validation_Steps']:
                        st.markdown(f"- {step}")
    else:
        st.info(f"No cached use cases for {get_display_name(selected_source)}. Click 'Download Use Cases' above to fetch them.")

st.sidebar.markdown("---")
st.sidebar.caption("SIEM Log Source Onboarding Assistant v1.0")
