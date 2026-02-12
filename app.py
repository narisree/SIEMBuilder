"""
SIEM Log Source Onboarding Assistant
A Streamlit application to help Security Engineers onboard log sources into Splunk.
Supports multiple AI backends: Groq (free), HuggingFace (free), Claude (paid), Ollama (local).
Now includes CIM Mapping Tool for field-to-CIM data model mapping.
"""

import streamlit as st
from utils.kb_loader import KBLoader
from utils.ai_client import AIClientFactory, BaseAIClient
from utils.usecase_loader import UseCaseLoader

# Page configuration
st.set_page_config(
    page_title="SIEM Onboarding Assistant",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header { font-size: 2.5rem; font-weight: bold; color: #1E3A5F; margin-bottom: 0.5rem; }
    .sub-header { font-size: 1.2rem; color: #5A6C7D; margin-bottom: 2rem; }
    .stTabs [data-baseweb="tab-list"] { gap: 24px; }
    .stTabs [data-baseweb="tab"] { height: 50px; padding-left: 20px; padding-right: 20px; }
    .reference-card { background-color: #f8f9fa; border-radius: 8px; padding: 1rem; margin-bottom: 0.5rem; border-left: 4px solid #1E3A5F; }
    .chat-message { padding: 1rem; border-radius: 8px; margin-bottom: 1rem; }
    .user-message { background-color: #e3f2fd; border-left: 4px solid #1976d2; }
    .assistant-message { background-color: #f5f5f5; border-left: 4px solid #4caf50; }
    .warning-box { background-color: #fff3cd; border: 1px solid #ffc107; border-radius: 8px; padding: 1rem; margin: 1rem 0; }
    .success-box { background-color: #d4edda; border: 1px solid #28a745; border-radius: 8px; padding: 1rem; margin: 1rem 0; }
    .info-box { background-color: #e7f3ff; border: 1px solid #0066cc; border-radius: 8px; padding: 1rem; margin: 1rem 0; }
    .provider-card { background-color: #f8f9fa; border-radius: 8px; padding: 0.75rem; margin-bottom: 0.5rem; border: 1px solid #dee2e6; }
    .free-badge { background-color: #28a745; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; margin-left: 8px; }
    .paid-badge { background-color: #6c757d; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; margin-left: 8px; }
    .usecase-card { background-color: #ffffff; border: 1px solid #e0e0e0; border-radius: 10px; padding: 1.5rem; margin-bottom: 1.5rem; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
    .usecase-title { font-size: 1.2rem; font-weight: bold; color: #1E3A5F; margin-bottom: 0.5rem; }
    .mitre-badge { background-color: #dc3545; color: white; padding: 3px 10px; border-radius: 4px; font-size: 0.8rem; margin-right: 8px; display: inline-block; margin-bottom: 5px; }
    .technique-badge { background-color: #6f42c1; color: white; padding: 3px 10px; border-radius: 4px; font-size: 0.8rem; display: inline-block; margin-bottom: 5px; }
    .l1-guidance-box { background-color: #e8f4f8; border: 1px solid #17a2b8; border-radius: 8px; padding: 1rem; margin-top: 1rem; }
    .l1-validation-box { background-color: #fff8e6; border: 1px solid #ffc107; border-radius: 8px; padding: 1rem; margin-top: 1rem; }
    .cim-card { background-color: #f0f7ff; border: 1px solid #0066cc; border-radius: 8px; padding: 1rem; margin: 1rem 0; }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if "chat_history" not in st.session_state:
    st.session_state.chat_history = []
if "selected_source" not in st.session_state:
    st.session_state.selected_source = None
if "selected_provider" not in st.session_state:
    st.session_state.selected_provider = None
if "ai_client" not in st.session_state:
    st.session_state.ai_client = None

# Initialize loaders
kb_loader = KBLoader()
usecase_loader = UseCaseLoader()

def get_secrets_dict():
    """Get all available secrets as a dictionary."""
    secrets = {}
    try:
        if hasattr(st, 'secrets'):
            for key in ["ANTHROPIC_API_KEY", "GROQ_API_KEY", "HUGGINGFACE_API_KEY"]:
                try:
                    value = st.secrets.get(key)
                    if value:
                        secrets[key] = value
                except:
                    pass
    except:
        pass
    return secrets

def initialize_ai_client(provider: str, secrets: dict) -> BaseAIClient:
    """Initialize AI client for the selected provider."""
    provider_info = AIClientFactory.PROVIDERS.get(provider, {})
    key_name = provider_info.get("key_name")
    if provider == "ollama":
        return AIClientFactory.create_client("ollama")
    elif key_name and secrets.get(key_name):
        return AIClientFactory.create_client(provider, secrets.get(key_name))
    return None

# Sidebar
with st.sidebar:
    st.image("https://img.icons8.com/color/96/000000/security-checked.png", width=80)
    st.markdown("## 🛡️ SIEM Onboarding")
    st.markdown("---")
    
    st.markdown("### 📋 Select Log Source")
    log_sources = kb_loader.get_available_sources()
    selected_source = st.selectbox(
        "Choose a log source to onboard:",
        options=list(log_sources.keys()),
        format_func=lambda x: log_sources[x]["display_name"],
        key="source_selector"
    )
    
    if st.session_state.selected_source != selected_source:
        st.session_state.selected_source = selected_source
        st.session_state.chat_history = []
    
    st.markdown("---")
    st.markdown("### 🤖 AI Assistant")
    
    providers = AIClientFactory.get_available_providers()
    secrets = get_secrets_dict()
    
    available_providers = []
    for prov_id, prov_info in providers.items():
        key_name = prov_info.get("key_name")
        if prov_id == "ollama":
            available_providers.append(prov_id)
        elif key_name and secrets.get(key_name):
            available_providers.append(prov_id)
    
    if available_providers:
        selected_provider = st.selectbox(
            "AI Provider:",
            options=available_providers,
            format_func=lambda x: providers[x]["name"],
            key="provider_selector"
        )
        
        if st.session_state.selected_provider != selected_provider:
            st.session_state.selected_provider = selected_provider
            st.session_state.ai_client = initialize_ai_client(selected_provider, secrets)
            st.session_state.chat_history = []
        
        if st.session_state.ai_client:
            st.success(f"✅ {st.session_state.ai_client.get_provider_name()}")
    else:
        st.warning("⚠️ No AI configured")
        st.markdown("Add API key in Settings")
    
    st.markdown("---")
    st.markdown("### ℹ️ About")
    st.markdown("This tool helps onboard log sources into Splunk SIEM.")

# Main content
st.markdown('<p class="main-header">🛡️ SIEM Log Source Onboarding Assistant</p>', unsafe_allow_html=True)
st.markdown(f'<p class="sub-header">Currently viewing: <strong>{log_sources[selected_source]["display_name"]}</strong></p>', unsafe_allow_html=True)

# Create tabs
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "📘 Integration Guide", "🔗 References", "🎯 Use Cases", 
    "🔧 CIM Mapper", "💬 AI Chat", "⚙️ AI Setup"
])

# Tab 1: Integration Guide
with tab1:
    kb_content = kb_loader.load_kb_content(selected_source)
    if kb_content["success"]:
        st.markdown(kb_content["content"])
    else:
        st.warning(f"KB not found: {kb_content['message']}")

# Tab 2: References
with tab2:
    references = kb_loader.get_references(selected_source)
    st.markdown(f"### 📚 Resources for {log_sources[selected_source]['display_name']}")
    
    if references["success"]:
        ref_data = references["data"]
        st.markdown("#### 📄 Official Documentation")
        for doc in ref_data.get("official_docs", []):
            st.markdown(f"- [{doc['title']}]({doc['url']})")
        
        st.markdown("#### 🎥 YouTube Videos")
        for video in ref_data.get("youtube", []):
            st.markdown(f"- [{video['title']}]({video['url']})")
        
        if ref_data.get("blogs_optional"):
            st.markdown("#### 📝 Blogs & Community")
            for blog in ref_data["blogs_optional"]:
                st.markdown(f"- [{blog['title']}]({blog['url']})")
    else:
        st.warning(references["message"])

# Tab 3: Use Cases
with tab3:
    st.markdown(f"### 🎯 Security Use Cases for {log_sources[selected_source]['display_name']}")
    use_cases = usecase_loader.get_use_cases_for_source(selected_source)
    
    if use_cases:
        st.success(f"Found **{len(use_cases)}** use case(s)")
        for idx, use_case in enumerate(use_cases):
            st.markdown(f"#### 📋 {use_case.get('Use case Name', 'Unnamed')}")
            st.markdown(f"**MITRE:** {use_case.get('MITRE Tactics', 'N/A')} | {use_case.get('MITRE Technique', 'N/A')}")
            st.info(use_case.get('Description', 'No description'))
            
            st.markdown("**SPL Query:**")
            st.code(use_case.get('SPL ', use_case.get('SPL', '')), language="sql")
            
            if use_case.get('L1_What_It_Detects'):
                st.markdown("**L1 Guidance:**")
                st.markdown(use_case['L1_What_It_Detects'])
            st.markdown("---")
    else:
        st.warning("No use cases found for this log source.")

# Tab 4: CIM Mapper
with tab4:
    st.markdown("### 🔧 Splunk CIM Field Mapper")
    st.markdown("*Upload log samples to map fields to Splunk CIM data models*")

    # Check CIM module availability
    try:
        from utils.cim.log_parser import LogParser
        from utils.cim.vector_store import initialize_vector_store
        from utils.cim.llm_chain import create_mapping_chain
        from utils.cim.output_generator import OutputGenerator
        from utils.cim.ai_field_parser import create_ai_field_parser
        from utils.cim.vendor_doc_loader import create_vendor_doc_loader
        CIM_AVAILABLE = True
    except ImportError as e:
        CIM_AVAILABLE = False
        cim_error = str(e)

    if not CIM_AVAILABLE:
        st.warning(f"CIM Mapper dependencies missing: {cim_error}")
        st.info("Install with: `pip install chromadb sentence-transformers`")
    else:
        # Deployment mode
        deployment_mode = st.selectbox(
            "🎯 Deployment Mode:",
            ["Both (Cloud + Enterprise)", "Splunk Cloud (GUI)", "Splunk Enterprise (Config)"]
        )
        mode_map = {"Both (Cloud + Enterprise)": "both", "Splunk Cloud (GUI)": "cloud", "Splunk Enterprise (Config)": "enterprise"}
        selected_mode = mode_map[deployment_mode]

        st.markdown("---")

        # Enhanced AI Options
        st.markdown("#### 🤖 AI-Enhanced Field Analysis")
        col_opt1, col_opt2 = st.columns(2)
        with col_opt1:
            use_ai_field_parsing = st.checkbox(
                "Enable AI Field Parsing",
                value=True,
                help="Use AI to semantically analyze fields for better CIM mapping accuracy"
            )
        with col_opt2:
            use_vendor_docs = st.checkbox(
                "Include Vendor Documentation",
                value=False,
                help="Upload vendor documentation to improve field interpretation"
            )

        st.markdown("---")
        st.markdown("#### 📤 Upload Files")

        col1, col2 = st.columns([2, 1])
        with col1:
            uploaded_file = st.file_uploader(
                "Upload log file",
                type=["log", "txt", "json", "csv", "xml"],
                key="log_file_uploader"
            )
        with col2:
            sourcetype_name = st.text_input("Sourcetype Name", placeholder="my_logs")

        # Optional vendor documentation upload
        vendor_doc_file = None
        vendor_doc_result = None
        if use_vendor_docs:
            vendor_doc_file = st.file_uploader(
                "Upload Vendor Documentation (Optional)",
                type=["pdf", "md", "txt", "html"],
                key="vendor_doc_uploader",
                help="Upload vendor field documentation for improved accuracy"
            )

            if vendor_doc_file:
                with st.spinner("Processing vendor documentation..."):
                    vendor_loader = create_vendor_doc_loader()
                    vendor_doc_result = vendor_loader.load_document(
                        vendor_doc_file.read(),
                        vendor_doc_file.name
                    )

                    if vendor_doc_result.success:
                        st.success(f"Loaded vendor documentation ({vendor_doc_result.doc_type})")

                        # Show extracted info
                        col_v1, col_v2 = st.columns(2)
                        with col_v1:
                            if vendor_doc_result.extracted_vendor:
                                st.info(f"Vendor: {vendor_doc_result.extracted_vendor}")
                        with col_v2:
                            if vendor_doc_result.field_definitions:
                                st.info(f"Field definitions found: {len(vendor_doc_result.field_definitions)}")

                        with st.expander("📖 Extracted Field Definitions"):
                            if vendor_doc_result.field_definitions:
                                for fname, fdesc in list(vendor_doc_result.field_definitions.items())[:20]:
                                    st.text(f"• {fname}: {fdesc[:80]}...")
                            else:
                                st.text("No field definitions automatically extracted")
                    else:
                        st.warning(f"Could not process document: {vendor_doc_result.error}")

        if uploaded_file and sourcetype_name:
            file_content = uploaded_file.read()

            st.markdown("#### 🔍 Log Analysis")
            with st.spinner("Analyzing log format..."):
                parser = LogParser()
                parsed_log = parser.parse_file(file_content, uploaded_file.name)

            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Format", parsed_log.format.value.upper())
            with col2:
                st.metric("Fields", len(parsed_log.fields))
            with col3:
                st.metric("Confidence", f"{parsed_log.confidence:.0%}")

            # AI Field Parsing (if enabled)
            ai_field_result = None
            if use_ai_field_parsing and st.session_state.ai_client:
                with st.spinner("Performing AI semantic field analysis..."):
                    ai_parser = create_ai_field_parser(st.session_state.ai_client)

                    # Get vendor context if available
                    vendor_context = None
                    if vendor_doc_result and vendor_doc_result.success:
                        vendor_loader = create_vendor_doc_loader()
                        vendor_context = vendor_loader.get_context_for_ai(vendor_doc_result)

                    ai_field_result = ai_parser.analyze_fields(parsed_log, vendor_context)

                    if ai_field_result.success:
                        st.success("AI field analysis complete")

                        # Show AI-detected info
                        col_ai1, col_ai2, col_ai3 = st.columns(3)
                        with col_ai1:
                            if ai_field_result.log_category:
                                st.info(f"Category: {ai_field_result.log_category}")
                        with col_ai2:
                            if ai_field_result.vendor_detected:
                                st.info(f"Vendor: {ai_field_result.vendor_detected}")
                        with col_ai3:
                            review_count = sum(1 for f in ai_field_result.enriched_fields.values() if f.needs_review)
                            if review_count > 0:
                                st.warning(f"Fields need review: {review_count}")

            # Display detected fields with AI enrichment
            with st.expander("📋 Detected Fields" + (" (AI-Enhanced)" if ai_field_result else "")):
                if ai_field_result and ai_field_result.success:
                    # Show enhanced field table
                    st.markdown("| Field | Category | Suggested CIM | Type |")
                    st.markdown("|-------|----------|---------------|------|")
                    for name, values in list(parsed_log.fields.items())[:20]:
                        enriched = ai_field_result.enriched_fields.get(name)
                        if enriched:
                            category = enriched.semantic_category
                            cim_field = enriched.suggested_cim_field or "-"
                            map_type = enriched.mapping_type or "-"
                            flag = " (!)" if enriched.needs_review else ""
                            st.markdown(f"| `{name}`{flag} | {category} | {cim_field} | {map_type} |")
                        else:
                            sample = ', '.join(str(v) for v in list(set(values))[:2])
                            st.markdown(f"| `{name}` | - | - | - |")
                else:
                    for name, values in list(parsed_log.fields.items())[:15]:
                        st.text(f"• {name}: {', '.join(str(v) for v in list(set(values))[:3])}")

            with st.expander("📄 Sample Events"):
                for event in parsed_log.sample_events[:3]:
                    st.code(event)

            st.markdown("---")

            if not st.session_state.ai_client:
                st.warning("Configure AI provider in AI Setup tab first.")
            else:
                if st.button("Generate CIM Mappings", type="primary", use_container_width=True):
                    with st.spinner("Initializing CIM knowledge base..."):
                        import os
                        base_dir = os.path.dirname(os.path.abspath(__file__))
                        knowledge_dir = os.path.join(base_dir, "data", "cim_knowledge")
                        db_dir = os.path.join(base_dir, "data", "vector_db")

                        try:
                            vector_store = initialize_vector_store(knowledge_dir, db_dir)
                            if vector_store.available:
                                stats = vector_store.get_stats()
                                st.info(f"Loaded {stats['total_fields']} CIM fields")
                        except Exception as e:
                            st.error(f"Failed to init: {e}")
                            vector_store = None

                    if vector_store:
                        with st.spinner("Generating CIM mappings with AI analysis..."):
                            try:
                                mapping_chain = create_mapping_chain(vector_store, st.session_state.ai_client)

                                # Get vendor context for mapping
                                vendor_context_for_mapping = None
                                if vendor_doc_result and vendor_doc_result.success:
                                    vendor_loader = create_vendor_doc_loader()
                                    vendor_context_for_mapping = vendor_loader.get_context_for_ai(vendor_doc_result)

                                # Call analyze with enhanced parameters
                                result = mapping_chain.analyze(
                                    parsed_log,
                                    ai_field_result=ai_field_result if use_ai_field_parsing else None,
                                    vendor_doc_content=vendor_context_for_mapping
                                )

                                if result['success']:
                                    st.success("CIM Mapping Generated!")

                                    # Show enhancement badges
                                    if result.get('ai_field_analysis_used') or result.get('vendor_docs_used'):
                                        badges = []
                                        if result.get('ai_field_analysis_used'):
                                            badges.append("AI Field Analysis")
                                        if result.get('vendor_docs_used'):
                                            badges.append("Vendor Docs")
                                        st.caption(f"Enhanced with: {', '.join(badges)}")

                                    col1, col2, col3 = st.columns(3)
                                    with col1:
                                        st.metric("Data Model", result.get('data_model', 'Unknown'))
                                    with col2:
                                        st.metric("Dataset", result.get('dataset', 'Unknown'))
                                    with col3:
                                        st.metric("Confidence", f"{result.get('confidence', 0):.0%}")

                                    # Generate outputs
                                    output_gen = OutputGenerator(selected_mode)
                                    outputs = output_gen.generate_output(result, sourcetype_name)

                                    if 'gui_instructions' in outputs:
                                        with st.expander("GUI Instructions", expanded=True):
                                            st.markdown(outputs['gui_instructions'])
                                        st.download_button("Download GUI Instructions", outputs['gui_instructions'],
                                                         file_name=f"{sourcetype_name}_gui.md", mime="text/markdown")

                                    if 'props_conf' in outputs:
                                        with st.expander("Config Files"):
                                            st.code(outputs['props_conf'], language="ini")
                                        st.download_button("Download props.conf", outputs['props_conf'],
                                                         file_name=f"{sourcetype_name}_props.conf", mime="text/plain")

                                    with st.expander("Validation SPL"):
                                        st.markdown(outputs['validation_spl'])

                                    with st.expander("Raw AI Output"):
                                        st.markdown(result['mapping'])
                                else:
                                    st.error(f"Mapping failed: {result.get('error')}")
                            except Exception as e:
                                st.error(f"Error: {e}")
        else:
            st.markdown("""
            **How CIM Mapping Works:**
            1. Upload a sample log file
            2. AI detects format and extracts fields
            3. **(New)** AI performs semantic field analysis for better understanding
            4. **(New)** Optional vendor documentation improves accuracy
            5. Fields are mapped to CIM data models
            6. Get ready-to-use config files

            **AI-Enhanced Features:**
            - **AI Field Parsing**: Understands field semantics beyond pattern matching
            - **Vendor Documentation**: Upload PDF/MD/TXT docs for vendor-specific field meanings
            - **Improved Accuracy**: Better handling of vendor-specific naming conventions

            **Supported Data Models:** Authentication, Network_Traffic, Web, Change, Endpoint,
            Malware, Email, Intrusion_Detection, Network_Resolution, Alerts, Databases
            """)

# Tab 5: AI Chat
with tab5:
    st.markdown("### 💬 Ask Questions About This Integration")
    
    if st.session_state.ai_client:
        st.markdown(f"*Using **{st.session_state.ai_client.get_provider_name()}** for {log_sources[selected_source]['display_name']}*")
        
        for message in st.session_state.chat_history:
            role_icon = "🧑" if message["role"] == "user" else "🤖"
            css_class = "user-message" if message["role"] == "user" else "assistant-message"
            st.markdown(f'<div class="chat-message {css_class}"><strong>{role_icon}</strong>: {message["content"]}</div>', 
                       unsafe_allow_html=True)
        
        with st.form(key="chat_form", clear_on_submit=True):
            user_question = st.text_area("Your question:", placeholder="What ports need to be open?", height=100)
            col1, col2 = st.columns([1, 5])
            with col1:
                submit = st.form_submit_button("Send 📤")
            with col2:
                if st.form_submit_button("Clear 🗑️"):
                    st.session_state.chat_history = []
                    st.rerun()
        
        if submit and user_question.strip():
            st.session_state.chat_history.append({"role": "user", "content": user_question})
            kb_data = kb_loader.load_kb_content(selected_source)
            kb_context = kb_data["content"] if kb_data["success"] else ""
            
            with st.spinner("AI is thinking..."):
                response = st.session_state.ai_client.get_response(
                    question=user_question,
                    kb_content=kb_context,
                    source_name=log_sources[selected_source]["display_name"],
                    chat_history=st.session_state.chat_history[:-1]
                )
            
            if response["success"]:
                st.session_state.chat_history.append({"role": "assistant", "content": response["response"]})
            else:
                st.error(response['message'])
            st.rerun()
    else:
        st.warning("⚠️ Configure an AI provider in the **AI Setup** tab.")

# Tab 6: AI Setup
with tab6:
    st.markdown("### ⚙️ AI Provider Configuration")
    st.markdown("Configure an AI provider for chat and CIM mapper. **Free options available!**")
    st.markdown("---")
    
    providers = AIClientFactory.get_available_providers()
    secrets = get_secrets_dict()
    
    for prov_id, prov_info in providers.items():
        is_free = prov_info.get("free", False)
        badge = '<span class="free-badge">FREE</span>' if is_free else '<span class="paid-badge">PAID</span>'
        key_name = prov_info.get("key_name")
        
        is_configured = bool(secrets.get(key_name)) if key_name and prov_id != "ollama" else prov_id == "ollama"
        status = "✅ Configured" if is_configured else "❌ Not configured"
        
        st.markdown(f"""
        <div class="provider-card">
            <strong>{prov_info['name']}</strong> {badge}<br>
            <small>{prov_info['description']}</small><br>
            <small><strong>Status:</strong> {status}</small>
        </div>
        """, unsafe_allow_html=True)
        
        with st.expander(f"Setup: {prov_info['name']}"):
            if prov_id == "groq":
                st.markdown("""
                **Groq (FREE):** Llama 4 Scout, 460+ tokens/sec
                1. Go to [console.groq.com/keys](https://console.groq.com/keys)
                2. Create API key
                3. Add to secrets: `GROQ_API_KEY = "gsk_..."`
                """)
            elif prov_id == "huggingface":
                st.markdown("""
                **HuggingFace (FREE):** Mixtral 8x7B
                1. Go to [huggingface.co/settings/tokens](https://huggingface.co/settings/tokens)
                2. Create token
                3. Add: `HUGGINGFACE_API_KEY = "hf_..."`
                """)
            elif prov_id == "claude":
                st.markdown("""
                **Claude (PAID):** Most capable
                1. Go to [console.anthropic.com](https://console.anthropic.com/)
                2. Create API key
                3. Add: `ANTHROPIC_API_KEY = "sk-ant-..."`
                """)
            elif prov_id == "ollama":
                st.markdown("""
                **Ollama (LOCAL):** 100% free and private
                1. Download from [ollama.ai](https://ollama.ai)
                2. Run: `ollama pull llama3.2`
                """)
    
    st.markdown("---")
    st.markdown("""
    ### 🔐 How to Add Secrets
    **Streamlit Cloud:** Settings → Secrets → Add TOML  
    **Local:** Create `.streamlit/secrets.toml`
    """)

# Footer
st.markdown("---")
st.markdown("""
<div style="text-align: center; color: #888;">
    <p>SIEM Onboarding Assistant v1.2 | Includes CIM Mapper | Free AI Support (Groq, HuggingFace)</p>
</div>
""", unsafe_allow_html=True)
