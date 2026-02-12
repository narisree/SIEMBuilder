"""
SIEM Log Source Onboarding Assistant
A Streamlit application to help Security Engineers onboard log sources into Splunk.
Supports multiple AI backends: Groq (free), HuggingFace (free), Claude (paid), Ollama (local).
Now includes CIM Mapping Tool with vendor schema learning and enhanced log parsing.
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
    .schema-card { background-color: #f8fff8; border: 1px solid #28a745; border-radius: 8px; padding: 1rem; margin: 1rem 0; }
    .vendor-doc-card { background-color: #fffbf0; border: 1px solid #ff9800; border-radius: 8px; padding: 1rem; margin: 1rem 0; }
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
if "learned_schema" not in st.session_state:
    st.session_state.learned_schema = None

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
        st.session_state.learned_schema = None  # Reset schema when source changes
    
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
    st.markdown("**Version:** 1.3")
    st.markdown("**Features:**")
    st.markdown("- Integration Guides")
    st.markdown("- CIM Field Mapper")
    st.markdown("- Vendor Schema Learning")
    st.markdown("- AI-Powered Chat")

# Main content
st.markdown('<p class="main-header">🛡️ SIEM Log Source Onboarding Assistant</p>', unsafe_allow_html=True)
st.markdown(f'<p class="sub-header">Currently viewing: <strong>{log_sources[selected_source]["display_name"]}</strong></p>', unsafe_allow_html=True)

# Create tabs
tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
    "📘 Integration Guide", "🔗 References", "🎯 Use Cases", 
    "🔧 CIM Mapper", "📚 Schema Learner", "💬 AI Chat", "⚙️ AI Setup"
])

# Tab 1: Integration Guide
with tab1:
    kb_content = kb_loader.load_kb_content(selected_source)
    if kb_content["success"]:
        st.markdown(kb_content["content"])
    else:
        st.warning(f"KB not found: {kb_content['message']}")
        st.info("""
        **How to add this KB:**
        1. Create a file named `kb/{source_slug}.md`
        2. Follow the KB template structure
        3. Restart the application
        """.format(source_slug=selected_source))

# Tab 2: References
with tab2:
    references = kb_loader.get_references(selected_source)
    st.markdown(f"### 📚 Resources for {log_sources[selected_source]['display_name']}")
    
    if references["success"]:
        ref_data = references["data"]
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### 📄 Official Documentation")
            for doc in ref_data.get("official_docs", []):
                st.markdown(f"- [{doc['title']}]({doc['url']})")
        
        with col2:
            st.markdown("#### 🎥 YouTube Videos")
            for video in ref_data.get("youtube", []):
                st.markdown(f"- [{video['title']}]({video['url']})")
        
        if ref_data.get("blogs_optional"):
            st.markdown("#### 📝 Blogs & Community")
            for blog in ref_data["blogs_optional"]:
                st.markdown(f"- [{blog['title']}]({blog['url']})")
    else:
        st.warning(references["message"])
    
    # Add vendor doc links from CSV
    st.markdown("---")
    st.markdown("#### 📋 Vendor Field Documentation Links")
    
    try:
        from utils.cim.url_lookup import get_all_urls_for_source
        vendor_name = log_sources[selected_source].get("vendor", "")
        display_name = log_sources[selected_source].get("display_name", "")
        
        urls = get_all_urls_for_source(vendor_name)
        if not urls:
            urls = get_all_urls_for_source(display_name.split()[0])
        
        if urls:
            for url in urls[:5]:
                st.markdown(f"- [{url}]({url})")
        else:
            st.info("No vendor documentation links found for this source.")
    except ImportError:
        st.info("URL lookup module not available.")

# Tab 3: Use Cases
with tab3:
    st.markdown(f"### 🎯 Security Use Cases for {log_sources[selected_source]['display_name']}")
    use_cases = usecase_loader.get_use_cases_for_source(selected_source)
    
    if use_cases:
        st.success(f"Found **{len(use_cases)}** use case(s)")
        
        # Search functionality
        search_query = st.text_input("🔍 Search use cases", placeholder="e.g., brute force, MFA")
        
        if search_query:
            use_cases = [uc for uc in use_cases if search_query.lower() in str(uc).lower()]
        
        for idx, use_case in enumerate(use_cases):
            with st.expander(f"📋 {use_case.get('Use case Name', 'Unnamed')}", expanded=(idx == 0)):
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    st.markdown(f"**Description:** {use_case.get('Description', 'No description')}")
                
                with col2:
                    st.markdown(f"**MITRE Tactic:** `{use_case.get('MITRE Tactics', 'N/A')}`")
                    st.markdown(f"**MITRE Technique:** `{use_case.get('MITRE Technique', 'N/A')}`")
                
                st.markdown("---")
                st.markdown("**SPL Query:**")
                spl = use_case.get('SPL ', use_case.get('SPL', ''))
                st.code(spl, language="sql")
                
                # L1 Analyst Guidance
                if use_case.get('L1_What_It_Detects'):
                    st.markdown("---")
                    st.markdown("**🎓 L1 Analyst Guidance**")
                    
                    st.markdown(f"**What This Detects:** {use_case['L1_What_It_Detects']}")
                    
                    if use_case.get('L1_Validation_Steps'):
                        st.markdown("**Validation Steps:**")
                        for step in use_case['L1_Validation_Steps']:
                            st.markdown(f"- {step}")
    else:
        st.warning("No use cases found for this log source.")
        st.info("Use cases are loaded from `kb/library.csv`. Add entries for this log source to see them here.")

# Tab 4: CIM Mapper
with tab4:
    st.markdown("### 🔧 Splunk CIM Field Mapper")
    st.markdown("*Upload log samples to map fields to Splunk CIM data models*")

    # Check CIM module availability
    CIM_AVAILABLE = True
    cim_error = ""
    
    try:
        from utils.cim.log_parser import LogParser
        from utils.cim.vector_store import initialize_vector_store
        from utils.cim.llm_chain import create_mapping_chain
        from utils.cim.output_generator import OutputGenerator
    except ImportError as e:
        CIM_AVAILABLE = False
        cim_error = str(e)
    
    # Try to import enhanced modules
    ENHANCED_PARSER_AVAILABLE = False
    try:
        from utils.cim.log_parser_enhanced import VendorAwareLogParser
        ENHANCED_PARSER_AVAILABLE = True
    except ImportError:
        pass
    
    AI_FIELD_PARSER_AVAILABLE = False
    try:
        from utils.cim.ai_field_parser import create_ai_field_parser
        AI_FIELD_PARSER_AVAILABLE = True
    except ImportError:
        pass
    
    VENDOR_DOC_AVAILABLE = False
    try:
        from utils.cim.vendor_doc_loader import create_vendor_doc_loader
        VENDOR_DOC_AVAILABLE = True
    except ImportError:
        pass

    if not CIM_AVAILABLE:
        st.warning(f"CIM Mapper dependencies missing: {cim_error}")
        st.info("Install with: `pip install chromadb sentence-transformers`")
    else:
        # Deployment mode
        deployment_mode = st.selectbox(
            "🎯 Deployment Mode:",
            ["Both (Cloud + Enterprise)", "Splunk Cloud (GUI)", "Splunk Enterprise (Config)"]
        )
        mode_map = {
            "Both (Cloud + Enterprise)": "both", 
            "Splunk Cloud (GUI)": "cloud", 
            "Splunk Enterprise (Config)": "enterprise"
        }
        selected_mode = mode_map[deployment_mode]

        st.markdown("---")

        # Enhanced Options
        st.markdown("#### 🤖 AI-Enhanced Field Analysis")
        
        col_opt1, col_opt2, col_opt3 = st.columns(3)
        with col_opt1:
            use_ai_field_parsing = st.checkbox(
                "Enable AI Field Parsing",
                value=True,
                help="Use AI to semantically analyze fields for better CIM mapping accuracy",
                disabled=not AI_FIELD_PARSER_AVAILABLE
            )
        with col_opt2:
            use_vendor_docs = st.checkbox(
                "Include Vendor Documentation",
                value=False,
                help="Upload vendor documentation to improve field interpretation",
                disabled=not VENDOR_DOC_AVAILABLE
            )
        with col_opt3:
            use_learned_schema = st.checkbox(
                "Use Learned Schema",
                value=st.session_state.learned_schema is not None,
                help="Use vendor schema learned from documentation URLs",
                disabled=st.session_state.learned_schema is None
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
        
        if use_vendor_docs and VENDOR_DOC_AVAILABLE:
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
                        st.success(f"✅ Loaded vendor documentation ({vendor_doc_result.doc_type})")

                        col_v1, col_v2 = st.columns(2)
                        with col_v1:
                            if vendor_doc_result.extracted_vendor:
                                st.info(f"**Vendor:** {vendor_doc_result.extracted_vendor}")
                        with col_v2:
                            if vendor_doc_result.field_definitions:
                                st.info(f"**Field definitions found:** {len(vendor_doc_result.field_definitions)}")

                        with st.expander("📖 Extracted Field Definitions"):
                            if vendor_doc_result.field_definitions:
                                for fname, fdesc in list(vendor_doc_result.field_definitions.items())[:20]:
                                    st.text(f"• {fname}: {fdesc[:80]}...")
                            else:
                                st.text("No field definitions automatically extracted")
                    else:
                        st.warning(f"Could not process document: {vendor_doc_result.error}")

        # Process log file
        if uploaded_file and sourcetype_name:
            file_content = uploaded_file.read()

            st.markdown("#### 🔍 Log Analysis")
            
            with st.spinner("Analyzing log format..."):
                # Use enhanced parser with learned schema if available
                if use_learned_schema and st.session_state.learned_schema and ENHANCED_PARSER_AVAILABLE:
                    parser = VendorAwareLogParser()
                    parsed_log = parser.parse_with_vendor_schema(
                        file_content, 
                        uploaded_file.name,
                        st.session_state.learned_schema
                    )
                    st.success("✅ Using learned vendor schema for field extraction")
                else:
                    parser = LogParser()
                    parsed_log = parser.parse_file(file_content, uploaded_file.name)

            # Display metrics
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Format", parsed_log.format.value.upper())
            with col2:
                st.metric("Fields", len(parsed_log.fields))
            with col3:
                st.metric("Confidence", f"{parsed_log.confidence:.0%}")
            with col4:
                schema_status = "✅ Yes" if getattr(parsed_log, 'schema_used', False) else "❌ No"
                st.metric("Schema Used", schema_status)

            # AI Field Parsing (if enabled)
            ai_field_result = None
            if use_ai_field_parsing and st.session_state.ai_client and AI_FIELD_PARSER_AVAILABLE:
                with st.spinner("Performing AI semantic field analysis..."):
                    ai_parser = create_ai_field_parser(st.session_state.ai_client)

                    # Get vendor context if available
                    vendor_context = None
                    if vendor_doc_result and vendor_doc_result.success and VENDOR_DOC_AVAILABLE:
                        vendor_loader = create_vendor_doc_loader()
                        vendor_context = vendor_loader.get_context_for_ai(vendor_doc_result)

                    ai_field_result = ai_parser.analyze_fields(parsed_log, vendor_context)

                    if ai_field_result.success:
                        st.success("✅ AI field analysis complete")

                        col_ai1, col_ai2, col_ai3 = st.columns(3)
                        with col_ai1:
                            if ai_field_result.log_category:
                                st.info(f"**Category:** {ai_field_result.log_category}")
                        with col_ai2:
                            if ai_field_result.vendor_detected:
                                st.info(f"**Vendor:** {ai_field_result.vendor_detected}")
                        with col_ai3:
                            review_count = sum(1 for f in ai_field_result.enriched_fields.values() if f.needs_review)
                            if review_count > 0:
                                st.warning(f"**Fields need review:** {review_count}")

            # Display detected fields with AI enrichment
            with st.expander("📋 Detected Fields" + (" (AI-Enhanced)" if ai_field_result else ""), expanded=True):
                if ai_field_result and ai_field_result.success:
                    # Show enhanced field table
                    field_data = []
                    for name, values in list(parsed_log.fields.items())[:30]:
                        enriched = ai_field_result.enriched_fields.get(name)
                        sample = ', '.join(str(v) for v in list(set(values))[:2])[:40]
                        if enriched:
                            field_data.append({
                                "Field": name,
                                "Category": enriched.semantic_category,
                                "CIM Field": enriched.suggested_cim_field or "-",
                                "Type": enriched.mapping_type or "-",
                                "Review": "⚠️" if enriched.needs_review else "✅",
                                "Sample": sample
                            })
                        else:
                            field_data.append({
                                "Field": name,
                                "Category": "-",
                                "CIM Field": "-",
                                "Type": "-",
                                "Review": "-",
                                "Sample": sample
                            })
                    
                    import pandas as pd
                    st.dataframe(pd.DataFrame(field_data), use_container_width=True)
                else:
                    for name, values in list(parsed_log.fields.items())[:15]:
                        sample_vals = ', '.join(str(v) for v in list(set(values))[:3])
                        st.text(f"• {name}: {sample_vals[:60]}...")

            with st.expander("📄 Sample Events"):
                for i, event in enumerate(parsed_log.sample_events[:3], 1):
                    st.text(f"Event {i}:")
                    st.code(event[:500] + ("..." if len(event) > 500 else ""), language="text")

            st.markdown("---")

            if not st.session_state.ai_client:
                st.warning("⚠️ Configure AI provider in **AI Setup** tab first.")
            else:
                if st.button("🚀 Generate CIM Mappings", type="primary", use_container_width=True):
                    with st.spinner("Initializing CIM knowledge base..."):
                        import os
                        base_dir = os.path.dirname(os.path.abspath(__file__))
                        knowledge_dir = os.path.join(base_dir, "data", "cim_knowledge")
                        db_dir = os.path.join(base_dir, "data", "vector_db")

                        try:
                            vector_store = initialize_vector_store(knowledge_dir, db_dir)
                            if vector_store.available:
                                stats = vector_store.get_stats()
                                st.info(f"📚 Loaded {stats['total_fields']} CIM fields from {stats['num_data_models']} data models")
                        except Exception as e:
                            st.error(f"Failed to initialize CIM knowledge base: {e}")
                            vector_store = None

                    if vector_store:
                        with st.spinner("Generating CIM mappings with AI analysis..."):
                            try:
                                mapping_chain = create_mapping_chain(vector_store, st.session_state.ai_client)

                                # Get vendor context for mapping
                                vendor_context_for_mapping = None
                                if vendor_doc_result and vendor_doc_result.success and VENDOR_DOC_AVAILABLE:
                                    vendor_loader = create_vendor_doc_loader()
                                    vendor_context_for_mapping = vendor_loader.get_context_for_ai(vendor_doc_result)

                                # Call analyze with enhanced parameters
                                result = mapping_chain.analyze(
                                    parsed_log,
                                    ai_field_result=ai_field_result if use_ai_field_parsing else None,
                                    vendor_doc_content=vendor_context_for_mapping
                                )

                                if result['success']:
                                    st.success("✅ CIM Mapping Generated Successfully!")

                                    # Show enhancement badges
                                    badges = []
                                    if result.get('ai_field_analysis_used'):
                                        badges.append("🤖 AI Field Analysis")
                                    if result.get('vendor_docs_used'):
                                        badges.append("📚 Vendor Docs")
                                    if getattr(parsed_log, 'schema_used', False):
                                        badges.append("📋 Learned Schema")
                                    
                                    if badges:
                                        st.caption(f"Enhanced with: {' | '.join(badges)}")

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

                                    # Display outputs in tabs
                                    output_tabs = st.tabs(["📋 GUI Instructions", "📁 Config Files", "✅ Validation", "🔍 Raw Output"])
                                    
                                    with output_tabs[0]:
                                        if 'gui_instructions' in outputs:
                                            st.markdown(outputs['gui_instructions'])
                                            st.download_button(
                                                "📥 Download GUI Instructions",
                                                outputs['gui_instructions'],
                                                file_name=f"{sourcetype_name}_gui_instructions.md",
                                                mime="text/markdown"
                                            )
                                    
                                    with output_tabs[1]:
                                        if 'props_conf' in outputs:
                                            st.markdown("**props.conf**")
                                            st.code(outputs['props_conf'], language="ini")
                                            st.download_button(
                                                "📥 Download props.conf",
                                                outputs['props_conf'],
                                                file_name=f"{sourcetype_name}_props.conf",
                                                mime="text/plain"
                                            )
                                        
                                        if 'eventtypes_conf' in outputs:
                                            st.markdown("**eventtypes.conf**")
                                            st.code(outputs['eventtypes_conf'], language="ini")
                                        
                                        if 'tags_conf' in outputs:
                                            st.markdown("**tags.conf**")
                                            st.code(outputs['tags_conf'], language="ini")
                                    
                                    with output_tabs[2]:
                                        if 'validation_spl' in outputs:
                                            st.markdown(outputs['validation_spl'])
                                    
                                    with output_tabs[3]:
                                        st.markdown("**Raw AI Mapping Output**")
                                        st.markdown(result['mapping'])

                                else:
                                    st.error(f"❌ Mapping failed: {result.get('error')}")
                            except Exception as e:
                                st.error(f"❌ Error during mapping: {e}")
                                import traceback
                                st.code(traceback.format_exc())
        else:
            # Instructions when no file uploaded
            st.markdown("""
            <div class="cim-card">
            <h4>📖 How CIM Mapping Works</h4>
            
            1. **Upload a sample log file** - Supports JSON, CSV, XML, Syslog, CEF, LEEF
            2. **AI detects format and extracts fields** - Automatic format detection
            3. **AI performs semantic field analysis** - Understands field meanings
            4. **Optional: Upload vendor documentation** - Improves accuracy
            5. **Fields are mapped to CIM data models** - Following Splunk best practices
            6. **Get ready-to-use config files** - For Cloud (GUI) or Enterprise (config)
            
            **AI-Enhanced Features:**
            - 🤖 **AI Field Parsing**: Understands field semantics beyond pattern matching
            - 📚 **Vendor Documentation**: Upload PDF/MD/TXT docs for vendor-specific field meanings
            - 📋 **Schema Learning**: Learn schemas from vendor documentation URLs (see Schema Learner tab)
            - ✅ **Improved Accuracy**: Better handling of vendor-specific naming conventions
            
            **Supported Data Models:** Authentication, Network_Traffic, Web, Change, Endpoint,
            Malware, Email, Intrusion_Detection, Network_Resolution, Alerts, Databases
            </div>
            """, unsafe_allow_html=True)

# Tab 5: Schema Learner
with tab5:
    st.markdown("### 📚 Vendor Schema Learner")
    st.markdown("*Learn log field schemas from vendor documentation URLs*")
    
    SCHEMA_LEARNER_AVAILABLE = False
    try:
        from utils.cim.vendor_schema_learner import create_vendor_schema_learner
        from utils.cim.url_lookup import load_vendor_doc_links, get_all_urls_for_source
        SCHEMA_LEARNER_AVAILABLE = True
    except ImportError as e:
        st.warning(f"Schema Learner module not available: {e}")
        st.info("Ensure `utils/cim/vendor_schema_learner.py` and `utils/cim/url_lookup.py` are present.")
    
    if SCHEMA_LEARNER_AVAILABLE:
        st.markdown("""
        <div class="vendor-doc-card">
        <h4>🎓 What is Schema Learning?</h4>
        
        Schema learning automatically extracts field definitions from vendor documentation.
        This is especially useful for **positional formats** like Palo Alto Traffic logs where
        field names are determined by column position, not by the data itself.
        
        **Benefits:**
        - ✅ Accurate field names from vendor specs
        - ✅ Correct field positions for CSV/positional formats
        - ✅ Cached schemas for fast re-use
        - ✅ AI-powered extraction from documentation pages
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("---")
        
        # Load available vendor doc links
        vendor_links = load_vendor_doc_links()
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### 📋 Available Vendor Documentation")
            
            if vendor_links:
                vendor_options = list(vendor_links.keys())
                selected_vendor_doc = st.selectbox(
                    "Select a log source:",
                    options=vendor_options,
                    key="vendor_doc_selector"
                )
                
                if selected_vendor_doc:
                    st.markdown(f"**Documentation URLs for {selected_vendor_doc}:**")
                    for i, url in enumerate(vendor_links[selected_vendor_doc], 1):
                        st.markdown(f"{i}. [{url[:60]}...]({url})")
            else:
                st.warning("No vendor documentation links found in `data/cim_knowledge/Log_Definition_Links.csv`")
        
        with col2:
            st.markdown("#### 🔗 Custom URL")
            custom_url = st.text_input(
                "Or enter a documentation URL:",
                placeholder="https://docs.vendor.com/log-fields"
            )
            
            vendor_name = st.text_input("Vendor Name:", placeholder="Palo Alto")
            product_name = st.text_input("Product Name:", placeholder="Firewall")
            log_type = st.text_input("Log Type:", placeholder="Traffic")
        
        st.markdown("---")
        
        # Learn Schema Button
        if st.session_state.ai_client:
            col_btn1, col_btn2 = st.columns(2)
            
            with col_btn1:
                learn_from_list = st.button(
                    "📚 Learn from Selected",
                    type="primary",
                    disabled=not (SCHEMA_LEARNER_AVAILABLE and vendor_links)
                )
            
            with col_btn2:
                learn_from_custom = st.button(
                    "🔗 Learn from Custom URL",
                    type="secondary",
                    disabled=not (custom_url and vendor_name and log_type)
                )
            
            if learn_from_list and selected_vendor_doc:
                urls = vendor_links.get(selected_vendor_doc, [])
                if urls:
                    # Parse vendor/product/log_type from selected_vendor_doc
                    parts = selected_vendor_doc.split()
                    v_name = parts[0] if parts else "Unknown"
                    l_type = parts[-1] if len(parts) > 1 else "Unknown"
                    p_name = "Firewall" if "firewall" in selected_vendor_doc.lower() else "Unknown"
                    
                    with st.spinner(f"Learning schema from {selected_vendor_doc}..."):
                        try:
                            learner = create_vendor_schema_learner(st.session_state.ai_client)
                            schema = learner.learn_schema(
                                vendor=v_name,
                                product=p_name,
                                log_type=l_type,
                                doc_url=urls[0],
                                force_refresh=False
                            )
                            
                            if schema.fields:
                                st.session_state.learned_schema = schema
                                st.success(f"✅ Learned schema with {len(schema.fields)} fields!")
                            else:
                                st.warning("No fields extracted. Check the documentation URL.")
                        except Exception as e:
                            st.error(f"Error learning schema: {e}")
            
            if learn_from_custom and custom_url:
                with st.spinner(f"Learning schema from custom URL..."):
                    try:
                        learner = create_vendor_schema_learner(st.session_state.ai_client)
                        schema = learner.learn_schema(
                            vendor=vendor_name,
                            product=product_name,
                            log_type=log_type,
                            doc_url=custom_url,
                            force_refresh=True
                        )
                        
                        if schema.fields:
                            st.session_state.learned_schema = schema
                            st.success(f"✅ Learned schema with {len(schema.fields)} fields!")
                        else:
                            st.warning("No fields extracted. Try a different documentation URL.")
                    except Exception as e:
                        st.error(f"Error learning schema: {e}")
        else:
            st.warning("⚠️ Configure an AI provider in the **AI Setup** tab to use Schema Learning.")
        
        # Display learned schema
        if st.session_state.learned_schema:
            st.markdown("---")
            st.markdown("#### 📋 Currently Loaded Schema")
            
            schema = st.session_state.learned_schema
            
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Vendor", schema.vendor)
            with col2:
                st.metric("Product", schema.product)
            with col3:
                st.metric("Log Type", schema.log_type)
            with col4:
                st.metric("Fields", len(schema.fields))
            
            st.markdown(f"**Format:** {schema.format_type}")
            if schema.delimiter:
                st.markdown(f"**Delimiter:** `{schema.delimiter}`")
            if schema.parsing_notes:
                st.info(f"**Notes:** {schema.parsing_notes}")
            
            with st.expander("📄 Field Definitions", expanded=True):
                import pandas as pd
                field_data = []
                for f in schema.fields[:50]:
                    field_data.append({
                        "Position": f.position if f.position is not None else "-",
                        "Field Name": f.name,
                        "Data Type": f.data_type,
                        "Description": f.description[:60] + "..." if len(f.description) > 60 else f.description,
                        "CIM Hint": f.cim_hint or "-"
                    })
                
                st.dataframe(pd.DataFrame(field_data), use_container_width=True)
            
            if st.button("🗑️ Clear Schema"):
                st.session_state.learned_schema = None
                st.rerun()

# Tab 6: AI Chat
with tab5:
    pass  # Already handled in tab5

with tab6:
    st.markdown("### 💬 Ask Questions About This Integration")
    
    if st.session_state.ai_client:
        st.markdown(f"*Using **{st.session_state.ai_client.get_provider_name()}** for {log_sources[selected_source]['display_name']}*")
        
        # Display chat history
        for message in st.session_state.chat_history:
            role_icon = "🧑" if message["role"] == "user" else "🤖"
            css_class = "user-message" if message["role"] == "user" else "assistant-message"
            st.markdown(
                f'<div class="chat-message {css_class}"><strong>{role_icon}</strong>: {message["content"]}</div>', 
                unsafe_allow_html=True
            )
        
        # Chat input form
        with st.form(key="chat_form", clear_on_submit=True):
            user_question = st.text_area(
                "Your question:",
                placeholder="What ports need to be open? How do I configure the inputs.conf?",
                height=100
            )
            col1, col2 = st.columns([1, 5])
            with col1:
                submit = st.form_submit_button("Send 📤", type="primary")
            with col2:
                if st.form_submit_button("Clear History 🗑️"):
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
                st.session_state.chat_history.append({
                    "role": "assistant", 
                    "content": response["response"]
                })
            else:
                st.error(f"❌ {response['message']}")
            st.rerun()
        
        # Quick questions
        st.markdown("---")
        st.markdown("**💡 Quick Questions:**")
        quick_questions = [
            "What are the network connectivity requirements?",
            "What log types should I collect?",
            "How do I troubleshoot if logs aren't appearing?",
            "What Splunk Add-on do I need?",
            "What are the security considerations?"
        ]
        
        cols = st.columns(3)
        for i, q in enumerate(quick_questions):
            with cols[i % 3]:
                if st.button(q[:40] + "...", key=f"quick_{i}"):
                    st.session_state.chat_history.append({"role": "user", "content": q})
                    kb_data = kb_loader.load_kb_content(selected_source)
                    kb_context = kb_data["content"] if kb_data["success"] else ""
                    
                    response = st.session_state.ai_client.get_response(
                        question=q,
                        kb_content=kb_context,
                        source_name=log_sources[selected_source]["display_name"],
                        chat_history=st.session_state.chat_history[:-1]
                    )
                    
                    if response["success"]:
                        st.session_state.chat_history.append({
                            "role": "assistant",
                            "content": response["response"]
                        })
                    st.rerun()
    else:
        st.warning("⚠️ Configure an AI provider in the **AI Setup** tab to use the chat feature.")
        st.info("""
        **How to get started:**
        1. Go to the **AI Setup** tab
        2. Choose a provider (Groq is FREE and recommended!)
        3. Add your API key
        4. Return here to chat
        """)

# Tab 7: AI Setup
with tab7:
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
        
        with st.expander(f"📋 Setup Instructions: {prov_info['name']}"):
            if prov_id == "groq":
                st.markdown("""
                ### Groq (FREE - Recommended!) 🌟
                
                **Model:** Llama 4 Scout - Very fast inference (460+ tokens/sec)
                
                **Setup Steps:**
                1. Go to [console.groq.com/keys](https://console.groq.com/keys)
                2. Create a free account
                3. Generate an API key
                4. Add to your Streamlit secrets:
                
                ```toml
                GROQ_API_KEY = "gsk_your_key_here"
                ```
                
                **Rate Limits:** ~30 requests/minute on free tier
                """)
            elif prov_id == "huggingface":
                st.markdown("""
                ### HuggingFace (FREE)
                
                **Model:** Mixtral 8x7B - Capable open-source model
                
                **Setup Steps:**
                1. Go to [huggingface.co/settings/tokens](https://huggingface.co/settings/tokens)
                2. Create a free account
                3. Generate an access token
                4. Add to your Streamlit secrets:
                
                ```toml
                HUGGINGFACE_API_KEY = "hf_your_token_here"
                ```
                
                **Note:** Model may need to load on first request (30-60 seconds)
                """)
            elif prov_id == "claude":
                st.markdown("""
                ### Claude (PAID - Most Capable)
                
                **Model:** Claude Sonnet 4 - Anthropic's latest model
                
                **Setup Steps:**
                1. Go to [console.anthropic.com](https://console.anthropic.com/)
                2. Create an account and add payment method
                3. Generate an API key
                4. Add to your Streamlit secrets:
                
                ```toml
                ANTHROPIC_API_KEY = "sk-ant-your_key_here"
                ```
                
                **Pricing:** ~$3/million input tokens, ~$15/million output tokens
                """)
            elif prov_id == "ollama":
                st.markdown("""
                ### Ollama (LOCAL - 100% Free & Private)
                
                **Model:** Various (Llama 3.2, Mistral, etc.)
                
                **Setup Steps:**
                1. Download from [ollama.ai](https://ollama.ai/download)
                2. Install and run Ollama
                3. Pull a model: `ollama pull llama3.2`
                4. Ollama will be auto-detected (no API key needed)
                
                **Benefits:** 
                - Completely free
                - Data stays on your machine
                - Works offline
                """)
    
    st.markdown("---")
    st.markdown("""
    ### 🔐 How to Add Secrets
    
    **For Streamlit Cloud:**
    1. Go to your app's Settings
    2. Navigate to the Secrets section
    3. Add your secrets in TOML format
    4. Save and reboot the app
    
    **For Local Development:**
    1. Create `.streamlit/secrets.toml` in your project root
    2. Add your API keys
    3. Restart the Streamlit app
    
    ```toml
    # Example .streamlit/secrets.toml
    GROQ_API_KEY = "gsk_your_key_here"
    # ANTHROPIC_API_KEY = "sk-ant-your_key_here"
    # HUGGINGFACE_API_KEY = "hf_your_token_here"
    ```
    """)

# Footer
st.markdown("---")
st.markdown("""
<div style="text-align: center; color: #888;">
    <p>🛡️ SIEM Log Source Onboarding Assistant v1.3</p>
    <p>Features: Integration Guides | CIM Mapper | Vendor Schema Learning | AI Chat</p>
    <p>Free AI Support: Groq (Llama 4) | HuggingFace (Mixtral) | Ollama (Local)</p>
</div>
""", unsafe_allow_html=True)
