import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import time
import json
import io
from typing import List, Dict, Any

from core.tor_connector import TorConnector
from core.analysis_tool import TorAnalyzer
from core.deanonymizer import TorDeanonymizer
from core.export_utils import ExportUtils
from utils.validators import URLValidator
from utils.progress_tracker import ProgressTracker

# Page configuration
st.set_page_config(
    page_title="Tor Onion Site De-anonymizer",
    page_icon="🕵️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for enhanced UI/UX
st.markdown("""
<style>
    /* Main container styling */
    .main .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
        max-width: 1200px;
    }
    
    /* Header styling */
    .main-header {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 2rem;
        border-radius: 15px;
        margin-bottom: 2rem;
        text-align: center;
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
    }
    
    .main-header h1 {
        color: white;
        font-size: 2.5rem;
        font-weight: 700;
        margin-bottom: 0.5rem;
        text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.3);
    }
    
    .main-header p {
        color: rgba(255, 255, 255, 0.9);
        font-size: 1.2rem;
        margin: 0;
    }
    
    /* Sidebar styling */
    .css-1d391kg {
        background: linear-gradient(180deg, #1e2139 0%, #2a2d47 100%);
    }
    
    /* Status indicators */
    .status-connected {
        background: linear-gradient(90deg, #00d4aa, #00b894);
        color: white;
        padding: 0.5rem 1rem;
        border-radius: 20px;
        font-weight: 600;
        text-align: center;
        margin: 0.5rem 0;
    }
    
    .status-disconnected {
        background: linear-gradient(90deg, #e74c3c, #c0392b);
        color: white;
        padding: 0.5rem 1rem;
        border-radius: 20px;
        font-weight: 600;
        text-align: center;
        margin: 0.5rem 0;
    }
    
    /* Card styling for content sections */
    .content-card {
        background: rgba(255, 255, 255, 0.05);
        backdrop-filter: blur(10px);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 15px;
        padding: 1.5rem;
        margin-bottom: 1.5rem;
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
    }
    
    /* Progress bar styling */
    .stProgress > div > div > div {
        background: linear-gradient(90deg, #00d4aa, #667eea);
        border-radius: 10px;
    }
    
    /* Button styling */
    .stButton > button {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border: none;
        border-radius: 25px;
        padding: 0.75rem 2rem;
        font-weight: 600;
        transition: all 0.3s ease;
        box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
    }
    
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 20px rgba(102, 126, 234, 0.4);
    }
    
    /* Tab styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background: rgba(255, 255, 255, 0.05);
        border-radius: 15px;
        padding: 0.5rem;
    }
    
    .stTabs [data-baseweb="tab"] {
        border-radius: 10px;
        padding: 0.75rem 1.5rem;
        font-weight: 600;
        background: transparent;
        border: 1px solid rgba(255, 255, 255, 0.1);
    }
    
    .stTabs [aria-selected="true"] {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
    }
    
    /* Metric styling */
    .metric-container {
        background: rgba(255, 255, 255, 0.05);
        border-radius: 15px;
        padding: 1rem;
        text-align: center;
        border: 1px solid rgba(255, 255, 255, 0.1);
        backdrop-filter: blur(10px);
    }
    
    /* Input field styling */
    .stTextInput > div > div > input {
        border-radius: 10px;
        border: 2px solid rgba(255, 255, 255, 0.1);
        background: rgba(255, 255, 255, 0.05);
        backdrop-filter: blur(10px);
    }
    
    .stTextArea > div > div > textarea {
        border-radius: 10px;
        border: 2px solid rgba(255, 255, 255, 0.1);
        background: rgba(255, 255, 255, 0.05);
        backdrop-filter: blur(10px);
    }
    
    /* Success/Error message styling */
    .stAlert {
        border-radius: 10px;
        backdrop-filter: blur(10px);
    }
    
    /* File uploader styling */
    .stFileUploader {
        border-radius: 15px;
        border: 2px dashed rgba(255, 255, 255, 0.2);
        background: rgba(255, 255, 255, 0.02);
        padding: 2rem;
        text-align: center;
    }
    
    /* Dataframe styling */
    .stDataFrame {
        border-radius: 10px;
        overflow: hidden;
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
    }
    
    /* Sidebar section headers */
    .sidebar-section {
        background: rgba(0, 212, 170, 0.1);
        padding: 0.75rem;
        border-radius: 10px;
        margin: 1rem 0;
        border-left: 4px solid #00d4aa;
    }
    
    /* Loading animations */
    @keyframes pulse {
        0% { opacity: 0.6; }
        50% { opacity: 1; }
        100% { opacity: 0.6; }
    }
    
    .loading-text {
        animation: pulse 1.5s ease-in-out infinite;
    }
    
    /* Hover effects */
    .hover-card:hover {
        transform: translateY(-5px);
        transition: all 0.3s ease;
        box-shadow: 0 12px 25px rgba(0, 0, 0, 0.15);
    }
    
    /* Risk level indicators */
    .risk-low {
        background: linear-gradient(90deg, #00d4aa, #00b894);
        color: white;
        padding: 0.25rem 0.75rem;
        border-radius: 15px;
        font-size: 0.85rem;
        font-weight: 600;
    }
    
    .risk-medium {
        background: linear-gradient(90deg, #f39c12, #e67e22);
        color: white;
        padding: 0.25rem 0.75rem;
        border-radius: 15px;
        font-size: 0.85rem;
        font-weight: 600;
    }
    
    .risk-high {
        background: linear-gradient(90deg, #e74c3c, #c0392b);
        color: white;
        padding: 0.25rem 0.75rem;
        border-radius: 15px;
        font-size: 0.85rem;
        font-weight: 600;
    }
</style>
""", unsafe_allow_html=True)

def init_session_state():
    """Initialize session state variables"""
    if 'analysis_results' not in st.session_state:
        st.session_state.analysis_results = []
    if 'search_history' not in st.session_state:
        st.session_state.search_history = []
    if 'tor_connected' not in st.session_state:
        st.session_state.tor_connected = False

def load_sample_data():
    """Load sample URLs for demonstration"""
    try:
        with open('data/sample_urls.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {"sample_urls": []}

def main():
    init_session_state()
    
    # Enhanced Header
    st.markdown("""
    <div class="main-header">
        <h1>🕵️ Tor Onion Site De-anonymizer</h1>
        <p>Advanced OSINT Analysis Tool for Tor Network Entities</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Enhanced Sidebar
    with st.sidebar:
        st.markdown('<div class="sidebar-section"><h2>⚙️ Configuration</h2></div>', unsafe_allow_html=True)
        
        # Tor connection status with enhanced styling
        st.markdown('<div class="sidebar-section"><h3>🔌 Tor Connection</h3></div>', unsafe_allow_html=True)
        tor_connector = TorConnector()
        
        if st.button("🔍 Check Tor Connection", key="tor_check_btn"):
            with st.spinner("🔄 Checking Tor connection..."):
                status = tor_connector.check_connection()
                if status:
                    st.success("✅ Tor connection active")
                    st.session_state.tor_connected = True
                else:
                    st.error("❌ Tor connection failed")
                    st.session_state.tor_connected = False
        
        # Enhanced status display
        if st.session_state.tor_connected:
            st.markdown('<div class="status-connected">🟢 Tor Status: Connected</div>', unsafe_allow_html=True)
        else:
            st.markdown('<div class="status-disconnected">🔴 Tor Status: Disconnected</div>', unsafe_allow_html=True)
        
        st.markdown("---")
        
        # Enhanced Analysis options
        st.markdown('<div class="sidebar-section"><h3>🎯 Analysis Options</h3></div>', unsafe_allow_html=True)
        
        with st.container():
            deep_analysis = st.checkbox("🔬 Deep OSINT Analysis", value=True, help="Comprehensive analysis using multiple OSINT sources")
            metadata_extraction = st.checkbox("📋 Metadata Extraction", value=True, help="Extract technical details and fingerprints")
            cross_reference = st.checkbox("🔄 Cross-reference Databases", value=True, help="Check against threat intelligence databases")
        
        st.markdown("---")
        
        # Enhanced Search history
        st.markdown('<div class="sidebar-section"><h3>📚 Search History</h3></div>', unsafe_allow_html=True)
        
        if st.session_state.search_history:
            st.markdown("**Recent searches:**")
            for i, url in enumerate(reversed(st.session_state.search_history[-5:]), 1):
                truncated_url = url[:30] + "..." if len(url) > 30 else url
                st.markdown(f"🔸 `{truncated_url}`")
        else:
            st.info("💡 No search history yet")
        
        if st.button("🗑️ Clear History", key="clear_history_btn"):
            st.session_state.search_history = []
            st.rerun()

    # Enhanced Main content area with modern tabs
    tab1, tab2, tab3, tab4 = st.tabs(["🎯 Analysis", "📊 Results", "📥 Export", "📚 Help"])
    
    # Add some spacing
    st.markdown("<br>", unsafe_allow_html=True)
    
    with tab1:
        st.markdown('<div class="content-card">', unsafe_allow_html=True)
        st.markdown("### 🎯 URL Analysis")
        st.markdown("Enter onion URLs for comprehensive analysis and de-anonymization")
        
        # Enhanced Input methods with better styling
        st.markdown("#### 📝 Choose Input Method")
        input_method = st.radio(
            "Select how you want to provide URLs:",
            ["Single URL", "Multiple URLs", "File Upload"],
            horizontal=True
        )
        
        urls_to_analyze = []
        
        if input_method == "Single URL":
            st.markdown("##### 🔗 Single URL Input")
            url_input = st.text_input(
                "Enter Onion URL:",
                placeholder="http://example.onion",
                help="Enter a single .onion URL for analysis"
            )
            if url_input:
                urls_to_analyze = [url_input]
                
        elif input_method == "Multiple URLs":
            st.markdown("##### 📝 Multiple URLs Input")
            urls_text = st.text_area(
                "Enter URLs (one per line):",
                height=150,
                placeholder="http://example1.onion\nhttp://example2.onion\nhttp://example3.onion",
                help="Enter multiple .onion URLs, one per line"
            )
            if urls_text:
                urls_to_analyze = [url.strip() for url in urls_text.split('\n') if url.strip()]
                
        elif input_method == "File Upload":
            st.markdown("##### 📁 File Upload")
            uploaded_file = st.file_uploader(
                "Upload text file with URLs",
                type=['txt'],
                help="Upload a .txt file containing onion URLs (one per line)"
            )
            if uploaded_file:
                content = uploaded_file.read().decode('utf-8')
                urls_to_analyze = [url.strip() for url in content.split('\n') if url.strip()]
        
        # Enhanced Sample data section
        sample_data = load_sample_data()
        if sample_data.get("sample_urls"):
            st.markdown("---")
            st.markdown("##### 🧪 Sample Data")
            col1, col2 = st.columns([2, 1])
            
            with col1:
                st.info("💡 Use sample URLs to test the application functionality")
            
            with col2:
                if st.button("🚀 Load Sample URLs", key="load_samples"):
                    urls_to_analyze = sample_data["sample_urls"]
                    st.success(f"✅ Loaded {len(urls_to_analyze)} sample URLs")
        
        # Enhanced Validation and analysis section
        if urls_to_analyze:
            st.markdown("---")
            st.markdown("### 🔍 URL Validation & Analysis")
            
            # Validate URLs
            validator = URLValidator()
            valid_urls = []
            invalid_urls = []
            
            for url in urls_to_analyze:
                if validator.is_valid_onion_url(url):
                    valid_urls.append(url)
                else:
                    invalid_urls.append(url)
            
            # Enhanced validation results display
            col1, col2, col3 = st.columns([2, 2, 1])
            
            with col1:
                if valid_urls:
                    st.markdown('<div class="metric-container">', unsafe_allow_html=True)
                    st.metric("✅ Valid URLs", len(valid_urls))
                    st.markdown('</div>', unsafe_allow_html=True)
                    
                    with st.expander("📋 View Valid URLs", expanded=False):
                        for i, url in enumerate(valid_urls, 1):
                            st.markdown(f"**{i}.** `{url}`")
            
            with col2:
                if invalid_urls:
                    st.markdown('<div class="metric-container">', unsafe_allow_html=True)
                    st.metric("❌ Invalid URLs", len(invalid_urls))
                    st.markdown('</div>', unsafe_allow_html=True)
                    
                    with st.expander("⚠️ View Invalid URLs", expanded=False):
                        for i, url in enumerate(invalid_urls, 1):
                            st.markdown(f"**{i}.** `{url}`")
            
            with col3:
                # Enhanced Analysis button
                if valid_urls:
                    st.markdown("<br>", unsafe_allow_html=True)
                    if st.button("🚀 Start Analysis", type="primary", key="start_analysis_btn"):
                        if not st.session_state.tor_connected:
                            st.error("🔒 Please establish Tor connection first!")
                        else:
                            perform_analysis(valid_urls, deep_analysis, metadata_extraction, cross_reference)
        
        st.markdown('</div>', unsafe_allow_html=True)
    
    with tab2:
        st.markdown('<div class="content-card">', unsafe_allow_html=True)
        display_results()
        st.markdown('</div>', unsafe_allow_html=True)
    
    with tab3:
        st.markdown('<div class="content-card">', unsafe_allow_html=True)
        display_export_options()
        st.markdown('</div>', unsafe_allow_html=True)
    
    with tab4:
        st.markdown('<div class="content-card">', unsafe_allow_html=True)
        display_help()
        st.markdown('</div>', unsafe_allow_html=True)

def perform_analysis(urls: List[str], deep_analysis: bool, metadata_extraction: bool, cross_reference: bool):
    """Perform the actual analysis of URLs"""
    st.subheader("🔍 Analysis in Progress")
    
    # Initialize components
    analyzer = TorAnalyzer()
    deanonymizer = TorDeanonymizer()
    progress_tracker = ProgressTracker()
    
    # Progress tracking
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    results = []
    
    for i, url in enumerate(urls):
        # Update progress
        progress = (i + 1) / len(urls)
        progress_bar.progress(progress)
        status_text.text(f"Analyzing {i+1}/{len(urls)}: {url}")
        
        try:
            # Basic analysis
            basic_result = analyzer.analyze_url(url)
            
            # Deep analysis if enabled
            if deep_analysis:
                osint_result = deanonymizer.perform_osint_analysis(url, basic_result)
                basic_result.update(osint_result)
            
            # Metadata extraction
            if metadata_extraction:
                metadata = analyzer.extract_metadata(url)
                basic_result['metadata'] = metadata
            
            # Cross-reference databases
            if cross_reference:
                cross_ref_result = deanonymizer.cross_reference_databases(basic_result)
                basic_result['cross_references'] = cross_ref_result
            
            # Add timestamp and URL
            basic_result['url'] = url
            basic_result['timestamp'] = datetime.now().isoformat()
            basic_result['analysis_id'] = f"analysis_{int(time.time())}_{i}"
            
            results.append(basic_result)
            
            # Add to search history
            if url not in st.session_state.search_history:
                st.session_state.search_history.append(url)
            
        except Exception as e:
            st.error(f"Error analyzing {url}: {str(e)}")
            results.append({
                'url': url,
                'error': str(e),
                'timestamp': datetime.now().isoformat(),
                'analysis_id': f"error_{int(time.time())}_{i}"
            })
    
    # Store results
    st.session_state.analysis_results.extend(results)
    
    # Complete
    progress_bar.progress(1.0)
    status_text.text("✅ Analysis completed!")
    
    st.success(f"Successfully analyzed {len(results)} URLs. Check the Results tab.")
    time.sleep(2)
    st.rerun()

def display_results():
    """Display analysis results with enhanced styling"""
    st.markdown("### 📊 Analysis Results")
    st.markdown("View comprehensive analysis results and insights")
    
    if not st.session_state.analysis_results:
        st.markdown("""
        <div style="text-align: center; padding: 3rem; background: rgba(255, 255, 255, 0.05); border-radius: 15px; border: 2px dashed rgba(255, 255, 255, 0.2);">
            <h3>🔍 No Results Yet</h3>
            <p>Run an analysis to see comprehensive results here</p>
            <p style="opacity: 0.7;">Go to the Analysis tab to get started</p>
        </div>
        """, unsafe_allow_html=True)
        return
    
    # Enhanced Results overview with modern styling
    total_results = len(st.session_state.analysis_results)
    successful_results = len([r for r in st.session_state.analysis_results if 'error' not in r])
    error_results = total_results - successful_results
    
    st.markdown("#### 📈 Overview")
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown('<div class="metric-container">', unsafe_allow_html=True)
        st.metric("🎯 Total", total_results)
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col2:
        st.markdown('<div class="metric-container">', unsafe_allow_html=True)
        st.metric("✅ Success", successful_results)
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col3:
        st.markdown('<div class="metric-container">', unsafe_allow_html=True)
        st.metric("❌ Errors", error_results)
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col4:
        success_rate = (successful_results / total_results * 100) if total_results > 0 else 0
        st.markdown('<div class="metric-container">', unsafe_allow_html=True)
        st.metric("📊 Success Rate", f"{success_rate:.1f}%")
        st.markdown('</div>', unsafe_allow_html=True)
    
    # Enhanced Results visualization
    if successful_results > 0:
        st.markdown("---")
        st.markdown("#### 📊 Risk Assessment Overview")
        
        # Create enhanced risk assessment chart
        risk_levels = []
        for result in st.session_state.analysis_results:
            if 'error' not in result and 'risk_level' in result:
                risk_levels.append(result['risk_level'])
        
        if risk_levels:
            col1, col2 = st.columns([2, 1])
            
            with col1:
                risk_df = pd.DataFrame({'Risk Level': risk_levels})
                fig = px.histogram(
                    risk_df, 
                    x='Risk Level', 
                    title="Risk Level Distribution",
                    color_discrete_sequence=['#00d4aa', '#f39c12', '#e74c3c']
                )
                fig.update_layout(
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='rgba(0,0,0,0)',
                    font_color='white'
                )
                st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                st.markdown("##### 🏷️ Risk Categories")
                risk_counts = pd.Series(risk_levels).value_counts()
                for risk, count in risk_counts.items():
                    risk_class = f"risk-{risk.lower()}" if risk.lower() in ['low', 'medium', 'high'] else "risk-medium"
                    st.markdown(f'<span class="{risk_class}">{risk.title()}: {count}</span>', unsafe_allow_html=True)
                    st.markdown("<br>", unsafe_allow_html=True)
    
    # Enhanced Detailed results table
    st.markdown("---")
    st.markdown("#### 📋 Detailed Results")
    
    # Create enhanced results dataframe
    results_data = []
    for result in st.session_state.analysis_results:
        row = {
            'URL': result.get('url', 'Unknown'),
            'Timestamp': result.get('timestamp', 'Unknown'),
            'Status': '✅ Success' if 'error' not in result else '❌ Error',
            'Risk Level': result.get('risk_level', 'Unknown'),
            'Entities Found': len(result.get('entities', [])) if 'entities' in result else 0,
            'OSINT Sources': len(result.get('osint_sources', [])) if 'osint_sources' in result else 0,
            'Analysis Score': f"{result.get('analysis_score', 0)}%" if 'analysis_score' in result else 'N/A'
        }
        results_data.append(row)
    
    if results_data:
        results_df = pd.DataFrame(results_data)
        
        # Style the dataframe
        styled_df = results_df.style.apply(lambda x: ['background-color: rgba(0, 212, 170, 0.1)' if '✅' in str(x.Status) 
                                                     else 'background-color: rgba(231, 76, 60, 0.1)' for _ in x], axis=1)
        
        st.dataframe(styled_df, use_container_width=True)
        
        # Detailed view selector
        st.subheader("Detailed View")
        selected_analysis = st.selectbox(
            "Select analysis for detailed view:",
            options=range(len(st.session_state.analysis_results)),
            format_func=lambda x: f"{st.session_state.analysis_results[x]['url']} - {st.session_state.analysis_results[x].get('timestamp', 'Unknown')}"
        )
        
        if selected_analysis is not None:
            display_detailed_result(st.session_state.analysis_results[selected_analysis])

def display_detailed_result(result: Dict[str, Any]):
    """Display detailed result for a single analysis"""
    st.subheader(f"Detailed Analysis: {result['url']}")
    
    if 'error' in result:
        st.error(f"Analysis failed: {result['error']}")
        return
    
    # Basic information
    col1, col2 = st.columns(2)
    with col1:
        st.write("**Basic Information**")
        st.write(f"- URL: {result['url']}")
        st.write(f"- Analysis Time: {result.get('timestamp', 'Unknown')}")
        st.write(f"- Risk Level: {result.get('risk_level', 'Unknown')}")
        st.write(f"- Response Code: {result.get('response_code', 'Unknown')}")
    
    with col2:
        st.write("**Technical Details**")
        st.write(f"- Server: {result.get('server_info', 'Unknown')}")
        st.write(f"- Content Type: {result.get('content_type', 'Unknown')}")
        st.write(f"- Page Size: {result.get('page_size', 'Unknown')} bytes")
        st.write(f"- Load Time: {result.get('load_time', 'Unknown')}s")
    
    # Entities found
    if 'entities' in result and result['entities']:
        st.subheader("🎯 Entities Found")
        entities_df = pd.DataFrame(result['entities'])
        st.dataframe(entities_df, use_container_width=True)
    
    # OSINT sources
    if 'osint_sources' in result and result['osint_sources']:
        st.subheader("🔍 OSINT Sources")
        for source in result['osint_sources']:
            with st.expander(f"Source: {source.get('name', 'Unknown')}"):
                st.json(source)
    
    # Metadata
    if 'metadata' in result and result['metadata']:
        st.subheader("📋 Metadata")
        st.json(result['metadata'])

def display_export_options():
    """Display enhanced export options"""
    st.markdown("### 📥 Export Results")
    st.markdown("Download your analysis results in multiple formats")
    
    if not st.session_state.analysis_results:
        st.markdown("""
        <div style="text-align: center; padding: 3rem; background: rgba(255, 255, 255, 0.05); border-radius: 15px; border: 2px dashed rgba(255, 255, 255, 0.2);">
            <h3>📄 No Data to Export</h3>
            <p>Run an analysis to generate exportable results</p>
            <p style="opacity: 0.7;">Results will appear here after successful analysis</p>
        </div>
        """, unsafe_allow_html=True)
        return
    
    st.markdown("#### 💾 Available Export Formats")
    st.markdown("Choose your preferred format for downloading analysis results")
    
    export_utils = ExportUtils()
    
    # Enhanced export options with better styling
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown('<div class="content-card hover-card" style="text-align: center; padding: 2rem;">', unsafe_allow_html=True)
        st.markdown("#### 📊 CSV Export")
        st.markdown("Spreadsheet format for data analysis")
        
        if st.button("📊 Generate CSV", key="csv_export", use_container_width=True):
            csv_data = export_utils.to_csv(st.session_state.analysis_results)
            st.download_button(
                label="⬇️ Download CSV",
                data=csv_data,
                file_name=f"tor_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True
            )
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col2:
        st.markdown('<div class="content-card hover-card" style="text-align: center; padding: 2rem;">', unsafe_allow_html=True)
        st.markdown("#### 📄 JSON Export")
        st.markdown("Structured data for programming")
        
        if st.button("📄 Generate JSON", key="json_export", use_container_width=True):
            json_data = export_utils.to_json(st.session_state.analysis_results)
            st.download_button(
                label="⬇️ Download JSON",
                data=json_data,
                file_name=f"tor_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                use_container_width=True
            )
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col3:
        st.markdown('<div class="content-card hover-card" style="text-align: center; padding: 2rem;">', unsafe_allow_html=True)
        st.markdown("#### 📑 PDF Report")
        st.markdown("Professional report format")
        
        if st.button("📑 Generate PDF", key="pdf_export", use_container_width=True):
            pdf_data = export_utils.to_pdf(st.session_state.analysis_results)
            st.download_button(
                label="⬇️ Download PDF",
                data=pdf_data,
                file_name=f"tor_analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                mime="application/pdf",
                use_container_width=True
            )
        st.markdown('</div>', unsafe_allow_html=True)
    
    # Enhanced clear results option
    st.markdown("---")
    st.markdown("#### 🗑️ Data Management")
    
    col1, col2 = st.columns([3, 1])
    with col1:
        st.info("⚠️ This will permanently delete all analysis results and search history")
    
    with col2:
        if st.button("🗑️ Clear All Data", type="secondary", key="clear_all_data"):
            st.session_state.analysis_results = []
            st.session_state.search_history = []
            st.success("✅ All data cleared successfully!")
            st.rerun()

def display_help():
    """Display help and documentation"""
    st.header("📚 Help & Documentation")
    
    st.markdown("""
    ## Overview
    This application performs de-anonymization analysis of Tor onion sites using various OSINT techniques.
    
    ## How to Use
    
    ### 1. Setup Tor Connection
    - Ensure Tor is running on your system (usually on port 9050)
    - Click "Check Tor Connection" in the sidebar to verify connectivity
    
    ### 2. Input URLs
    - Enter single or multiple onion URLs
    - Upload a text file with URLs (one per line)
    - Use sample URLs for testing
    
    ### 3. Configure Analysis
    - **Deep OSINT Analysis**: Performs comprehensive analysis using multiple sources
    - **Metadata Extraction**: Extracts and analyzes page metadata
    - **Cross-reference Databases**: Checks against known databases and sources
    
    ### 4. Review Results
    - View summary statistics and risk assessments
    - Examine detailed results for each URL
    - Export results in CSV, JSON, or PDF format
    
    ## Analysis Components
    
    ### Risk Assessment
    - **Low**: Standard onion site with no suspicious indicators
    - **Medium**: Some indicators present, requires further investigation
    - **High**: Multiple red flags, likely compromised or monitored
    - **Critical**: Immediate security concerns identified
    
    ### OSINT Sources
    - Reverse WHOIS lookups
    - Shodan database queries
    - Certificate transparency logs
    - Domain reputation services
    - Social media cross-references
    
    ### Metadata Analysis
    - HTTP headers analysis
    - SSL/TLS certificate information
    - Server fingerprinting
    - Content analysis
    - Link structure mapping
    
    ## Privacy & Security
    - All analysis is performed through Tor proxy
    - No logs are stored permanently
    - Results are kept only in session memory
    - Use responsibly and in accordance with applicable laws
    
    ## Troubleshooting
    
    ### Tor Connection Issues
    - Ensure Tor is installed and running
    - Check that port 9050 is accessible
    - Verify proxy settings
    
    ### Analysis Failures
    - Check URL format (must be valid .onion address)
    - Ensure target site is accessible
    - Some sites may block automated access
    
    ## Disclaimer
    This tool is for educational and research purposes only. Users are responsible for ensuring their use complies with applicable laws and regulations.
    """)

if __name__ == "__main__":
    main()
