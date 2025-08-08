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
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

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
    
    # Header
    st.title("🔍 Tor Onion Site De-anonymizer")
    st.markdown("**Advanced OSINT Analysis Tool for Tor Network Entities**")
    
    # Sidebar
    with st.sidebar:
        st.header("⚙️ Configuration")
        
        # Tor connection status
        st.subheader("Tor Connection")
        tor_connector = TorConnector()
        
        if st.button("Check Tor Connection"):
            with st.spinner("Checking Tor connection..."):
                status = tor_connector.check_connection()
                if status:
                    st.success("✅ Tor connection active")
                    st.session_state.tor_connected = True
                else:
                    st.error("❌ Tor connection failed")
                    st.session_state.tor_connected = False
        
        # Display current status
        if st.session_state.tor_connected:
            st.success("Tor Status: Connected")
        else:
            st.warning("Tor Status: Disconnected")
        
        st.divider()
        
        # Analysis options
        st.subheader("Analysis Options")
        deep_analysis = st.checkbox("Deep OSINT Analysis", value=True)
        metadata_extraction = st.checkbox("Metadata Extraction", value=True)
        cross_reference = st.checkbox("Cross-reference Databases", value=True)
        
        st.divider()
        
        # Search history
        st.subheader("Search History")
        if st.session_state.search_history:
            for i, url in enumerate(reversed(st.session_state.search_history[-5:])):
                st.text(f"{i+1}. {url[:30]}...")
        else:
            st.text("No search history")
        
        if st.button("Clear History"):
            st.session_state.search_history = []
            st.rerun()

    # Main content area
    tab1, tab2, tab3, tab4 = st.tabs(["🎯 Analysis", "📊 Results", "📥 Export", "📚 Help"])
    
    with tab1:
        st.header("URL Analysis")
        
        # Input methods
        input_method = st.radio("Input Method:", ["Single URL", "Multiple URLs", "File Upload"])
        
        urls_to_analyze = []
        
        if input_method == "Single URL":
            url_input = st.text_input("Enter Onion URL:", placeholder="http://example.onion")
            if url_input:
                urls_to_analyze = [url_input]
                
        elif input_method == "Multiple URLs":
            urls_text = st.text_area("Enter URLs (one per line):", height=150)
            if urls_text:
                urls_to_analyze = [url.strip() for url in urls_text.split('\n') if url.strip()]
                
        elif input_method == "File Upload":
            uploaded_file = st.file_uploader("Upload text file with URLs", type=['txt'])
            if uploaded_file:
                content = uploaded_file.read().decode('utf-8')
                urls_to_analyze = [url.strip() for url in content.split('\n') if url.strip()]
        
        # Sample data
        sample_data = load_sample_data()
        if sample_data.get("sample_urls"):
            st.subheader("Sample URLs")
            if st.button("Load Sample URLs"):
                urls_to_analyze = sample_data["sample_urls"]
                st.success(f"Loaded {len(urls_to_analyze)} sample URLs")
        
        # Validation and analysis
        if urls_to_analyze:
            st.subheader("URLs to Analyze")
            
            # Validate URLs
            validator = URLValidator()
            valid_urls = []
            invalid_urls = []
            
            for url in urls_to_analyze:
                if validator.is_valid_onion_url(url):
                    valid_urls.append(url)
                else:
                    invalid_urls.append(url)
            
            # Display validation results
            col1, col2 = st.columns(2)
            with col1:
                st.success(f"✅ Valid URLs: {len(valid_urls)}")
                for url in valid_urls:
                    st.text(f"• {url}")
            
            with col2:
                if invalid_urls:
                    st.error(f"❌ Invalid URLs: {len(invalid_urls)}")
                    for url in invalid_urls:
                        st.text(f"• {url}")
            
            # Analysis button
            if valid_urls and st.button("🚀 Start Analysis", type="primary"):
                if not st.session_state.tor_connected:
                    st.error("Please establish Tor connection first!")
                else:
                    perform_analysis(valid_urls, deep_analysis, metadata_extraction, cross_reference)
    
    with tab2:
        display_results()
    
    with tab3:
        display_export_options()
    
    with tab4:
        display_help()

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
    """Display analysis results"""
    st.header("📊 Analysis Results")
    
    if not st.session_state.analysis_results:
        st.info("No analysis results available. Please run an analysis first.")
        return
    
    # Results overview
    total_results = len(st.session_state.analysis_results)
    successful_results = len([r for r in st.session_state.analysis_results if 'error' not in r])
    error_results = total_results - successful_results
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Analyses", total_results)
    with col2:
        st.metric("Successful", successful_results)
    with col3:
        st.metric("Errors", error_results)
    
    # Results visualization
    if successful_results > 0:
        st.subheader("Risk Assessment Overview")
        
        # Create risk assessment chart
        risk_levels = []
        for result in st.session_state.analysis_results:
            if 'error' not in result and 'risk_level' in result:
                risk_levels.append(result['risk_level'])
        
        if risk_levels:
            risk_df = pd.DataFrame({'Risk Level': risk_levels})
            fig = px.histogram(risk_df, x='Risk Level', title="Risk Level Distribution")
            st.plotly_chart(fig, use_container_width=True)
    
    # Detailed results table
    st.subheader("Detailed Results")
    
    # Create results dataframe
    results_data = []
    for result in st.session_state.analysis_results:
        row = {
            'URL': result.get('url', 'Unknown'),
            'Timestamp': result.get('timestamp', 'Unknown'),
            'Status': 'Error' if 'error' in result else 'Success',
            'Risk Level': result.get('risk_level', 'Unknown'),
            'Entities Found': len(result.get('entities', [])) if 'entities' in result else 0,
            'OSINT Sources': len(result.get('osint_sources', [])) if 'osint_sources' in result else 0
        }
        results_data.append(row)
    
    if results_data:
        results_df = pd.DataFrame(results_data)
        st.dataframe(results_df, use_container_width=True)
        
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
    """Display export options"""
    st.header("📥 Export Results")
    
    if not st.session_state.analysis_results:
        st.info("No results to export. Please run an analysis first.")
        return
    
    st.write("Export your analysis results in various formats:")
    
    export_utils = ExportUtils()
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.subheader("CSV Export")
        if st.button("📊 Export as CSV"):
            csv_data = export_utils.to_csv(st.session_state.analysis_results)
            st.download_button(
                label="Download CSV",
                data=csv_data,
                file_name=f"tor_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
    
    with col2:
        st.subheader("JSON Export")
        if st.button("📄 Export as JSON"):
            json_data = export_utils.to_json(st.session_state.analysis_results)
            st.download_button(
                label="Download JSON",
                data=json_data,
                file_name=f"tor_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )
    
    with col3:
        st.subheader("PDF Report")
        if st.button("📑 Generate PDF Report"):
            pdf_data = export_utils.to_pdf(st.session_state.analysis_results)
            st.download_button(
                label="Download PDF",
                data=pdf_data,
                file_name=f"tor_analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                mime="application/pdf"
            )
    
    # Clear results option
    st.divider()
    st.subheader("🗑️ Clear Results")
    if st.button("Clear All Results", type="secondary"):
        st.session_state.analysis_results = []
        st.session_state.search_history = []
        st.success("All results cleared!")
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
