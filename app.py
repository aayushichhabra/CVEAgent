import streamlit as st
import cve_analysis
import scanner

st.set_page_config(
    page_title="CVE Agent - All in One",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ CVE Agent")

# Initialize state
if "active_tab" not in st.session_state:
    st.session_state.active_tab = "CVE Analysis"

# Display tab selector
col1, col2 = st.columns(2)
with col1:
    if st.button("🔍 CVE Analysis"):
        st.session_state.active_tab = "CVE Analysis"
with col2:
    if st.button("🛠️ Dependency Scanner"):
        st.session_state.active_tab = "Dependency Scanner"

# Route to the correct page
if st.session_state.active_tab == "CVE Analysis":
    st.query_params = {"tab": "cve"}
    cve_analysis.main()
elif st.session_state.active_tab == "Dependency Scanner":
    st.query_params = {"tab": "scanner"}
    scanner.main()
