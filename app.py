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

# Display tab selector as buttons
col1, col2 = st.columns(2)
with col1:
    if st.button("🔍 CVE Analysis"):
        st.session_state.active_tab = "CVE Analysis"
with col2:
    if st.button("🛠️ Dependency Scanner"):
        st.session_state.active_tab = "Dependency Scanner"

# Show selected tab content
if st.session_state.active_tab == "CVE Analysis":
    cve_analysis.main()
elif st.session_state.active_tab == "Dependency Scanner":
    scanner.main()
