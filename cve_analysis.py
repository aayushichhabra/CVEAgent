import os
import json
import requests
import streamlit as st
from typing import TypedDict
from langgraph.graph import StateGraph, END
import google.generativeai as genai
from bs4 import BeautifulSoup
import time
from dotenv import load_dotenv
import re

# Load environment variables from .env file
load_dotenv()
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '.env'))

# NIST NVD API Configuration
NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

class CVEAgentState(TypedDict):
    cve_id: str
    description: str
    summary: str
    cvss_score: str
    published_date: str
    references: list
    mitigation: list
    summary_mitigation: str
    structured_fix: list  # --- NEW FIELD ---

def get_api_keys():
    gemini_key = None
    nvd_key = None
    
    # Try Streamlit secrets first
    try:
        if hasattr(st, 'secrets') and st.secrets:
            gemini_key = st.secrets.get("GEMINI_API_KEY")
            nvd_key = st.secrets.get("NVD_API_KEY")
            if gemini_key:
                st.sidebar.success("🔧 Using Streamlit secrets for API keys")
    except Exception as e:
        st.sidebar.warning(f"Streamlit secrets not available: {e}")

    # Fallback to environment variables
    if not gemini_key:
        gemini_key = os.getenv("GEMINI_API_KEY")
        if gemini_key:
            st.sidebar.info("🔧 Using .env file for API keys")

    if not nvd_key:
        nvd_key = os.getenv("NVD_API_KEY")

    # Display status and setup instructions
    if gemini_key:
        st.sidebar.success("✅ Gemini API Key: Configured")
    else:
        st.sidebar.error("❌ Gemini API Key: Required for AI features")
        with st.sidebar.expander("🔧 How to set up API keys"):
            st.markdown("""
            **Option 1: Streamlit Secrets (Recommended)**
            
            Create `.streamlit/secrets.toml` file:
            ```toml
            GEMINI_API_KEY = "your_gemini_api_key_here"
            NVD_API_KEY = "your_nvd_api_key_here"  # optional
            ```
            
            **Option 2: Environment Variables**
            
            Create `.env` file:
            ```
            GEMINI_API_KEY=your_gemini_api_key_here
            NVD_API_KEY=your_nvd_api_key_here
            ```
            
            **Get API Keys:**
            - 🤖 [Google AI Studio](https://makersuite.google.com/app/apikey)
            - 🛡️ [NIST NVD](https://nvd.nist.gov/developers/request-an-api-key)
            """)
    
    if nvd_key:
        st.sidebar.success("✅ NVD API Key: Configured (faster CVE retrieval)")
    else:
        st.sidebar.info("ℹ️ NVD API Key: Not set (optional, but recommended)")
    
    return gemini_key, nvd_key

def test_gemini_api_key(api_key):
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel(model_name="models/gemini-1.5-flash")
        response = model.generate_content("Hello")
        return True, "API key is working correctly"
    except Exception as e:
        return False, str(e)

def initialize_gemini():
    gemini_key, _ = get_api_keys()
    if gemini_key:
        is_valid, message = test_gemini_api_key(gemini_key)
        if is_valid:
            st.sidebar.success("🎉 API Key Test: PASSED")
            genai.configure(api_key=gemini_key)
            return genai.GenerativeModel(model_name="models/gemini-1.5-flash")
        else:
            st.sidebar.error(f"🚫 API Key Test: FAILED")
            st.sidebar.error(f"Error: {message}")
            return None
    return None

def fetch_cve_from_api(cve_id):
    _, nvd_key = get_api_keys()
    headers = {
        'Accept': 'application/json',
        'User-Agent': 'CVE-Agent/1.0'
    }
    if nvd_key:
        headers["apiKey"] = nvd_key
    params = {"cveId": cve_id}
    try:
        with st.spinner(f"Fetching {cve_id} from NIST NVD API..."):
            response = requests.get(NVD_API_BASE_URL, params=params, headers=headers, timeout=30)
        if response.status_code == 200:
            data = response.json()
            if data.get("totalResults", 0) > 0:
                vulnerability = data["vulnerabilities"][0]["cve"]
                descriptions = vulnerability.get("descriptions", [])
                description = next((desc["value"] for desc in descriptions if desc["lang"] == "en"), "No description available")
                cvss_score = "N/A"
                metrics = vulnerability.get("metrics", {})
                if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                    cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                    cvss_score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
                elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                    cvss_score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
                published_date = vulnerability.get("published", "N/A")
                references = [ref["url"] for ref in vulnerability.get("references", [])]
                st.success(f"Successfully fetched {cve_id} from NVD API")
                return {
                    "cve_id": cve_id,
                    "description": description,
                    "summary": "",
                    "cvss_score": str(cvss_score),
                    "published_date": published_date,
                    "references": references,
                    "mitigation": [],
                    "summary_mitigation": "",
                    "structured_fix": []
                }
            else:
                st.error(f"CVE {cve_id} not found in NVD API")
        else:
            st.error(f"API request failed with status code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        st.error(f"Network error fetching CVE {cve_id}: {e}")
    return {
        "cve_id": cve_id,
        "description": f"Error fetching CVE {cve_id}",
        "summary": "",
        "cvss_score": "N/A",
        "published_date": "N/A",
        "references": [],
        "mitigation": [],
        "summary_mitigation": "",
        "structured_fix": []
    }

def fetch_cve(state):
    cve_id = state["cve_id"]
    time.sleep(1)
    return fetch_cve_from_api(cve_id)

def summarize_with_gemini(state):
    model = initialize_gemini()
    if not model:
        state["summary"] = "Gemini API key not configured - AI summary unavailable"
        return state
    description = state["description"]
    try:
        with st.spinner("Generating AI summary..."):
            response = model.generate_content([f"Summarize this CVE description:\n{description}"])
            state["summary"] = response.text
    except Exception as e:
        state["summary"] = f"Gemini Error: {e}"
    return state

def extract_mitigation_from_references(urls):
    mitigation_keywords = ["patch", "fix", "workaround", "update", "mitigation", "security advisory"]
    mitigation_data = []
    progress_bar = st.progress(0)
    for i, url in enumerate(urls[:5]):
        try:
            resp = requests.get(url, timeout=10)
            soup = BeautifulSoup(resp.text, "html.parser")
            text = soup.get_text(separator="\n")
            lines = text.split("\n")
            findings = [line.strip() for line in lines if any(k.lower() in line.lower() for k in mitigation_keywords)]
            if findings:
                mitigation_data.append({"url": url, "mitigation": findings[:10]})
        except Exception as e:
            mitigation_data.append({"url": url, "error": str(e)})
        progress_bar.progress((i + 1) / min(len(urls), 5))
    return mitigation_data

def add_mitigation_data(state):
    refs = state.get("references", [])
    if refs:
        with st.spinner("Analyzing references for mitigation information..."):
            state["mitigation"] = extract_mitigation_from_references(refs)
    else:
        state["mitigation"] = []
    return state

def summarize_mitigation(state):
    model = initialize_gemini()
    if not model:
        state["summary_mitigation"] = "Gemini API key not configured - AI mitigation summary unavailable"
        return state

    mitigation_texts = []
    for entry in state["mitigation"]:
        lines = entry.get("mitigation", [])
        if isinstance(lines, list):
            mitigation_texts.extend(lines)

    combined_text = "\n".join(mitigation_texts[:30])
    try:
        if combined_text.strip():
            with st.spinner("Generating mitigation summary..."):
                response = model.generate_content([f"Summarize these mitigation techniques:\n{combined_text}"])
                state["summary_mitigation"] = response.text
        else:
            state["summary_mitigation"] = "No mitigation techniques found to summarize."
    except Exception as e:
        state["summary_mitigation"] = f"Gemini Error: {e}"
    return state


def extract_structured_fix(state):
    structured_fixes = []
    patterns = [
        r"upgrade.*\bversion\b",
        r"update.*\bversion\b",
        r"install.*\bversion\b",
        r"apply.*patch",
        r"fixed in",
        r"patched in",
        r"available.*update",
        r"recommend.*update"
    ]
    for entry in state.get("mitigation", []):
        lines = entry.get("mitigation", [])
        for line in lines:
            for pat in patterns:
                if re.search(pat, line, flags=re.IGNORECASE):
                    structured_fixes.append(line.strip())
                    break
    state["structured_fix"] = structured_fixes
    return state

def suggest_structured_fix_with_gemini(state):
    if state["structured_fix"]:
        return state  # Already found fixes

    model = initialize_gemini()
    if not model:
        state["structured_fix"] = []
        return state

    mitigation_texts = []
    for entry in state.get("mitigation", []):
        lines = entry.get("mitigation", [])
        if isinstance(lines, list):
            mitigation_texts.extend(lines)

    combined_text = "\n".join(mitigation_texts[:50])
    if not combined_text.strip():
        state["structured_fix"] = []
        return state

    try:
        with st.spinner("Asking Gemini for structured fix recommendation..."):
            prompt = (
                "Given these mitigation details, suggest a single clear upgrade or patch "
                "instruction in one line. If no clear upgrade is possible, respond with 'NO FIX FOUND'.\n"
                + combined_text
            )
            response = model.generate_content([prompt])
            suggestion = response.text.strip()
            if suggestion and "NO FIX FOUND" not in suggestion.upper():
                state["structured_fix"] = [suggestion]
            else:
                state["structured_fix"] = []
    except Exception as e:
        state["structured_fix"] = []

    return state


# Create LangGraph workflow
graph_builder = StateGraph(CVEAgentState)
graph_builder.add_node("FetchCVE", fetch_cve)
graph_builder.add_node("Summarize", summarize_with_gemini)
graph_builder.add_node("ScrapeMitigation", add_mitigation_data)
graph_builder.add_node("SummarizeMitigation", summarize_mitigation)
graph_builder.add_node("ExtractStructuredFix", extract_structured_fix)  # NEW NODE

graph_builder.set_entry_point("FetchCVE")
graph_builder.add_edge("FetchCVE", "Summarize")
graph_builder.add_edge("Summarize", "ScrapeMitigation")
graph_builder.add_edge("ScrapeMitigation", "SummarizeMitigation")
graph_builder.add_edge("SummarizeMitigation", "ExtractStructuredFix")  # NEW EDGE
graph_builder.add_edge("ExtractStructuredFix", END)
graph_builder.add_node("SuggestStructuredFix", suggest_structured_fix_with_gemini)
graph_builder.add_edge("ExtractStructuredFix", "SuggestStructuredFix")
graph_builder.add_edge("SuggestStructuredFix", END)


graph = graph_builder.compile()
def get_cvss_color(score):
    try:
        score_val = float(score)
        if score_val >= 9.0:
            return "🔴"
        elif score_val >= 7.0:
            return "🟠"
        elif score_val >= 4.0:
            return "🟡"
        elif score_val > 0:
            return "🟢"
        else:
            return "⚪"
    except:
        return "⚪"

def main():
    st.title("🔒 CVE Agent - AI-Powered Vulnerability Analysis")
    st.markdown("Chat with the CVE Agent to analyze vulnerabilities using NIST NVD API 2.0 and Google Gemini AI")

    # Initialize chat history
    if "chat_messages" not in st.session_state:
        st.session_state.chat_messages = []
        # Add initial bot message
        st.session_state.chat_messages.append({
            "role": "assistant",
            "content": "👋 Hello! I'm your CVE Analysis Agent. What CVE would you like me to analyze?\n\n**Example CVEs:** `CVE-2023-40088`, `CVE-2021-44228`, `CVE-2023-23397`, `CVE-2022-30190`\n\nJust type a CVE ID and I'll provide a comprehensive security analysis!"
        })

    # Sidebar configuration
    with st.sidebar:
        st.header("⚙️ Configuration")
        gemini_key, nvd_key = get_api_keys()
        
        if st.button("🗑️ Clear Chat History"):
            st.session_state.chat_messages = []
            st.session_state.chat_messages.append({
                "role": "assistant", 
                "content": "👋 Hello! I'm your CVE Analysis Agent. What CVE would you like me to analyze?\n\n**Example CVEs:** `CVE-2023-40088`, `CVE-2021-44228`, `CVE-2023-23397`, `CVE-2022-30190`\n\nJust type a CVE ID and I'll provide a comprehensive security analysis!"
            })
            st.rerun()

    # Display chat history
    for message in st.session_state.chat_messages:
        with st.chat_message(message["role"]):
            if message["role"] == "assistant" and "analysis_data" in message:
                # Display formatted analysis results
                display_analysis_results(message["analysis_data"])
            else:
                st.markdown(message["content"])

    # Handle auto-analyze from dependency scanner
    auto_analyze_cve = None
    if 'selected_cve' in st.session_state:
        auto_analyze_cve = st.session_state['selected_cve']
        st.session_state.pop('selected_cve')

    # Chat input
    if auto_analyze_cve:
        user_input = auto_analyze_cve
    else:
        user_input = st.chat_input("Enter CVE ID (e.g., CVE-2023-40088)")

    if user_input:
        # Add user message to chat
        st.session_state.chat_messages.append({"role": "user", "content": user_input})
        
        with st.chat_message("user"):
            st.markdown(user_input)

        # Validate CVE format
        cve_id = user_input.strip().upper()
        if not cve_id.startswith('CVE-'):
            with st.chat_message("assistant"):
                st.error("❌ Please enter a valid CVE ID in the format: CVE-YYYY-NNNN")
            st.session_state.chat_messages.append({
                "role": "assistant",
                "content": "❌ Please enter a valid CVE ID in the format: CVE-YYYY-NNNN\n\n**Example:** `CVE-2023-40088`"
            })
            st.rerun()
            return

        # Check API key requirement
        if not gemini_key:
            with st.chat_message("assistant"):
                st.error("🚫 Gemini API key is required for AI analysis")
                st.info("Please add your Gemini API key to the .env file or Streamlit secrets")
            st.session_state.chat_messages.append({
                "role": "assistant",
                "content": "🚫 **Error:** Gemini API key is required for AI analysis.\n\nPlease add your Gemini API key to the .env file or Streamlit secrets to enable full functionality."
            })
            st.rerun()
            return

        # Show analysis in progress
        with st.chat_message("assistant"):
            with st.spinner(f"🔍 Analyzing {cve_id}..."):
                try:
                    # Run analysis graph
                    result = graph.invoke({
                        "cve_id": cve_id,
                        "description": "",
                        "summary": "",
                        "cvss_score": "",
                        "published_date": "",
                        "references": [],
                        "mitigation": [],
                        "summary_mitigation": "",
                        "structured_fix": []
                    })

                    # Check if CVE was found
                    if "Error fetching CVE" in result.get("description", ""):
                        st.error(f"❌ CVE {cve_id} not found in the NIST database")
                        st.session_state.chat_messages.append({
                            "role": "assistant",
                            "content": f"❌ **CVE {cve_id} not found** in the NIST database.\n\nPlease check the CVE ID and try again. Make sure it's in the correct format: CVE-YYYY-NNNN"
                        })
                    else:
                        # Display results
                        st.success(f"✅ Analysis complete for {cve_id}")
                        display_analysis_results(result)
                        
                        # Add to chat history with analysis data
                        st.session_state.chat_messages.append({
                            "role": "assistant",
                            "content": f"✅ **Analysis complete for {cve_id}**",
                            "analysis_data": result
                        })

                        # Add follow-up message
                        st.session_state.chat_messages.append({
                            "role": "assistant",
                            "content": "🔍 **Want to analyze another CVE?** Just enter another CVE ID below!\n\n**Quick examples:** `CVE-2021-44228` (Log4j), `CVE-2023-23397` (Outlook), `CVE-2022-30190` (Follina)"
                        })

                except Exception as e:
                    st.error(f"❌ An error occurred during analysis: {str(e)}")
                    st.session_state.chat_messages.append({
                        "role": "assistant",
                        "content": f"❌ **Error during analysis:** {str(e)}\n\nPlease try again or contact support if the issue persists."
                    })

        st.rerun()


def display_analysis_results(result):
    """Display formatted CVE analysis results in chat format"""
    
    # Header with key metrics
    col1, col2, col3 = st.columns(3)
    with col1:
        cvss_color = get_cvss_color(result['cvss_score'])
        st.metric("CVSS Score", f"{cvss_color} {result['cvss_score']}")
    with col2:
        st.metric("Published", result['published_date'][:10] if result['published_date'] != "N/A" else "N/A")
    with col3:
        st.metric("References", len(result['references']))

    # Expandable sections for detailed information
    with st.expander("📝 **CVE Description**", expanded=True):
        st.markdown(result['description'])

    if result['summary'] and not result['summary'].startswith("Gemini"):
        with st.expander("🤖 **AI Summary**", expanded=True):
            st.markdown(result['summary'])

    if result['summary_mitigation'] and result['summary_mitigation'] != "No mitigation techniques found to summarize." and not result['summary_mitigation'].startswith("Gemini"):
        with st.expander("🛡️ **Mitigation Summary**"):
            st.markdown(result['summary_mitigation'])

    # Structured fix recommendations
    if result.get("structured_fix"):
        st.subheader("🛠️ **Fix Recommendations**")
        for fix in sorted(set(result["structured_fix"])):
            st.success(f"✅ {fix}")
        
        # Show Apply Fix button if we have the original uploaded file and fix candidate
        if "original_file" in st.session_state and "fix_candidate" in st.session_state:
            if st.button("🛠️ Apply Fix and Download", key=f"apply_fix_{result['cve_id']}"):
                apply_automated_fix(result)
    else:
        st.warning("⚠️ No automated fix available. Please apply mitigation steps manually.")

    # References section
    if result['references']:
        with st.expander("🔗 **References**"):
            for i, ref in enumerate(result['references'][:10], 1):
                st.markdown(f"{i}. [{ref}]({ref})")

    # Detailed mitigation analysis
    if result['mitigation']:
        with st.expander("🔍 **Detailed Mitigation Analysis**"):
            for entry in result['mitigation']:
                if 'error' not in entry:
                    st.markdown(f"**Source:** {entry['url']}")
                    for finding in entry.get('mitigation', [])[:5]:
                        st.markdown(f"• {finding}")
                    st.markdown("---")


def apply_automated_fix(result):
    """Apply automated fix to the original dependency file"""
    original_file = st.session_state["original_file"]
    fix_candidate = st.session_state["fix_candidate"]
    updated_lines = []
    
    # Extract version from fix recommendation
    new_version = None
    for line in result["structured_fix"]:
        match = re.search(r"(\d+\.\d+\.\d+|\d+\.\d+)", line)
        if match:
            new_version = match.group(1)
            break
    
    if new_version:
        for line in original_file.splitlines():
            if fix_candidate["name"] in line and fix_candidate["version"] in line:
                # Replace with new version
                line = line.replace(fix_candidate["version"], new_version)
            updated_lines.append(line)
        
        fixed_file = "\n".join(updated_lines)
        st.success("✅ Fix applied! Download the updated file below:")
        st.download_button(
            label="⬇️ Download Fixed requirements.txt",
            data=fixed_file,
            file_name="fixed_requirements.txt",
            mime="text/plain",
            key=f"download_fix_{result['cve_id']}"
        )
    else:
        st.warning("⚠️ Could not extract a clear version number from the fix recommendation. Please update manually.")


if __name__ == "__main__":
    main()
