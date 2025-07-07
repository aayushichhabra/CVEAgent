# 🛡️ CVE Agent

AI-powered vulnerability analysis and dependency scanning tool built with Streamlit.

## 🚀 Live Demo

This app is deployed on Streamlit Cloud. Click the link in the repository description to access it.

## ✨ Features

- 🔍 **CVE Analysis Chatbot**: AI-powered vulnerability analysis using Google Gemini
- 📦 **Dependency Scanner Chatbot**: Scan requirement files for known vulnerabilities  
- 🤖 **Conversational Interface**: Chat-based interaction for both modules
- 🛠️ **Automated Fixes**: Smart fix recommendations and downloadable patches
- 🎯 **Multi-Format Support**: PyPI, Go, Alpine, and Debian dependencies

## 🔑 API Keys Setup (Streamlit Cloud)

The app requires API keys configured in Streamlit Cloud secrets:

1. **Deploy to Streamlit Cloud** from this repository
2. **Go to app settings** → **Secrets**
3. **Add the following secrets**:
   ```toml
   GEMINI_API_KEY = "your_gemini_api_key_here"
   NVD_API_KEY = "your_nvd_api_key_here"  # optional
   ```

### Getting API Keys

- **🤖 Gemini API**: Get from [Google AI Studio](https://makersuite.google.com/app/apikey) (Required)
- **🛡️ NVD API**: Get from [NIST NVD](https://nvd.nist.gov/developers/request-an-api-key) (Optional)

## 📖 Usage

### CVE Analysis
1. Click **"🔍 CVE Analysis"** tab
2. Enter CVE ID (e.g., `CVE-2023-40088`)
3. Get AI-powered analysis with:
   - CVSS risk scores
   - Vulnerability summaries
   - Mitigation recommendations
   - Automated fix suggestions

### Dependency Scanner
1. Click **"🛠️ Dependency Scanner"** tab
2. Upload your dependency file (`requirements.txt`, etc.)
3. View vulnerability scan results
4. Click **"Analyze in CVE Agent"** for detailed analysis

## 📦 Supported Dependency Formats

- **PyPI**: `package==1.0.0`
- **Go**: `github.com/user/repo==v1.0.0`
- **Alpine**: `Alpine:v3.19/package-name`
- **Debian**: `Debian:11/package-name`

## 🏗️ Local Development

1. **Clone the repository**:
   ```bash
   git clone <your-repo-url>
   cd <repo-name>
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up API keys**:
   Create `.streamlit/secrets.toml`:
   ```toml
   GEMINI_API_KEY = "your_gemini_api_key_here"
   NVD_API_KEY = "your_nvd_api_key_here"
   ```

4. **Run locally**:
   ```bash
   streamlit run cve_agent/app2.py
   ```

## 🛠️ Technical Stack

- **Frontend**: Streamlit
- **AI**: Google Gemini API
- **Data Sources**: NIST NVD API, OSV.dev
- **Workflow**: LangGraph
- **Web Scraping**: BeautifulSoup4
