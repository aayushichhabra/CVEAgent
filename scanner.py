import streamlit as st
import requests

def parse_mixed_requirements(file_content):
    packages = []
    for line in file_content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # PyPI format
        if "==" in line and not line.startswith("github.com/"):
            name, version = line.split("==", 1)
            packages.append({"ecosystem": "PyPI", "name": name.strip(), "version": version.strip()})

        # Go module (GitHub) format
        elif line.startswith("github.com/"):
            if "==" in line:
                name, version = line.split("==", 1)
            else:
                name, version = line, "latest"
            packages.append({"ecosystem": "Go", "name": name.strip(), "version": version.strip()})

        # OS-style format: Alpine:v3.19/py3-requests
        elif ":" in line and "/" in line:
            eco_ver, name = line.split("/", 1)
            ecosystem, version = eco_ver.split(":", 1)
            packages.append({"ecosystem": ecosystem.strip(), "name": name.strip(), "version": version.strip()})
    return packages

def check_vulnerabilities(packages):
    url = "https://api.osv.dev/v1/querybatch"
    query = {
        "queries": [
            {
                "package": {
                    "name": pkg["name"],
                    "ecosystem": pkg["ecosystem"]
                },
                "version": pkg["version"]
            }
            for pkg in packages
        ]
    }
    response = requests.post(url, json=query)
    return response.json()

def get_advisory_link(vuln_id):
    if vuln_id.startswith("CVE-"):
        return f"https://cve.org/CVERecord?id={vuln_id}"
    elif vuln_id.startswith("GHSA-"):
        return f"https://github.com/advisories/{vuln_id}"
    elif vuln_id.startswith("PYSEC-"):
        return f"https://osv.dev/vulnerability/{vuln_id}"
    else:
        return f"https://osv.dev/vulnerability/{vuln_id}"

def display_scan_results_chat(content, packages, result):
    """Display scan results in chat format"""
    
    # File contents in expandable section
    with st.expander("📄 **Uploaded File Contents**", expanded=False):
        st.code(content, language='text')

    results = result.get("results", [])
    if not results:
        st.success("✅ **Great news!** No vulnerabilities found in your dependencies.")
        return []

    found_cves = []
    vulnerabilities_found = False
    
    for idx, entry in enumerate(results):
        vulns = entry.get("vulns", [])
        pkg_info = packages[idx] if idx < len(packages) else {"name": "Unknown", "version": "?", "ecosystem": "?"}

        if vulns:
            vulnerabilities_found = True
            st.markdown(f"### 🚨 **{pkg_info['name']}=={pkg_info['version']}** _(Ecosystem: {pkg_info['ecosystem']})_")
            
            for vuln in vulns:
                vuln_id = vuln.get("id", "UNKNOWN")
                summary = vuln.get("summary") or vuln.get("details") or "_No description available._"

                link = get_advisory_link(vuln_id)
                st.markdown(f"**🔍 Vulnerability:** [{vuln_id}]({link})")
                st.markdown(f"**📋 Summary:** {summary}")

                if vuln_id.upper().startswith("CVE-"):
                    found_cves.append(vuln_id.upper())
                    col1, col2 = st.columns([1, 1])
                    with col1:
                        if st.button(f"🔍 Analyze {vuln_id} in CVE Agent", key=f"analyze_{pkg_info['name']}_{vuln_id}"):
                            st.session_state.selected_cve = vuln_id
                            st.session_state.active_tab = "CVE Analysis"
                            st.session_state.fix_candidate = {
                                "name": pkg_info["name"],
                                "version": pkg_info["version"],
                                "ecosystem": pkg_info["ecosystem"]
                            }
                            st.session_state.original_file = content
                            st.rerun()
                    with col2:
                        if st.button(f"🔗 View Advisory", key=f"advisory_{pkg_info['name']}_{vuln_id}"):
                            st.markdown(f"Opening: {link}")
                
                st.markdown("---")
        else:
            st.markdown(f"### ✅ **{pkg_info['name']}=={pkg_info['version']}** _(Safe)_")

    if not vulnerabilities_found:
        st.success("✅ **All dependencies are safe!** No known vulnerabilities detected.")
    
    return found_cves

def main():
    st.title("📦 Dependency Scanner Agent")
    st.markdown("Chat with the Scanner Agent to analyze your dependency files for vulnerabilities")

    # Initialize chat history
    if "scanner_chat_messages" not in st.session_state:
        st.session_state.scanner_chat_messages = []
        # Add initial bot message
        st.session_state.scanner_chat_messages.append({
            "role": "assistant",
            "content": "👋 Hello! I'm your Dependency Scanner Agent. Upload your dependency file and I'll scan it for known vulnerabilities!\n\n**Supported formats:**\n- 📦 **PyPI**: `package==1.0.0`\n- 🐹 **Go**: `github.com/user/repo==v1.0.0`\n- 🏔️ **Alpine**: `Alpine:v3.19/package-name`\n- 🐧 **Debian**: `Debian:11/package-name`\n\n**Ready to scan?** Just upload your `requirements.txt` or dependency file!"
        })

    # Sidebar configuration
    with st.sidebar:
        st.header("🔧 Scanner Settings")
        
        if st.button("🗑️ Clear Chat History"):
            st.session_state.scanner_chat_messages = []
            st.session_state.scanner_chat_messages.append({
                "role": "assistant", 
                "content": "👋 Hello! I'm your Dependency Scanner Agent. Upload your dependency file and I'll scan it for known vulnerabilities!\n\n**Supported formats:**\n- 📦 **PyPI**: `package==1.0.0`\n- 🐹 **Go**: `github.com/user/repo==v1.0.0`\n- 🏔️ **Alpine**: `Alpine:v3.19/package-name`\n- 🐧 **Debian**: `Debian:11/package-name`\n\n**Ready to scan?** Just upload your `requirements.txt` or dependency file!"
            })
            # Clear stored scan data
            if "dependency_file_content" in st.session_state:
                st.session_state.pop("dependency_file_content", None)
                st.session_state.pop("dependency_scan_results", None)
                st.session_state.pop("dependency_packages", None)
            st.rerun()

        # Show scan statistics if available
        if "dependency_scan_results" in st.session_state:
            results = st.session_state["dependency_scan_results"].get("results", [])
            total_packages = len(results)
            vulnerable_packages = sum(1 for r in results if r.get("vulns"))
            st.metric("📦 Total Packages", total_packages)
            st.metric("🚨 Vulnerable Packages", vulnerable_packages)
            if total_packages > 0:
                safety_score = ((total_packages - vulnerable_packages) / total_packages) * 100
                st.metric("🛡️ Safety Score", f"{safety_score:.1f}%")

    # Display chat history
    for message in st.session_state.scanner_chat_messages:
        with st.chat_message(message["role"]):
            if message["role"] == "assistant" and "scan_data" in message:
                # Display formatted scan results
                found_cves = display_scan_results_chat(
                    message["scan_data"]["content"],
                    message["scan_data"]["packages"], 
                    message["scan_data"]["results"]
                )
                if found_cves:
                    st.info(f"💡 **Tip:** Click the 'Analyze in CVE Agent' buttons above to get detailed vulnerability analysis and fix recommendations!")
            else:
                st.markdown(message["content"])

    # File upload section
    uploaded_file = st.file_uploader(
        "📁 Upload your dependency file", 
        type=["txt"],
        help="Upload requirements.txt or any dependency file with supported formats"
    )

    if uploaded_file:
        # Add user message about file upload
        filename = uploaded_file.name
        file_size = uploaded_file.size
        
        # Check if this is a new file
        if "last_uploaded_file" not in st.session_state or st.session_state.last_uploaded_file != filename:
            st.session_state.last_uploaded_file = filename
            st.session_state.scanner_chat_messages.append({
                "role": "user", 
                "content": f"📁 Uploaded: **{filename}** ({file_size} bytes)"
            })

            with st.chat_message("user"):
                st.markdown(f"📁 Uploaded: **{filename}** ({file_size} bytes)")

            # Process the file
            content = uploaded_file.read().decode("utf-8")
            packages = parse_mixed_requirements(content)

            with st.chat_message("assistant"):
                if not packages:
                    st.warning("⚠️ **No valid packages found** in the uploaded file.")
                    st.markdown("Please check that your file contains dependencies in supported formats:")
                    st.markdown("- `package==1.0.0` (PyPI)")
                    st.markdown("- `github.com/user/repo==v1.0.0` (Go)")
                    st.markdown("- `Alpine:v3.19/package-name` (Alpine)")
                    
                    st.session_state.scanner_chat_messages.append({
                        "role": "assistant",
                        "content": f"⚠️ **No valid packages found** in {filename}.\n\nPlease check that your file contains dependencies in supported formats:\n- `package==1.0.0` (PyPI)\n- `github.com/user/repo==v1.0.0` (Go)\n- `Alpine:v3.19/package-name` (Alpine)"
                    })
                    st.rerun()
                    return

                with st.spinner(f"🔎 Scanning {len(packages)} packages for vulnerabilities..."):
                    try:
                        result = check_vulnerabilities(packages)
                        
                        # Store scan results
                        st.session_state["dependency_file_content"] = content
                        st.session_state["dependency_scan_results"] = result
                        st.session_state["dependency_packages"] = packages

                        # Display results
                        found_cves = display_scan_results_chat(content, packages, result)
                        
                        # Count vulnerabilities
                        total_vulns = sum(len(entry.get("vulns", [])) for entry in result.get("results", []))
                        
                        if total_vulns == 0:
                            success_msg = f"✅ **Scan Complete!** All {len(packages)} packages are safe."
                            st.success(success_msg)
                            
                            st.session_state.scanner_chat_messages.append({
                                "role": "assistant",
                                "content": success_msg,
                                "scan_data": {"content": content, "packages": packages, "results": result}
                            })
                        else:
                            warning_msg = f"🚨 **Scan Complete!** Found {total_vulns} vulnerabilities across {len(packages)} packages."
                            st.warning(warning_msg)
                            
                            st.session_state.scanner_chat_messages.append({
                                "role": "assistant",
                                "content": warning_msg,
                                "scan_data": {"content": content, "packages": packages, "results": result}
                            })

                        # Add follow-up message
                        if found_cves:
                            followup_msg = "🔍 **Next Steps:** Use the 'Analyze in CVE Agent' buttons above for detailed vulnerability analysis and automated fixes!"
                        else:
                            followup_msg = "🔄 **Want to scan another file?** Just upload a new dependency file above!"
                        
                        st.session_state.scanner_chat_messages.append({
                            "role": "assistant",
                            "content": followup_msg
                        })

                    except Exception as e:
                        error_msg = f"❌ **Scan failed:** {str(e)}"
                        st.error(error_msg)
                        st.session_state.scanner_chat_messages.append({
                            "role": "assistant",
                            "content": f"{error_msg}\n\nPlease try again or check your internet connection."
                        })

            st.rerun()


if __name__ == "__main__":
    main()
