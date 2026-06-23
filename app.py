import streamlit as st
import splunklib.client as client
from google import genai
from google.genai import types
import json
import subprocess
import re
import os
from datetime import datetime

# Set page configuration for an enterprise SOC theme
st.set_page_config(page_title="Alert Investigation Dashboard", page_icon="⚡", layout="wide")

# Custom CSS for professional styling
st.markdown("""
<style>
    * {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
    }
    .metric-card {
        background: #f8f9fa;
        padding: 16px;
        border-radius: 8px;
        border-left: 4px solid #2196F3;
        margin-bottom: 8px;
        min-height: 80px;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
    }
    .metric-label {
        font-size: 12px;
        font-weight: 600;
        color: #666;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-bottom: 8px;
    }
    .metric-value {
        font-size: 16px;
        font-weight: 700;
        color: #1a1a1a;
        word-wrap: break-word;
    }
    .alert-card {
        background: #fff3cd;
        border-left: 4px solid #ff9800;
        padding: 16px;
        border-radius: 8px;
        margin: 12px 0;
        color: #333;
        font-size: 14px;
    }
    .success-card {
        background: #d4edda;
        border-left: 4px solid #28a745;
        padding: 16px;
        border-radius: 8px;
        margin: 12px 0;
        color: #1a3a1a;
        font-size: 14px;
        font-weight: 500;
    }
    .error-card {
        background: #f8d7da;
        border-left: 4px solid #dc3545;
        padding: 16px;
        border-radius: 8px;
        margin: 12px 0;
        color: #721c24;
        font-size: 14px;
        font-weight: 500;
    }
    .success-card code, .error-card code, .alert-card code {
        background: rgba(0, 0, 0, 0.1);
        padding: 2px 6px;
        border-radius: 4px;
        font-family: 'Courier New', monospace;
        font-weight: 600;
        font-size: 13px;
    }
    .severity-critical {
        color: #dc3545;
        font-weight: 700;
        font-size: 18px;
    }
    .severity-high {
        color: #ff9800;
        font-weight: 700;
        font-size: 18px;
    }
    .severity-medium {
        color: #2196F3;
        font-weight: 700;
        font-size: 18px;
    }
    .log-timeline {
        font-family: 'Courier New', monospace;
        font-size: 12px;
        line-height: 1.8;
        background: #f8f9fa;
        padding: 12px;
        border-radius: 4px;
        border-left: 3px solid #666;
    }
    .section-header {
        font-size: 16px;
        font-weight: 600;
        color: #333;
        margin: 20px 0 12px 0;
    }
    .divider {
        border-top: 1px solid #e0e0e0;
        margin: 24px 0;
    }
</style>
""", unsafe_allow_html=True)

# Title
st.markdown("# Alert Investigation Dashboard")
st.markdown("*Automated security event enrichment and response*")
st.markdown('<div class="divider"></div>', unsafe_allow_html=True)

# ENV AND SECURITY INITIALIZATION
SPLUNK_PASSWORD = os.getenv("SPLUNK_PASSWORD", "YOUR_SPLUNK_PASSWORD") 
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

if not GEMINI_API_KEY:
    st.error("Configuration Error: GEMINI_API_KEY environment variable not found")
    st.stop()

# Initialize persistent session state
if "raw_log" not in st.session_state:
    st.session_state.raw_log = ""
    st.session_state.attacker_ip = None
    st.session_state.target_ip = None
    st.session_state.ai_report = ""
    st.session_state.severity_score = 0
    st.session_state.signature = ""
if "audit_log" not in st.session_state:
    st.session_state.audit_log = []

# ==================== BACKEND FUNCTIONS ====================

def get_local_fallback_report(signature, src, dest):
    """Fallback analysis using local signature rules."""
    fallback_score = 8 if "Brute Force" in signature else 5
    
    fallback_markdown = f"""
**System Status:** AI analysis service unavailable. Local signature matching applied.

**MITRE ATT&CK Classification**
- Tactic: Credential Access
- Technique: Brute Force: Password Guessing (T1110.001)
- Description: High-volume automated SSH authentication attempts from {src} to {dest}

**Recommended Response**
1. Implement firewall block on attacker IP
2. Audit successful logins on target system
3. Review outbound connections from target
4. Force password reset for affected accounts
"""
    return fallback_score, fallback_markdown

def query_siem_and_parse(password_input):
    """Query Splunk SIEM for latest security events."""
    service = client.connect(host="localhost", port=8089, username="admin", password=password_input)
    searchquery = 'search index=suricata sourcetype="suricata:eve" (alert.signature="SSH Brute Force Attempt Detected" OR alert.signature="SSH Banner - Possible Scan") | head 1'
    
    oneshotsearch_results = service.jobs.oneshot(searchquery, output_mode="json")
    search_results = json.loads(oneshotsearch_results.read())
    
    if not search_results.get("results"):
        return None, None, None, "Unknown Alert"

    raw_log = search_results["results"][0]["_raw"]
    
    attacker_ip, target_ip, signature = None, None, "SSH Brute Force"
    try:
        log_json = json.loads(raw_log)
        attacker_ip = log_json.get("src_ip")
        target_ip = log_json.get("dest_ip")
        signature = log_json.get("alert", {}).get("signature", "SSH Brute Force")
    except Exception:
        ip_matches = re.findall(r'\b(?:[0-8]?\d{1,2}|2[0-4]\d|25[0-5])\.(?:[0-8]?\d{1,2}|2[0-4]\d|25[0-5])\.(?:[0-8]?\d{1,2}|2[0-4]\d|25[0-5])\.(?:[0-8]?\d{1,2}|2[0-4]\d|25[0-5])\b', raw_log)
        if len(ip_matches) >= 2:
            attacker_ip = ip_matches[0]
            target_ip = ip_matches[1]

    return raw_log, attacker_ip, target_ip, signature

def run_ai_analysis(api_key, log_payload):
    """Run AI-powered threat analysis on security event."""
    ai_client = genai.Client(api_key=api_key, http_options=types.HttpOptions(api_version='v1beta'))
    
    prompt = f"""You are a security analyst. Analyze this alert and provide:
1. Severity score (1-10) in format [RISK_SCORE=X]
2. MITRE ATT&CK classification (tactic and technique)
3. Key indicators from this event
4. Specific recommended response actions

Keep response concise and technical. Format clearly with bullet points.

Alert Data:
{log_payload}"""
    
    response = ai_client.models.generate_content(model='gemini-2.5-flash', contents=prompt)
    full_text = response.text
    
    score_match = re.search(r'\[RISK_SCORE=(\d+)\]', full_text)
    if score_match:
        extracted_score = int(score_match.group(1))
        severity_score = max(1, min(extracted_score, 10))
        cleaned_report = full_text.replace(f"[RISK_SCORE={extracted_score}]", "").strip()
    else:
        severity_score = 8
        cleaned_report = full_text

    return severity_score, cleaned_report

def trigger_pipeline_run():
    """Main pipeline: fetch alert, enrich with AI, display results."""
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        raw_log, src, dest, signature = query_siem_and_parse(SPLUNK_PASSWORD)
        
        if not raw_log:
            st.error("No matching alerts found in SIEM")
            return
            
        st.session_state.raw_log = raw_log
        st.session_state.attacker_ip = src
        st.session_state.target_ip = dest
        st.session_state.signature = signature
        
        try:
            score, report = run_ai_analysis(GEMINI_API_KEY, raw_log)
            st.session_state.severity_score = score
            st.session_state.ai_report = report
            st.session_state.audit_log.insert(0, f"{timestamp} | Alert enriched | Severity: {score}/10")
        except Exception as ai_ex:
            # Fallback to local rules
            st.sidebar.warning("AI service unavailable - using local analysis")
            score, report = get_local_fallback_report(signature, src, dest)
            st.session_state.severity_score = score
            st.session_state.ai_report = report
            st.session_state.audit_log.insert(0, f"{timestamp} | Local analysis applied | Severity: {score}/10")

    except Exception as e:
        st.error(f"Error: {str(e)}")

# ==================== UI LAYOUT ====================

# Control bar
col_button, col_spacer = st.columns([1, 10])
with col_button:
    st.button("Fetch Alert", use_container_width=True, on_click=trigger_pipeline_run)

# Display alert details if available
if st.session_state.raw_log:
    # Key metrics
    m1, m2, m3, m4 = st.columns(4)
    
    with m1:
        st.markdown(
            '<div class="metric-card"><div class="metric-label">Alert Type</div><div class="metric-value">' + 
            getattr(st.session_state, 'signature', 'Unknown') + '</div></div>', 
            unsafe_allow_html=True
        )
    
    with m2:
        st.markdown(
            '<div class="metric-card"><div class="metric-label">Source IP</div><div class="metric-value">' + 
            str(st.session_state.attacker_ip) + '</div></div>', 
            unsafe_allow_html=True
        )
    
    with m3:
        st.markdown(
            '<div class="metric-card"><div class="metric-label">Target IP</div><div class="metric-value">' + 
            str(st.session_state.target_ip) + '</div></div>', 
            unsafe_allow_html=True
        )
    
    with m4:
        score = st.session_state.severity_score
        if score >= 8:
            severity_class = "severity-critical"
            severity_label = "CRITICAL"
        elif score >= 6:
            severity_class = "severity-high"
            severity_label = "HIGH"
        else:
            severity_class = "severity-medium"
            severity_label = "MEDIUM"
        
        st.markdown(
            f'<div class="metric-card"><div class="metric-label">Severity</div><div class="metric-value"><span class="{severity_class}">{score}/10 {severity_label}</span></div></div>',
            unsafe_allow_html=True
        )
    
    st.markdown('<div class="divider"></div>', unsafe_allow_html=True)
    
    # Main content layout
    col_left, col_right = st.columns([50, 50])
    
    # LEFT: Raw data and actions
    with col_left:
        st.markdown('<div class="section-header">Event Data</div>', unsafe_allow_html=True)
        with st.expander("View raw log (JSON)", expanded=False):
            st.code(st.session_state.raw_log, language="json")
        
        st.markdown('<div class="section-header" style="margin-top: 28px;">Response Actions</div>', unsafe_allow_html=True)
        
        if st.session_state.severity_score >= 8:
            st.markdown(
                '<div class="alert-card"><strong>High Severity Alert</strong><br>Immediate containment recommended</div>',
                unsafe_allow_html=True
            )
        
        if st.button("Block Source IP", type="primary", use_container_width=True):
            current_target = st.session_state.attacker_ip
            action_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            if current_target:
                rule_name = f"SOAR_Block_{current_target.replace('.', '_')}"
                cmd_args = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}", "dir=in", "action=block",
                    f"remoteip={current_target}", "enable=yes"
                ]
                result = subprocess.run(cmd_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                
                if result.returncode == 0:
                    st.markdown(
                        f'<div class="success-card"><strong>✓ Success</strong><br>Firewall rule created: <code>{rule_name}</code></div>',
                        unsafe_allow_html=True
                    )
                    st.session_state.audit_log.insert(0, f"{action_timestamp} | Firewall block applied: {current_target}")
                else:
                    st.markdown(
                        '<div class="error-card"><strong>✗ Failed</strong><br>Could not apply firewall rule. Check permissions.</div>',
                        unsafe_allow_html=True
                    )
                    st.session_state.audit_log.insert(0, f"{action_timestamp} | Firewall block failed: {current_target}")
    
    # RIGHT: Analysis report
    with col_right:
        st.markdown('<div class="section-header">Analysis Report</div>', unsafe_allow_html=True)
        st.markdown(st.session_state.ai_report)
    
    # Bottom: Audit log
    st.markdown('<div class="divider"></div>', unsafe_allow_html=True)
    st.markdown('<div class="section-header">Activity Timeline</div>', unsafe_allow_html=True)
    
    if st.session_state.audit_log:
        log_content = "\n".join(st.session_state.audit_log)
        st.markdown(f'<pre class="log-timeline">{log_content}</pre>', unsafe_allow_html=True)
    else:
        st.caption("No activity logged")
