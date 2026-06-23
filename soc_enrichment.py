import splunklib.client as client
from google import genai
from google.genai import types
import json

print("=" * 60)
print("🚀 STARTING AI-ENHANCED SOC ENRICHMENT PIPELINE")
print("=" * 60)

# 1. CONNECT TO WINDOWS SPLUNK INSTANCE
print("[*] Connecting to Splunk API on localhost:8089...")
try:
    service = client.connect(
        host="localhost",
        port=8089,
        username="admin",
        password="YOUR_SPLUNK_PASSWORD"  # <--- Change this to your Splunk password
    )
    print("[+] Successfully authenticated with Splunk.")
except Exception as e:
    print(f"[-] Splunk Connection Failed: {e}")
    exit()

# 2. QUERY SPLUNK FOR THE HYDRA ATTACK LOG
searchquery = 'search index=suricata sourcetype="suricata:eve" "alert.signature"="SSH Banner - Possible Scan" | head 1'
print(f"[*] Executing SIEM Query: {searchquery}")

oneshotsearch_results = service.jobs.oneshot(searchquery, output_mode="json")

# Parse the result
search_results = json.loads(oneshotsearch_results.read())

if not search_results.get("results"):
    print("[-] No matching Suricata logs found in Splunk. Did you run the Hydra attack?")
    exit()

# Extract the raw JSON log string that came from Ubuntu
raw_log = search_results["results"][0]["_raw"]
print("[+] Raw log payload successfully retrieved from SIEM.")

# -------------------------------------------------------------
# NEW STEP 2: PARSE ATTACKER IP ADDRESS FROM THE LOG
# -------------------------------------------------------------
try:
    log_json = json.loads(raw_log)
    attacker_ip = log_json.get("src_ip")
    target_ip = log_json.get("dest_ip")
    print(f"[+] Targeted Automation Extraction:")
    print(f"    - Malicious Attacker IP: {attacker_ip}")
    print(f"    - Internal Victim IP: {target_ip}")
except Exception as e:
    print(f"[-] Failed to parse IP metrics from raw log: {e}")
    attacker_ip = None
# -------------------------------------------------------------

# 3. INITIALIZE THE AI LAYER
print("[*] Contacting LLM Brain Layer...")

client = genai.Client(
    api_key="AIzaSyAFYvd58B3ju_VCfqpekuf6xcUA5ALWiAo",
    http_options=types.HttpOptions(api_version='v1beta')
)

# Construct the precise system prompt ensuring a structured markdown output
prompt = f"""
You are an advanced automated Tier-3 Incident Response AI. Analyze this raw Suricata IDS security log extracted from our Splunk SIEM.
Generate a structured incident triage report in clean Markdown formatting.

You MUST include these exact headers:
### 🚨 AUTOMATED SEVERITY ANALYSIS
(Provide a brief explanation of the threat and assign an aggressive risk score from 1-10)

### 🎯 MITRE ATT&CK SEGMENTATION
(Identify the exact Tactic and Technique IDs relevant to this attack pattern)

### 📋 INCIDENT RESPONSE RECOMMENDED PLAYBOOK
(Provide a 3-bullet step-by-step containment strategy for the human analyst to review)

Raw Security Event Telemetry:
{raw_log}
"""

# 4. DISPATCH AND PRINT GENERATED INTEL REPORT
print("[*] Processing analytics and generating mitigation roadmap...\n")
try:
    response = client.models.generate_content(
        model='gemini-2.5-flash',
        contents=prompt,
    )
    print("=" * 60)
    print(response.text)
    print("=" * 60)
    
    # STEP 1: SAVE TO FILE
    report_filename = "incident_report.md"
    with open(report_filename, "w", encoding="utf-8") as file:
        file.write(response.text)
    print(f"\n[+] Success! Report saved automatically to: {report_filename}")

except Exception as e:
    print(f"[-] LLM Analysis Failed: {e}")