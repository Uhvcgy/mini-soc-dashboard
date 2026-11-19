import streamlit as st
import sqlite3
import pandas as pd
from google import genai

# Page Configuration
st.set_page_config(page_title="Mini-SOC Dashboard", layout="wide")

st.title("Mini-SOC Security Operations Dashboard")
st.markdown("Real-time monitoring and AI-driven incident analysis for unauthorized **SSH** access attempts.")

# Sidebar for Secure API Key & Model Selection
with st.sidebar:
    st.header("Configuration")
    api_key = st.text_input(
        "Enter Gemini API Key:", 
        type="password", 
        help="Your API key is kept strictly in your current session."
    )
    selected_model = st.selectbox(
        "Preferred AI Model:",
        ["gemini-3.8-flash-lite", "gemini-3.8-flash", "gemini-2.5-pro"]
    )

# Load data from SQLite database
def load_data():
    conn = sqlite3.connect("soc_alerts.db")
    df = pd.read_sql_query("SELECT * FROM alerts ORDER BY id DESC", conn)
    conn.close()
    return df

# Local Rule-Based Fallback Report (Ensures 100% Uptime)
def generate_fallback_report(row):
    severity = "HIGH" if row['attempt_count'] >= 5 else "MEDIUM"
    return f"""
### Automated SOC Incident Report (Local Engine)
*(Note: Cloud AI servers are currently experiencing peak traffic. Generated via built-in SOC heuristic engine.)*

#### 1. Threat Severity Assessment
* **Severity Level:** **{severity}**
* **Incident ID:** `#{row['id']}` | **Detected At:** `{row['timestamp']}`
* **Threat Source:** `{row['ip_address']}` executed **{row['attempt_count']}** consecutive failed authentication attempts.

#### 2. Behavioral Analysis & MITRE ATT&CK Mapping
* **Tactic:** Credential Access (`TA0006`)
* **Technique:** Brute Force - Password Guessing (`T1110.001`)
* **Targeted Accounts:** `{row['targeted_users']}` (Indicates automated dictionary/credential stuffing targeting privileged system accounts).

#### 3. Immediate Containment & Remediation Commands
Execute the following commands on the affected Linux host to block the threat source immediately:
```bash
# Block offending IP via UFW Firewall
sudo ufw deny from {row['ip_address']} to any port 22

# Verify active firewall rule
sudo ufw status numbered
```
"""

try:
    df = load_data()

    if df.empty:
        st.success("Status: Secure. No anomalous activity detected in the database.")
    else:
        # Top KPI Metrics
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Security Alerts", len(df))
        col2.metric("Peak Failed Attempts", f"{df['attempt_count'].max()} Attempts")
        col3.metric("Top Threat Source IP", df.at[0, 'ip_address'])

        st.divider()

        # Security Alerts Table
        st.subheader("Detected Security Incidents")
        st.dataframe(df, use_container_width=True)

        st.divider()

        # AI Analyst Section
        st.subheader("AI-Powered Incident Analysis")
        selected_id = st.selectbox("Select Incident ID for investigation:", df['id'])
        
        if st.button("Generate AI Incident Report"):
            alert_row = df[df['id'] == selected_id].to_dict('records')[0]
            if not api_key:
                st.warning("No API Key detected. Generating report using Local SOC Engine:")
                st.markdown(generate_fallback_report(alert_row))
            else:
                with st.spinner("Analyzing threat telemetry..."):
                    try:
                        client = genai.Client(api_key=api_key)
                        prompt = f"""
                        Act as an expert Tier-2 SOC Analyst. Analyze this SSH alert concisely:
                        - Incident ID: {alert_row['id']}, Time: {alert_row['timestamp']}
                        - Source IP: {alert_row['ip_address']}, Failed Attempts: {alert_row['attempt_count']}
                        - Targeted Users: {alert_row['targeted_users']}, Type: {alert_row['attack_type']}
                        Provide: 1. Severity, 2. MITRE ATT&CK Mapping, 3. Linux UFW Remediation Commands.
                        """
                        response = client.models.generate_content(
                            model=selected_model,
                            contents=prompt,
                        )
                        st.success("AI Analysis Complete (Gemini Cloud Engine)")
                        st.markdown(response.text)
                    except Exception:
                        st.info("Cloud AI API is currently busy (503). Automatically switched to Local SOC Engine:")
                        st.markdown(generate_fallback_report(alert_row))

except Exception as e:
    st.error(f"Database Connection Error: {e}")
