import streamlit as st
import sqlite3
import pandas as pd

# Page Configuration
st.set_page_config(page_title="Mini-SOC Dashboard", layout="wide")

st.title("Mini-SOC Security Operations Dashboard")
st.markdown("Real-time monitoring and incident analysis for unauthorized **SSH** access attempts.")

# Load data from SQLite database
def load_data():
    conn = sqlite3.connect("soc_alerts.db")
    df = pd.read_sql_query("SELECT * FROM alerts ORDER BY id DESC", conn)
    conn.close()
    return df

try:
    df = load_data()

    if df.empty:
        st.success("Status: Secure. No anomalous activity detected in the database.")
    else:
        # Top KPI Metrics
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Security Alerts", len(df))
        col2.metric("Peak Failed Attempts", f"{df['attempt_count'].max()} Attempts")
        col3.metric("Top Threat Source IP", df.iloc[0]['ip_address'])

        st.divider()

        # Security Alerts Table
        st.subheader("Detected Security Incidents")
        st.dataframe(df, use_container_width=True)

        st.divider()

        # AI Analyst Section
        st.subheader("Automated Incident Analysis")
        selected_id = st.selectbox("Select Incident ID for investigation:", df['id'])
        
        if st.button("Generate Incident Report"):
            alert_row = df[df['id'] == selected_id].iloc[0]
            st.info(f"""
            **Incident Report - ID #{alert_row['id']}:**
            * **Threat Source:** IP Address `{alert_row['ip_address']}` executed `{alert_row['attempt_count']}` failed SSH authentication attempts.
            * **Attack Vector:** `{alert_row['attack_type']}` targeting accounts: (`{alert_row['targeted_users']}`).
            * **Recommended Mitigation:** Block the originating IP address at the firewall level:
              ```bash
              sudo ufw deny from {alert_row['ip_address']}
              ```
            """)

except Exception as e:
    st.error(f"Database Connection Error: {e}")
    
