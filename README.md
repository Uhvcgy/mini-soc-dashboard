# Mini-SOC Security Operations Dashboard

A lightweight Security Operations Center (SOC) tool built with Python, SQLite, and Streamlit to detect, log, and analyze SSH Brute-Force attacks in real time.

## Features
- **Log Parsing & Detection:** Analyzes Linux authentication logs (`auth.log`) using Regular Expressions to identify repeated failed SSH login attempts.
- **Alert Storage:** Automatically stores detected security incidents, timestamps, source IPs, and targeted usernames in a local SQLite database (`soc_alerts.db`).
- **Interactive SOC Dashboard:** Built with Streamlit to visualize key security metrics, incident tables, and automated mitigation recommendations.

## Project Structure
- `analyze_ssh.py`: Core log analysis engine and SQLite database logger.
- `dashboard.py`: Streamlit web interface for incident monitoring and reporting.
- `requirements.txt`: Required Python dependencies.

## How to Run
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Run the log analyzer to populate the database:
   ```bash
   python3 analyze_ssh.py
   ```
3. Launch the SOC dashboard:
   ```bash
   streamlit run dashboard.py
   ```
