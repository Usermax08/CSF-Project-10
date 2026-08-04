import streamlit as st
import sqlite3
import pandas as pd

# Page Configuration
st.set_page_config(page_title="Threat Intelligence Platform", page_icon="🛡️", layout="wide")

def get_db_connection():
    conn = sqlite3.connect("cyber_intel.db")
    return conn

# Safely create table and auto-migrate missing columns if using an old database
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Ensure Base Table Exists
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS intel_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            raw_content TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # 2. Check Existing Columns for Auto-Migration
    cursor.execute("PRAGMA table_info(intel_reports)")
    existing_columns = [col[1] for col in cursor.fetchall()]
    
    # Add 'severity' column if missing
    if "severity" not in existing_columns:
        cursor.execute("ALTER TABLE intel_reports ADD COLUMN severity TEXT DEFAULT 'Medium ℹ️'")
        
    # Add 'threat_actor' column if missing
    if "threat_actor" not in existing_columns:
        cursor.execute("ALTER TABLE intel_reports ADD COLUMN threat_actor TEXT DEFAULT 'Unknown'")
        
    # Add 'mitigation' column if missing
    if "mitigation" not in existing_columns:
        cursor.execute("ALTER TABLE intel_reports ADD COLUMN mitigation TEXT DEFAULT 'Monitor network traffic'")
        
    # 3. Pre-load Expanded Threat Intelligence Feed if Table is Empty
    cursor.execute("SELECT COUNT(*) FROM intel_reports")
    count = cursor.fetchone()[0]
    
    if count == 0:
        default_threats = [
            (
                "New Ransomware Campaign Targeting Enterprise Infrastructure",
                "IPv4: 45.22.109.12\nIPv4: 192.168.1.5\nEmail: threat-actor@dark-web-ops.net\nDescription: A massive breach was detected. Threat actors are requesting Bitcoin payment for decryption keys.",
                "Critical 🚨",
                "DarkWeb Ops",
                "Isolate infected hosts (45.22.109.12), revoke compromised admin credentials, and block port 445 inbound."
            ),
            (
                "DDoS Botnet Sighting & Volume Spike",
                "IPv4: 203.0.113.45\nIPv4: 198.51.100.22\nDescription: High-volume SYN flood traffic anomaly detected targeting primary gateway servers.",
                "High ⚠️",
                "Botnet Operator",
                "Enable rate-limiting at edge routers and apply cloud-based DDoS mitigation rules."
            ),
            (
                "Phishing Campaign Targeting Corporate Credentials",
                "Email: fake-admin@corporate-support-portal.com\nEmail: hr-updates@malicious-domain.net\nDescription: Employees report receiving fake login portals attempting to steal corporate SSO credentials.",
                "High ⚠️",
                "Credential Harvester",
                "Block domains on email gateway, force password reset for targeted accounts, and run security awareness reminders."
            ),
            (
                "Malicious C2 Communication Detected",
                "IPv4: 185.199.108.153\nDomain: malicious-update-server.io\nDescription: Suspicious outbound beacons observed connecting to known command-and-control infrastructure during off-hours.",
                "Critical 🚨",
                "APT-29 (Cozy Bear)",
                "Block external IP/domain at perimeter firewall, pull memory dump of the originating workstation."
            ),
            (
                "SQL Injection Attempt on Public Web Application",
                "Payload: ' OR '1'='1' -- \nSource IP: 193.24.201.8\nDescription: Repeated automated scanning and injection attempts logged against login endpoints.",
                "Medium ℹ️",
                "Script Kiddie / Automated Scanner",
                "Review web application firewall (WAF) rules, ensure parameterized queries are enforced across all database inputs."
            ),
            (
                "Supply Chain Package Dependency Vulnerability",
                "Package: request-parser-v2.1 (NPM/PyPI)\nCVE: CVE-2026-8891\nDescription: A critical remote code execution vulnerability discovered in a widely used third-party logging package.",
                "High ⚠️",
                "Software Supply Chain",
                "Upgrade dependency package to version 2.2+ immediately and audit internal repositories for affected lockfiles."
            )
        ]
        
        cursor.executemany('''
            INSERT INTO intel_reports (title, raw_content, severity, threat_actor, mitigation)
            VALUES (?, ?, ?, ?, ?)
        ''', default_threats)
        
    conn.commit()
    conn.close()

# Execute Database Initialization
init_db()

# --- HEADER SECTION ---
st.title("🛡️ AI-Powered Threat Intelligence Platform")
st.markdown("Real-time telemetry and Threat Indicators of Compromise (IoCs).")

# --- SIDEBAR: SUBMIT INTEL FORM ---
st.sidebar.header("⚙️ Analyst Toolkit")

with st.sidebar.expander("➕ Submit New Threat Intel", expanded=False):
    with st.form("submit_intel_form"):
        threat_title = st.text_input("Threat Title", placeholder="e.g., Banking Trojan Sighting")
        severity = st.selectbox("Severity Level", ["Critical 🚨", "High ⚠️", "Medium ℹ️", "Low 🟢"])
        threat_actor = st.text_input("Threat Actor / Group", placeholder="e.g., APT28, Lazarus, Unknown")
        raw_content = st.text_area("Indicators & Raw Details", placeholder="Include IPs, domain emails, or CVE IDs...")
        mitigation_action = st.text_area("Recommended Mitigation", placeholder="e.g., Block IP at firewall level")
        
        submitted = st.form_submit_button("Submit to Database")
        
        if submitted:
            if threat_title and raw_content:
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO intel_reports (title, raw_content, severity, threat_actor, mitigation)
                    VALUES (?, ?, ?, ?, ?)
                ''', (threat_title, raw_content, severity, threat_actor if threat_actor else "Unknown", mitigation_action if mitigation_action else "Investigate IoCs"))
                conn.commit()
                conn.close()
                st.success("✅ Threat report logged successfully!")
                st.rerun()
            else:
                st.error("Please fill out the Title and Indicators fields.")

# --- MAIN DASHBOARD CONTENT ---
conn = get_db_connection()
reports_df = pd.read_sql_query("SELECT * FROM intel_reports ORDER BY id DESC", conn)

# Metrics Summary Bar
col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("Total Intel Reports", len(reports_df))
with col2:
    critical_count = len(reports_df[reports_df['severity'].str.contains("Critical", na=False)])
    st.metric("Critical Threats 🚨", critical_count)
with col3:
    st.metric("Active Feeds", "2 (Pulsedive / OTX)")
with col4:
    st.metric("System Status", "ONLINE", delta="100% Operational")

st.markdown("---")

# --- ACTIVE INTEL FEED ---
st.subheader("📋 Active Intelligence Feed & Risk Analysis")

if not reports_df.empty:
    for idx, row in reports_df.iterrows():
        sev = row['severity'] if pd.notnull(row['severity']) else "Medium ℹ️"
        actor = row['threat_actor'] if pd.notnull(row['threat_actor']) else "Unknown"
        mitig = row['mitigation'] if pd.notnull(row['mitigation']) else "Monitor network traffic"
        
        card_title = f"{sev} | {row['title']} (Actor: {actor})"
        
        with st.expander(card_title, expanded=False):
            c1, c2 = st.columns([2, 1])
            with c1:
                st.markdown("**📝 Threat Description & Raw Indicators:**")
                st.code(row['raw_content'], language="text")
            with c2:
                st.markdown("**🛡️ Recommended Mitigation:**")
                st.info(mitig)
                st.caption(f"Log Timestamp: {row['timestamp']}")
else:
    st.info("No threat intelligence records found.")

# Raw Data Table View
st.markdown("---")
st.subheader("🔍 Structured Database Records")
st.dataframe(reports_df, use_container_width=True)

conn.close()