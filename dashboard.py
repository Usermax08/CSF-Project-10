import streamlit as st
import sqlite3
import pandas as pd

# Page Configuration
st.set_page_config(page_title="Cyber Shakti Threat Intel Platform", page_icon="🛡️", layout="wide")

def get_db_connection():
    conn = sqlite3.connect("cyber_intel.db")
    return conn

# Force schema setup & seed initial baseline data
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Enable schema migration by resetting table if columns are missing
    try:
        cursor.execute("SELECT severity FROM intel_reports LIMIT 1")
    except sqlite3.OperationalError:
        # Table exists with old schema -> drop and rebuild
        cursor.execute("DROP TABLE IF EXISTS intel_reports")
    
    # Create Table with full schema
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS intel_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            raw_content TEXT,
            severity TEXT DEFAULT 'Medium ℹ️',
            threat_actor TEXT DEFAULT 'Unknown',
            mitigation TEXT DEFAULT 'Monitor network traffic',
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Check if table is empty
    cursor.execute("SELECT COUNT(*) FROM intel_reports")
    count = cursor.fetchone()[0]
    
    # Pre-load initial baseline threat intelligence if empty
    if count == 0:
        default_threats = [
            (
                "New Ransomware Campaign Targeting cyber-shakti Infrastructure",
                "IPv4: 45.22.109.12\nIPv4: 192.168.1.5\nEmail: threat-actor@dark-web-ops.net\nEmail: admin@cyber-shakti.org\nDescription: A massive breach was detected. Threat actors are requesting Bitcoin.",
                "Critical 🚨",
                "DarkWeb Ops",
                "Isolate infected hosts (45.22.109.12), revoke compromised admin credentials, and block port 445 inbound."
            ),
            (
                "DDoS Botnet Sighting",
                "IPv4: 203.0.113.45\nIPv4: 198.51.100.22\nDescription: High volume traffic anomaly detected targeting cyber-shakti main servers.",
                "High ⚠️",
                "Botnet Operator",
                "Enable rate-limiting at edge routers and apply Cloudflare / AWS Shield DDoS mitigation rules."
            ),
            (
                "Phishing Campaign against Cyber Shakti Employees",
                "Email: fake-admin@cyber-shakti-support.com\nEmail: hr-updates@malicious-domain.net\nDescription: Users report receiving fake login portals attempting to steal credentials.",
                "High ⚠️",
                "Credential Harvester",
                "Block domains on email gateway, force password reset for targeted accounts, and run security awareness campaign."
            )
        ]
        
        cursor.executemany('''
            INSERT INTO intel_reports (title, raw_content, severity, threat_actor, mitigation)
            VALUES (?, ?, ?, ?, ?)
        ''', default_threats)
        
    conn.commit()
    conn.close()

# Run database setup & seeding
init_db()

# --- HEADER SECTION ---
st.title("🛡️ Cyber Shakti Threat Intelligence Dashboard")
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
        card_title = f"{row['severity']} | {row['title']} (Actor: {row['threat_actor']})"
        
        with st.expander(card_title, expanded=False):
            c1, c2 = st.columns([2, 1])
            with c1:
                st.markdown("**📝 Threat Description & Raw Indicators:**")
                st.code(row['raw_content'], language="text")
            with c2:
                st.markdown("**🛡️ Recommended Mitigation:**")
                st.info(row['mitigation'])
                st.caption(f"Log Timestamp: {row['timestamp']}")
else:
    st.info("No threat intelligence records found.")

# Raw Data Table View
st.markdown("---")
st.subheader("🔍 Structured Database Records")
st.dataframe(reports_df, use_container_width=True)

conn.close()