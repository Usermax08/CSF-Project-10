import streamlit as st
import sqlite3
import pandas as pd

# 1. PAGE CONFIGURATION
st.set_page_config(page_title="Threat Intel Dashboard", page_icon="🛡️", layout="wide")

# 2. DASHBOARD HEADER
st.title("🛡️ Cyber Shakti - Threat Intelligence Platform")
st.markdown("Live feed of extracted threat intelligence and compromised assets.")

# 3. CONNECT TO THE VAULT
def load_data():
    conn = sqlite3.connect("cyber_intel.db")
    query = "SELECT source, raw_text, extracted_entities, keyword_flag, timestamp FROM intel"
    df = pd.read_sql_query(query, conn)
    conn.close()
    return df

df = load_data()

# 4. TOP METRICS
st.subheader("System Overview")
col1, col2, col3 = st.columns(3)

total_reports = len(df)
critical_alerts = df['keyword_flag'].str.contains('ransomware|cyber-shakti|breach', case=False, na=False).sum()

col1.metric("Total Intel Reports", total_reports)
col2.metric("Critical Watchlist Alerts", int(critical_alerts))
col3.metric("System Status", "Operational", delta="Online", delta_color="normal")

st.divider()

# 5. THE MAIN FEED
st.subheader("Extracted Intelligence Feed")

st.dataframe(
    df,
    column_config={
        "source": "Source",
        "raw_text": "Raw Text Intercept",
        "extracted_entities": "Extracted Indicators",
        "keyword_flag": "Watchlist Flags",
        "timestamp": "Time Logged"
    },
    use_container_width=True,
    hide_index=True
)