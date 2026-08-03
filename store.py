import sqlite3
import os
import json
from datetime import datetime
from extractor import extract_intelligence

conn = sqlite3.connect("cyber_intel.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS intel (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT,
    raw_text TEXT,
    extracted_entities TEXT,
    keyword_flag TEXT,
    timestamp TEXT
)
""")

# We now look at the main data folder to catch both mock and live data
data_folder = "data"

cursor.execute("DELETE FROM intel")

# Read every file in the folder
for filename in os.listdir(data_folder):
    filepath = os.path.join(data_folder, filename)
    
    # Check if it is a file (and ignore the 'mock' subfolder)
    if os.path.isfile(filepath):
        with open(filepath, "r", encoding="utf-8") as file:
            text = file.read()

        # Pass the file text into your extraction engine
        extracted_data = extract_intelligence(text)

        keyword_flag = ", ".join(extracted_data["keywords_flagged"])
        entities_json = json.dumps(extracted_data)

        cursor.execute("""
        INSERT INTO intel
        (source, raw_text, extracted_entities, keyword_flag, timestamp)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            filename,
            text,
            entities_json,
            keyword_flag,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))

conn.commit()
conn.close()

print("All live intelligence processed and saved to the database!")