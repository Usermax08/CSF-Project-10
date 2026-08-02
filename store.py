import sqlite3
import os
import json  # Added this so we can convert your dictionary to text for the database
from datetime import datetime

# 1. THE HANDSHAKE: Import your extraction engine!
from extractor import extract_intelligence

# Connect to SQLite database
conn = sqlite3.connect("cyber_intel.db")
cursor = conn.cursor()

# Create table if it doesn't exist
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

# Folder containing mock leak files
mock_folder = "data/mock"

cursor.execute("DELETE FROM intel")

# Read every .txt file
for filename in os.listdir(mock_folder):
    if filename.endswith(".txt"):
        filepath = os.path.join(mock_folder, filename)

        with open(filepath, "r", encoding="utf-8") as file:
            text = file.read()

        # 2. PASS THE BATON: Send the text through your engine!
        extracted_data = extract_intelligence(text)

        # 3. FORMAT FOR DATABASE: Databases need strings, not Python lists
        # We join your keywords with commas, and dump your dictionary to a JSON string
        keyword_flag = ", ".join(extracted_data["keywords_flagged"])
        entities_json = json.dumps(extracted_data)

        # Insert into database
        cursor.execute("""
        INSERT INTO intel
        (source, raw_text, extracted_entities, keyword_flag, timestamp)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            filename,
            text,
            entities_json,  # 4. We drop your extracted dictionary right here!
            keyword_flag,   # 5. We use your Pro-level keyword flags here!
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))

# Save everything
conn.commit()

# Close database
conn.close()

print("All files successfully processed by the Extractor and saved to the database!")