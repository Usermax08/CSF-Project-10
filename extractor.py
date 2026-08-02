import re
import os
import json

def extract_intelligence(raw_text):
    # 1. Define all of your regex patterns (Now featuring the Pro IP Pattern & Watchlist!)
    keyword_pattern = r'\b(breach|leak|ransomware|cyber-shakti)\b'
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    wallet_pattern = r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'

    # 2. Run the patterns against the raw text to find matches
    found_keywords = re.findall(keyword_pattern, raw_text, re.IGNORECASE)
    found_ips = re.findall(ip_pattern, raw_text)
    found_emails = re.findall(email_pattern, raw_text)
    found_wallets = re.findall(wallet_pattern, raw_text)

    # 3. Structure the output into a dictionary
    results = {
        "keywords_flagged": list(set(found_keywords)), 
        "ip_addresses": list(set(found_ips)),
        "emails": list(set(found_emails)),
        "crypto_wallets": list(set(found_wallets))
    }
    
    return results

# 4. Read actual files and pretty-print the output
if __name__ == "__main__":
    # Define the path to the mock file
    file_path = "data/mock/leak1.txt"
    
    # Check if the file exists before trying to open it
    if os.path.exists(file_path):
        print(f"Opening file: {file_path}")
        
        # Open the file and read the text inside
        with open(file_path, 'r', encoding='utf-8') as file:
            raw_text = file.read()
            
        # Pass the real text into your extraction engine
        extracted_data = extract_intelligence(raw_text)
        
        print("\n--- EXTRACTION RESULTS ---")
        
        # This is the magic line that formats the output perfectly
        print(json.dumps(extracted_data, indent=4))
        
    else:
        print(f"Error: Could not find the file at {file_path}")