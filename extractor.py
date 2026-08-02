import re

def extract_intelligence(raw_text):
    # 1. Define all of your regex patterns
    keyword_pattern = r'\b(breach|leak|ransomware)\b'
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
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

# 4. A quick test block to ensure your engine works
if __name__ == "__main__":
    dummy_text = """
    URGENT: The server at 192.168.1.5 was hit by ransomware today. 
    A major breach has occurred. Contact admin@cyber-shakti.org immediately. 
    Send the recovery funds to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa.
    """
    
    extracted_data = extract_intelligence(dummy_text)
    print(extracted_data)