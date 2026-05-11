import joblib
import pandas as pd
import re
import requests
import base64
from urllib.parse import urlparse
from datetime import datetime
from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import whois


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

model = joblib.load('phishguard_model.pkl')
VT_API_KEY = " "

class URLRequest(BaseModel):
    url: str

# Global memory to store our live scan history
scan_history = []

def extract_url_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc # Focus analysis on the domain
    
    has_ip = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain) else 0
    is_https = 1 if parsed.scheme == 'https' else 0
    
    try:
        has_suspicious_port = 1 if parsed.port not in [None, 80, 443] else 0
    except ValueError:
        has_suspicious_port = 1 
        
    domain_length = len(domain)
    
    # NEW FIX: Only count numbers and hyphens in the domain, ignore the path!
    num_digits = sum(c.isdigit() for c in domain)
    num_hyphens = domain.count('-')
    
    # Keep @ for the full URL because user:pass@domain is a classic trick
    num_at_symbols = url.count('@') 
    
    return pd.Series({
        'domain_length': domain_length,
        'is_https': is_https,
        'has_ip': has_ip,
        'has_suspicious_port': has_suspicious_port,
        'num_digits': num_digits,
        'num_hyphens': num_hyphens,
        'num_at_symbols': num_at_symbols
    })

def get_virustotal_verdict(url, api_key):
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {"accept": "application/json", "x-apikey": api_key}
    response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
    
    if response.status_code == 200:
        return response.json()['data']['attributes']['last_analysis_stats'].get('malicious', 0)
    elif response.status_code == 404:
        return -1
    else:
        return -1
    
def get_domain_age_in_days(url):
    try:
        domain = urlparse(url).netloc
        if domain.startswith("www."):
            domain = domain[4:]
            
        domain_info = whois.whois(domain)
        
        # Grab the updated_date instead of creation_date
        updated_date = domain_info.updated_date
        
        if not updated_date:
            return -1 
            
        # WHOIS often returns multiple update dates in a list, grab the first one
        if type(updated_date) is list:
            updated_date = updated_date[0]
            
        # --- THE FIX: Strip the timezone (make it 'naive') before subtracting ---
        if updated_date.tzinfo is not None:
            updated_date = updated_date.replace(tzinfo=None)
            
        # Calculate how many days ago it was updated
        age = (datetime.now() - updated_date).days
        return age
        
    except Exception as e:
        print(f"!!! WHOIS ERROR for {url}: {e} !!!")
        return -1
        

@app.post("/scan")
async def scan_url(request: URLRequest):
    # --- LAYER 1: Machine Learning ---
    features = extract_url_features(request.url)
    features_df = pd.DataFrame([features])
    ml_prediction = int(model.predict(features_df)[0])
    
    # --- LAYER 2 & 3: Threat Intelligence & Forensics ---
    vt_malicious_votes = get_virustotal_verdict(request.url, VT_API_KEY)
    domain_age_days = get_domain_age_in_days(request.url) # The new WHOIS check!
    
    # --- LAYER 4: The Master Decision Engine ---
    if vt_malicious_votes >= 3:
        # Known threat. Block it.
        is_malicious = True
        
    elif vt_malicious_votes == 0:
        # Known safe. Allow it.
        is_malicious = False
        
    else:
        # Zero-Day Unknown Threat. Now we check the Forensics!
        if 0 <= domain_age_days < 30:
            # It's a burner domain! Override ML and block it.
            is_malicious = True
        else:
            # It's an older domain, or WHOIS failed. Let the ML model make the final call.
            is_malicious = bool(ml_prediction)
            
    # Create the structured log report
    report = {
        "id": len(scan_history) + 1,
        "url": request.url,
        "ml_flagged": bool(ml_prediction),
        "vt_votes": vt_malicious_votes,
        "domain_age": domain_age_days, # Added to the report!
        "is_malicious": is_malicious,
        "threat_level": "High" if is_malicious else "Low",
        "time": datetime.now().strftime("%I:%M %p")
    }
    
    scan_history.insert(0, report)
    return report

@app.get("/history")
async def get_history():
    return scan_history