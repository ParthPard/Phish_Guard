<div align="center">
  <h1>🛡️ PhishGuard</h1>
  <p><b>Real-Time, ML-Powered Phishing URL Detection & SOC Dashboard</b></p>

  <img src="https://img.shields.io/badge/Python-3.10+-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/FastAPI-0.103.0-009688.svg" alt="FastAPI">
  <img src="https://img.shields.io/badge/React-18.2.0-61DAFB.svg" alt="React">
  <img src="https://img.shields.io/badge/XGBoost-Deployed-orange.svg" alt="XGBoost">
  <img src="https://img.shields.io/badge/Status-Active-success.svg" alt="Status">
</div>

---

## Overview
**PhishGuard** is a lightweight, asynchronous phishing detection system designed to mirror enterprise Security Operations Center (SOC) workflows. It addresses the vulnerability of traditional static blacklists by combining statistical machine learning classification with active Cyber Threat Intelligence (CTI) and WHOIS forensics to identify malicious, newly registered, and obfuscated domains in real-time.

Built by **Parth Pardeshi** @ Indian Institute of Technology (IIT) Guwahati.

## Key Features
- **Zero-Day Threat Detection:** Custom XGBoost model trained on PhishTank & Tranco Top 1M datasets to classify URLs based on lexical properties and structural anomalies.
- **Defense in Depth Architecture:** 4-layer heuristic engine overriding ML false positives with global threat consensus.
- **Active Threat Intelligence:** Live REST integration with the VirusTotal API (v3).
- **Domain Forensics:** Real-time WHOIS registry queries to calculate domain age and flag newly registered "burner" domains.
- **Live SOC Dashboard:** React/Tailwind interface featuring real-time scan histories, threat vector distribution, and IoC (Indicator of Compromise) CSV exports.

---

## System Architecture
PhishGuard operates on a decoupled microservices architecture to ensure sub-500ms browser response times:

1. **Client Sensor (Chrome Extension):** Intercepts active tab URLs and acts as the initial payload trigger.
2. **The Orchestrator (FastAPI Backend):** Manages simultaneous external API calls and ML feature extraction.
3. **Decision Engine:**
   - **Layer 1:** XGBoost ML Profiler (Domain length, digit frequency, raw IP routing, port anomalies).
   - **Layer 2:** VirusTotal CTI (Global vendor consensus).
   - **Layer 3:** WHOIS Forensics (Domain age verification).
   - **Layer 4:** Trust-weighted resolution logic.
4. **Analyst Command Center (React UI):** Real-time data visualization of the backend pipeline.

---

## Project Structure
```text
PhishGuard/
├── backend/
│   ├── main.py                 # FastAPI application & routing
│   ├── phishguard_model.pkl    # Serialized XGBoost classification model
│   └── requirements.txt        # Python dependencies
├── dashboard/                  # React.js & Vite frontend environment
│   ├── src/
│   │   ├── App.jsx             # Main SOC Dashboard UI and Logic
│   │   └── index.css           # Tailwind configuration
│   └── package.json
├── extension/                  # Chrome Extension assets
│   ├── manifest.json
│   ├── background.js
│   └── popup.html
├── .gitignore
└── README.md
