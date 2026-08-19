<div align="center">

# 🛡️ PhishTriage Engine
### Automated SOC Artifact & Quishing Triage Pipeline

[![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)]([https://www.python.org/](https://www.python.org/))
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![SOC-Automation](https://img.shields.io/badge/SOC-Tier--1%20Automation-red?style=for-the-badge)](https://github.com/kali878/phish-triage-engine)
[![Threat-Intel](https://img.shields.io/badge/Threat%20Intel-VirusTotal%20%7C%20AbuseIPDB-orange?style=for-the-badge)](https://www.virustotal.com/)

<p align="center">
  <b>A production-grade Tier-1 SOC automation tool designed to extract deep email forensics, detect hidden Quishing (QR code) payloads via Computer Vision, defang dangerous IOCs, enrich artifacts with live Threat Intelligence, and generate actionable incident triage reports.</b>
</p>

</div>

---

## 📌 Executive Summary

Tier-1 SOC analysts routinely spend **10–15 minutes per phishing ticket** manually decoding email headers, verifying SPF/DKIM/DMARC records, checking attachment hashes, and analyzing risky QR codes. This leads to **alert fatigue** and significantly inflates **Mean Time to Respond (MTTR)**.

**PhishTriage Engine** solves this operational bottleneck by automating the entire triage lifecycle:
* ⚡ **Zero-Execution Analysis:** Decodes Quishing lures directly from raw byte streams using computer vision without sandbox overhead.
* ⚡ **Multi-Format Ingestion:** Seamlessly parses raw `.eml`, `.pdf`, and `.txt` logs.
* ⚡ **Dynamic 0–100 Risk Engine:** Computes threat scores across email authentication, threat intel feeds, and malicious heuristics in under **10 seconds**.

---

## 🚀 Key Features

| Feature | Description |
|---|---|
| **📷 Quishing Extraction** | Leverages Computer Vision (`pyzbar` + `Pillow`) to decode hidden QR codes inside image attachments (`.png`, `.jpg`) and PDF graphics. |
| **📄 Multi-Format Ingestion** | Natively handles `.eml`, `.msg`, multi-page `.pdf` documents, and unstructured `.txt`/`.log` files. |
| **✉️ Authentication Auditing** | Automatically validates `SPF`, `DKIM`, and `DMARC` records from `Authentication-Results` to catch spoofing attempts. |
| **🌐 Originating IP Tracing** | Recursively traverses SMTP `Received:` headers to pinpoint the real external gateway IP while discarding RFC-1918 subnets. |
| **🔍 Live Threat Intel** | Integrates with **AbuseIPDB v2** (IP reputation) and **VirusTotal v3** (URLs, QR payloads, and SHA-256 file hashes). |
| **🛡️ Automated IOC Defanging** | Automatically sanitizes malicious indicators (`hxxps://`, `[.]`) across all terminal feeds and export reports. |
| **📋 Actionable SOC Reports** | Generates detailed Markdown investigation reports with recommended containment steps (Mailbox purge, firewall blocks). |

---

## 🧰 Tech Stack

| Domain | Tools & Libraries |
|---|---|
| **Language** | Python 3.9+ |
| **Computer Vision** | `pyzbar`, `Pillow` (PIL) |
| **Parsing & Forensics** | `BeautifulSoup4`, `dnspython`, `pypdf` |
| **Threat Intelligence** | VirusTotal REST API v3, AbuseIPDB REST API v2 |
| **Automation & CLI** | `argparse`, `requests`, `qrcode` |

---

## 📂 Directory Structure

```text
phish-triage-engine/
├── core/
│   ├── __init__.py           # Package marker
│   ├── email_parser.py       # Header analysis, SPF/DKIM verification & defanging
│   ├── generic_parser.py     # PDF & unstructured log file extraction
│   ├── intel_enricher.py     # Threat intel API wrappers (VT & AbuseIPDB)
│   ├── quishing_parser.py    # Computer-vision QR code extractor
│   └── risk_scorer.py        # Scoring logic & SOC report builder
├── output/                   # Generated investigation reports (.md)
├── samples/                  # Mock/Sample test cases
├── .gitignore                # Git exclusions
├── config.example.py         # Config template for API keys
├── config.py                 # Active credentials (Ignored by git)
├── generate_test_sample.py   # Quishing attack generator for testing
├── main.py                   # Main CLI Entry Point
├── README.md                 # Project Documentation
└── requirements.txt          # Python Dependencies
```

---

## ⚙️ Getting Started

1. Create and activate a virtual environment.
2. Install dependencies: `pip install -r requirements.txt`
3. Rename `config.example.py` to `config.py` and add your API keys.
4. Run `python main.py samples/test_quishing.eml`
5. Review the generated report in the `output/` folder.

---

## 🔐 Configuration

Add your API credentials in `config.py`:

```python
ABUSEIPDB_API_KEY = "YOUR_ABUSEIPDB_API_KEY"
VIRUSTOTAL_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
```

---

## 🧪 Example Usage

```bash
python generate_test_sample.py
python main.py samples/test_quishing.eml -o output
```

---

## 📜 License

This project is licensed under the MIT License.
