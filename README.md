# 🛡️ PhishTriage Engine: Automated SOC Artifact & Quishing Triage Pipeline

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![SOC-Automation](https://img.shields.io/badge/SOC-Tier--1%20Automation-red.svg)]()

**PhishTriage Engine** is an end-to-end artifact triage tool designed to accelerate Tier-1 Security Operations Center (SOC) incident response. It automates email header auditing, multi-format file ingestion (`.eml`, `.pdf`, `.txt`), computer-vision QR Code phishing (**Quishing**) extraction, dynamic indicator defanging, real-time threat intelligence enrichment, and structured incident reporting.

---

## ⚡ Problem Statement & Solution

* **The Problem:** Tier-1 SOC analysts spend 10–15 minutes per phishing ticket manually inspecting headers, decoding obscure authentication results, scanning attachment hashes, and safely analyzing QR-code lures. This causes severe alert fatigue and delays MTTR (Mean Time to Respond).
* **The Solution:** This engine automates the entire ingestion-to-triage lifecycle, extracting all actionable indicators in under 10 seconds, scoring threats dynamically on a **0–100 weighted matrix**, and exporting a standardized Markdown SOC case report.

---

## 🚀 Key Features

* 📷 **Quishing (QR Code Phishing) Extraction:** Uses computer vision (`pyzbar` & `Pillow`) to extract embedded malicious URLs directly from raw image attachments and embedded PDF graphics without risky sandbox rendering.
* 📄 **Multi-Format Ingestion Engine:** Supports native parsing for `.eml`, `.msg`, `.pdf` documents (text + images), and raw `.txt`/`.log` unstructured files.
* ✉️ **Email Header & Authentication Auditing:** Parses SPF, DKIM, and DMARC verdicts from `Authentication-Results` / `Received-SPF` headers to instantly flag domain spoofing.
* 🌐 **Originating IP Relay Tracing:** Walks reverse SMTP `Received:` headers to isolate the external gateway IP while discarding RFC-1918 internal/private subnets.
* 🔍 **Multi-Source Threat Intelligence:**
  * **AbuseIPDB API:** Fetches Abuse Confidence Scores, total reports, country, and ISP data.
  * **VirusTotal API (v3):** Checks real-time detection ratios for URLs, QR payloads, and SHA-256 attachment hashes.
* 🛡️ **Automated IOC Defanging:** Sanitizes URLs and IPs (`hxxps://evil[.]com`, `185.220.101[.]5`) across outputs to prevent accidental analyst execution.
* 📋 **Dynamic Risk Scoring & SOC Markdown Playbooks:** Outputs comprehensive investigation reports with severity classification and remediation playbooks (e.g., Mailbox Purge, IP/URL perimeter blocking).

---

## 🏗️ Architecture & Data Flow