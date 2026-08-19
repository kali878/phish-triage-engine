from datetime import datetime
from core.email_parser import defang_indicator

SUSPICIOUS_KEYWORDS = [
    "urgent", "immediate action", "verify your account", "password expired",
    "wire transfer", "invoice attached", "suspended", "unauthorized login",
    "banking alert", "security update", "payroll"
]

def calculate_risk_score(parsed_email: dict, ip_intel: dict, url_intels: list, hash_intels: list, quishing_urls: list) -> dict:
    score = 0
    reasons = []

    auth = parsed_email["headers"].get("auth_verdicts", {})
    if auth.get("spf") == "fail" or auth.get("dmarc") == "fail":
        score += 25
        reasons.append("Email Authentication Failed (SPF/DMARC Spoofing detected)")
    elif auth.get("dkim") == "fail":
        score += 15
        reasons.append("DKIM Signature Verification Failed")

    abuse_score = ip_intel.get("abuse_score", 0)
    if abuse_score > 50:
        score += 30
        reasons.append(f"Originating IP has high AbuseIPDB score: {abuse_score}% (ISP: {ip_intel.get('isp', 'Unknown')})")
    elif abuse_score > 10:
        score += 15
        reasons.append(f"Originating IP has moderate abuse history ({abuse_score}%)")

    for u_res in url_intels:
        if u_res.get("malicious_count", 0) > 0:
            score += 35
            reasons.append(f"Malicious URL detected by {u_res['malicious_count']} engines on VirusTotal ({defang_indicator(u_res.get('url', ''))})")
            break

    for h_res in hash_intels:
        if h_res.get("malicious_count", 0) > 0:
            score += 40
            reasons.append(f"Attachment hash matched known malware on VirusTotal (SHA256: {h_res.get('sha256', '')})")
            break

    if quishing_urls:
        score += 25
        reasons.append(f"Hidden QR Code detected in image attachment pointing to: {defang_indicator(quishing_urls[0])}")

    subject = parsed_email["headers"].get("subject", "").lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in subject:
            score += 10
            reasons.append(f"Urgent/Phishing keyword detected in subject line: '{kw}'")
            break

    final_score = min(score, 100)

    if final_score >= 80:
        severity = "CRITICAL / MALICIOUS"
    elif final_score >= 50:
        severity = "SUSPICIOUS"
    elif final_score >= 20:
        severity = "LOW RISK"
    else:
        severity = "BENIGN"

    return {"score": final_score, "severity": severity, "reasons": reasons}

def generate_markdown_report(parsed_email: dict, ip_intel: dict, url_intels: list, hash_intels: list, quishing_urls: list, risk_data: dict) -> str:
    h = parsed_email["headers"]
    auth = h.get("auth_verdicts", {})
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    report = f"# 🛡️ SOC Incident Triage Report: Phishing Investigation\n"
    report += f"**Generated At:** {timestamp}  \n"
    report += f"**Overall Verdict:** `{risk_data['severity']}` (Risk Score: **{risk_data['score']}/100**)\n\n"
    report += "---\n\n## 1. Executive Summary\n"
    report += f"* **Subject:** {h.get('subject', 'N/A')}\n"
    report += f"* **Sender (From):** `{h.get('from', 'N/A')}`\n"
    report += f"* **Recipient (To):** `{h.get('to', 'N/A')}`\n"
    report += f"* **Originating IP:** `{defang_indicator(h.get('originating_ip', 'N/A'))}` ({ip_intel.get('country', 'XX')} - {ip_intel.get('isp', 'N/A')})\n"
    report += f"* **Authentication Status:** SPF: `{auth.get('spf')}` | DKIM: `{auth.get('dkim')}` | DMARC: `{auth.get('dmarc')}`\n\n"
    report += "---\n\n## 2. Threat Indicators & Triggered Rules\n"

    if risk_data["reasons"]:
        for r in risk_data["reasons"]:
            report += f"- ⚠️ **{r}**\n"
    else:
        report += "- ✅ No high-risk indicators or known signatures matched.\n"

    report += "\n---\n\n## 3. Extracted Artifacts & Forensics\n"
    report += "### Extracted URLs (Defanged)\n"
    if parsed_email.get("urls"):
        for u in parsed_email["urls"]:
            report += f"- `{defang_indicator(u)}`\n"
    else:
        report += "- *No URLs found in email body.*\n"

    report += "\n### QR Code (Quishing) Analysis\n"
    if quishing_urls:
        for qr in quishing_urls:
            report += f"- 📷 **QR Code Payload Extracted:** `{defang_indicator(qr)}`\n"
    else:
        report += "- *No QR codes detected in attachments/images.*\n"

    report += "\n### Attachment Hashes\n"
    if parsed_email.get("attachments"):
        for att in parsed_email["attachments"]:
            report += f"- **File:** `{att['filename']}` | **Type:** `{att['content_type']}`\n  - SHA256: `{att['sha256']}`\n"
    else:
        report += "- *No file attachments present.*\n"

    report += "\n---\n\n## 4. Recommended SOC Actions\n"
    if risk_data["score"] >= 70:
        report += "1. **Block Sender Domain & Originating IP** on Email Gateway and Perimeter Firewall.\n"
        report += "2. **Purge Email** from all user inboxes across the tenant.\n"
        report += "3. **Block Defanged URLs/Domains** on Web Proxy / DNS Sinkhole.\n"
        report += "4. **Reset Credentials** if recipient engaged or submitted input to the landing page.\n"
    elif risk_data["score"] >= 40:
        report += "1. **Monitor Recipient Host** for outbound connections to extracted URLs.\n"
        report += "2. **Warn User** regarding suspicious nature of the communication.\n"
    else:
        report += "1. **No immediate remediation required.** Mark alert as False Positive or Benign.\n"

    return report
