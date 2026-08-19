# core/risk_scorer.py
import re
from datetime import datetime
from core.email_parser import defang_indicator

SUSPICIOUS_KEYWORDS = [
    "urgent", "immediate action", "verify your account", "password expired",
    "wire transfer", "invoice attached", "suspended", "unauthorized login",
    "banking alert", "security update", "payroll"
]

def calculate_risk_score(parsed_email: dict, ip_intel: dict, url_intels: list, hash_intels: list, quishing_urls: list) -> dict:
    """
    Computes numerical risk score (0-100) and compiles triggered threat signals.
    """
    score = 0
    reasons = []

    # 1. Email Auth Checks (SPF/DKIM/DMARC)
    auth = parsed_email["headers"].get("auth_verdicts", {})
    if auth.get("spf") == "fail" or auth.get("dmarc") == "fail":
        score += 25
        reasons.append("Email Authentication Failed (SPF/DMARC Spoofing detected)")
    elif auth.get("dkim") == "fail":
        score += 15
        reasons.append("DKIM Signature Verification Failed")

    # 2. Originating IP Reputation
    abuse_score = ip_intel.get("abuse_score", 0)
    if abuse_score > 50:
        score += 30
        reasons.append(f"Originating IP has high AbuseIPDB score: {abuse_score}% (ISP: {ip_intel.get('isp', 'Unknown')})")
    elif abuse_score > 10:
        score += 15
        reasons.append(f"Originating IP has moderate abuse history ({abuse_score}%)")

    # 3. VirusTotal URL Intelligence
    for u_res in url_intels:
        if u_res.get("malicious_count", 0) > 0:
            score += 35
            reasons.append(f"Malicious URL detected by {u_res['malicious_count']} engines on VirusTotal ({defang_indicator(u_res['url'])})")
            break

    # 4. VirusTotal Attachment Hash Intelligence
    for h_res in hash_intels:
        if h_res.get("malicious_count", 0) > 0:
            score += 40
            reasons.append(f"Attachment hash matched known malware on VirusTotal (SHA256: {h_res['sha256']})")
            break

    # 5. Quishing / Hidden QR code URLs
    if quishing_urls:
        score += 25
        reasons.append(f"Hidden QR Code detected in image attachment pointing to: {defang_indicator(quishing_urls[0])}")

    # 6. Keyword & Social Engineering Heuristics
    subject = parsed_email["headers"].get("subject", "").lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in subject:
            score += 10
            reasons.append(f"Urgent/Phishing keyword detected in subject line: '{kw}'")
            break

    # Cap score at 100
    final_score = min(score, 100)

    # Determine Severity Level
    if final_score >= 80:
        severity = "CRITICAL / MALICIOUS"
    elif final_score >= 50:
        severity = "SUSPICIOUS"
    elif final_score >= 20:
        severity = "LOW RISK"
    else:
        severity = "BENIGN"

    return {
        "score": final_score,
        "severity": severity,
        "reasons": reasons
    }


def generate_markdown_report(parsed_email: dict, ip_intel: dict, url_intels: list, hash_intels: list, quishing_urls: list, risk_data: dict) -> str:
    """
    Generates a structured SOC Triage Investigation Report in Markdown.
    """
    h = parsed_email["headers"]
    auth = h.get("auth_verdicts", {})
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    report = f"""# 🛡️ SOC Incident Triage Report: Phishing Investigation
**Generated At:** {timestamp}  
**Overall Verdict:** `{risk_data['severity']}` (Risk Score: **{risk_data['score']}/100**)

---

## 1. Executive Summary
* **Subject:** {h.get('subject', 'N/A')}
* **Sender (From):** `{h.get('from', 'N/A')}`
* **Recipient (To):** `{h.get('to', 'N/A')}`
* **Originating IP:** `{defang_indicator(h.get('originating_ip', 'N/A'))}` ({ip_intel.get('country', 'XX')} - {ip_intel.get('isp', 'N/A')})
* **Authentication Status:** SPF: `{auth.get('spf')}` | DKIM: `{auth.get('dkim')}` | DMARC: `{auth.get('dmarc')}`

---

## 2. Threat Indicators & Triggered Rules
"""
    if risk_data["reasons"]:
        for r in risk_data["reasons"]:
            report += f"- ⚠️ **{r}**\n"
    else:
        report += "- ✅ No high-risk indicators or known signatures matched.\n"

    report += "\n---\n\n## 3. Extracted Artifacts & Forensics\n"
    
    # URLs
    report += "### Extracted URLs (Defanged)\n"
    if parsed_email["urls"]:
        for u in parsed_email["urls"]:
            report += f"- `{defang_indicator(u)}`\n"
    else:
        report += "- *No URLs found in email body.*\n"

    # Quishing
    report += "\n### QR Code (Quishing) Analysis\n"
    if quishing_urls:
        for qr in quishing_urls:
            report += f"- 📷 **QR Code Payload Extracted:** `{defang_indicator(qr)}`\n"
    else:
        report += "- *No QR codes detected in attachments/images.*\n"

    # Attachments
    report += "\n### Attachment Hashes\n"
    if parsed_email["attachments"]:
        for att in parsed_email["attachments"]:
            report += f"- **File:** `{att['filename']}` | **Type:** `{att['content_type']}`\n  - SHA256: `{att['sha256']}`\n"
    else:
        report += "- *No file attachments present.*\n"

    # Recommended Actions
    report += "\n---\n\n## 4. Recommended SOC Actions\n"
    if risk_data["score"] >= 70:
        report += """1. **Block Sender Domain & Originating IP** on Email Gateway and Perimeter Firewall.
2. **Purge Email** from all user inboxes across the tenant.
3. **Block Defanged URLs/Domains** on Web Proxy / DNS Sinkhole.
4. **Reset Credentials** if recipient engaged or submitted input to the landing page.
"""
    elif risk_data["score"] >= 40:
        report += """1. **Monitor Recipient Host** for outbound connections to extracted URLs.
2. **Warn User** regarding suspicious nature of the communication.
"""
    else:
        report += "1. **No immediate remediation required.** Mark alert as False Positive or Benign.\n"

    return report