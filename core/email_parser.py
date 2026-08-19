import re
import email
from email import policy
from email.parser import BytesParser
from bs4 import BeautifulSoup
import hashlib

def defang_indicator(indicator: str) -> str:
    if not indicator:
        return ""
    defanged = re.sub(r'^http://', 'hxxp://', indicator, flags=re.IGNORECASE)
    defanged = re.sub(r'^https://', 'hxxps://', defanged, flags=re.IGNORECASE)
    defanged = defanged.replace('.', '[.]')
    return defanged

def extract_originating_ip(received_headers: list) -> str:
    ip_pattern = r'\[?(\b(?:\d{1,3}\.){3}\d{1,3}\b)\]?'
    for header in reversed(received_headers):
        matches = re.findall(ip_pattern, str(header))
        for ip in matches:
            if not (ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('127.') or ip.startswith('172.16.') or ip.startswith('172.31.')):
                return ip
    return ""

def parse_auth_results(auth_header: str, spf_header: str) -> dict:
    results = {"spf": "neutral", "dkim": "neutral", "dmarc": "neutral"}
    combined = (str(auth_header) + " " + str(spf_header)).lower()

    if "spf=pass" in combined or "pass" in str(spf_header).lower():
        results["spf"] = "pass"
    elif "spf=fail" in combined or "spf=softfail" in combined:
        results["spf"] = "fail"

    if "dkim=pass" in combined:
        results["dkim"] = "pass"
    elif "dkim=fail" in combined:
        results["dkim"] = "fail"

    if "dmarc=pass" in combined:
        results["dmarc"] = "pass"
    elif "dmarc=fail" in combined:
        results["dmarc"] = "fail"

    return results

def parse_email_file(file_path: str) -> dict:
    with open(file_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    headers = {
        "from": msg.get("From", ""),
        "to": msg.get("To", ""),
        "subject": msg.get("Subject", ""),
        "date": msg.get("Date", ""),
        "message_id": msg.get("Message-ID", ""),
        "return_path": msg.get("Return-Path", "")
    }

    received_headers = msg.get_all("Received", [])
    headers["originating_ip"] = extract_originating_ip(received_headers)
    headers["auth_verdicts"] = parse_auth_results(
        msg.get("Authentication-Results", ""),
        msg.get("Received-SPF", "")
    )

    body_text = ""
    raw_urls = set()
    attachments = []

    for part in msg.walk():
        content_type = part.get_content_type()
        disposition = str(part.get("Content-Disposition", ""))

        if "attachment" in disposition or part.get_filename():
            filename = part.get_filename() or "unnamed_attachment"
            payload = part.get_payload(decode=True)
            if payload:
                file_hash = hashlib.sha256(payload).hexdigest()
                attachments.append({
                    "filename": filename,
                    "content_type": content_type,
                    "sha256": file_hash,
                    "raw_bytes": payload
                })
            continue

        if content_type == "text/plain":
            body_text += part.get_content()
        elif content_type == "text/html":
            html_content = part.get_content()
            soup = BeautifulSoup(html_content, "html.parser")
            body_text += " " + soup.get_text()
            for a in soup.find_all("a", href=True):
                raw_urls.add(a["href"])

    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    for match in re.findall(url_pattern, body_text):
        raw_urls.add(match)

    clean_urls = [u for u in raw_urls if not u.startswith("[http://www.w3.org](http://www.w3.org)")]

    return {
        "headers": headers,
        "body_preview": body_text[:500].strip(),
        "urls": clean_urls,
        "defanged_urls": [defang_indicator(u) for u in clean_urls],
        "attachments": attachments
    }
