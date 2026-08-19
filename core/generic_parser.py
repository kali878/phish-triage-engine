# core/generic_parser.py
import re
import os
from pypdf import PdfReader
from core.email_parser import defang_indicator
import hashlib

def extract_urls_and_ips_from_text(raw_text: str) -> dict:
    """
    Regex engine to harvest URLs, IPs, and Email addresses from arbitrary text.
    """
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'

    urls = list(set(re.findall(url_pattern, raw_text)))
    ips = list(set(re.findall(ip_pattern, raw_text)))
    emails = list(set(re.findall(email_pattern, raw_text)))

    # Filter out private RFC1918 IPs
    clean_ips = [ip for ip in ips if not (ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('127.'))]

    return {
        "urls": urls,
        "originating_ip": clean_ips[0] if clean_ips else None,
        "extracted_emails": emails
    }

def parse_pdf_file(pdf_path: str) -> dict:
    """
    Extracts text, embedded links, and embedded images from a PDF file.
    """
    reader = PdfReader(pdf_path)
    combined_text = ""
    extracted_images = []

    # 1. Extract text from each page
    for page_idx, page in enumerate(reader.pages):
        text = page.extract_text() or ""
        combined_text += f"\n--- Page {page_idx+1} ---\n" + text

        # 2. Extract embedded images for Quishing/QR checking
        for img in page.images:
            extracted_images.append({
                "filename": img.name,
                "content_type": "image/png",
                "raw_bytes": img.data,
                "sha256": hashlib.sha256(img.data).hexdigest()
            })

    artifacts = extract_urls_and_ips_from_text(combined_text)

    # Standardize data structure to match email parser output
    return {
        "headers": {
            "from": ", ".join(artifacts["extracted_emails"]) if artifacts["extracted_emails"] else "PDF Embedded Entity",
            "to": "N/A",
            "subject": f"PDF Incident Extraction: {os.path.basename(pdf_path)}",
            "originating_ip": artifacts["originating_ip"],
            "auth_verdicts": {"spf": "neutral", "dkim": "neutral", "dmarc": "neutral"}
        },
        "body_preview": combined_text[:500].strip(),
        "urls": artifacts["urls"],
        "defanged_urls": [defang_indicator(u) for u in artifacts["urls"]],
        "attachments": extracted_images
    }

def parse_txt_file(txt_path: str) -> dict:
    """
    Extracts text artifacts from a raw .txt or unstructured log file.
    """
    with open(txt_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    artifacts = extract_urls_and_ips_from_text(content)

    return {
        "headers": {
            "from": ", ".join(artifacts["extracted_emails"]) if artifacts["extracted_emails"] else "Raw Text Log",
            "to": "N/A",
            "subject": f"Text File Ingestion: {os.path.basename(txt_path)}",
            "originating_ip": artifacts["originating_ip"],
            "auth_verdicts": {"spf": "neutral", "dkim": "neutral", "dmarc": "neutral"}
        },
        "body_preview": content[:500].strip(),
        "urls": artifacts["urls"],
        "defanged_urls": [defang_indicator(u) for u in artifacts["urls"]],
        "attachments": []
    }