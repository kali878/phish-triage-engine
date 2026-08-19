# main.py
import os
import sys
import argparse
from core.email_parser import parse_email_file
from core.generic_parser import parse_pdf_file, parse_txt_file
from core.quishing_parser import scan_image_for_qr
from core.intel_enricher import check_ip_abuseipdb, check_url_virustotal, check_hash_virustotal
from core.risk_scorer import calculate_risk_score, generate_markdown_report

def get_parsed_data_by_filetype(file_path: str) -> dict:
    """
    Routes the file to the appropriate parser based on its extension.
    """
    ext = os.path.splitext(file_path)[1].lower()
    
    if ext in ['.eml', '.msg']:
        print("[+] Format detected: MIME Email (.eml/.msg)")
        return parse_email_file(file_path)
    elif ext == '.pdf':
        print("[+] Format detected: Portable Document Format (.pdf)")
        return parse_pdf_file(file_path)
    elif ext in ['.txt', '.log', '.csv']:
        print("[+] Format detected: Text / Raw Log (.txt/.log/.csv)")
        return parse_txt_file(file_path)
    else:
        print(f"[!] Unknown extension '{ext}'. Falling back to raw text parsing...")
        return parse_txt_file(file_path)

def triage_file(file_path: str, output_dir: str = "output"):
    """
    Main triage execution pipeline.
    """
    if not os.path.exists(file_path):
        print(f"[!] Error: File not found: {file_path}")
        return

    print(f"\n[*] Starting SOC Triage Analysis for: {file_path}")
    print("=" * 60)
    
    # 1. Parse File Artifacts
    parsed = get_parsed_data_by_filetype(file_path)

    # 2. Extract Quishing (QR Codes) from Images/Attachments
    print("[+] Scanning extracted images for embedded QR codes (Quishing)...")
    quishing_urls = []
    for att in parsed.get("attachments", []):
        filename = att.get("filename", "").lower()
        content_type = att.get("content_type", "").lower()
        if "image" in content_type or filename.endswith(('.png', '.jpg', '.jpeg')):
            extracted_qr = scan_image_for_qr(att["raw_bytes"])
            if extracted_qr:
                quishing_urls.extend(extracted_qr)

    # 3. Query Threat Intel for Originating IP
    origin_ip = parsed["headers"].get("originating_ip")
    if origin_ip:
        print(f"[+] Querying AbuseIPDB for Originating IP: {origin_ip}...")
        ip_intel = check_ip_abuseipdb(origin_ip)
    else:
        print("[+] No external Originating IP found. Skipping IP reputation check.")
        ip_intel = {"status": "skipped", "abuse_score": 0, "country": "Unknown", "isp": "Unknown"}

    # 4. Query Threat Intel for URLs & Extracted QR links
    all_urls = list(set(parsed.get("urls", []) + quishing_urls))
    url_intels = []
    if all_urls:
        print(f"[+] Querying VirusTotal for {len(all_urls)} extracted URL(s)...")
        for url in all_urls:
            res = check_url_virustotal(url)
            url_intels.append(res)
    else:
        print("[+] No URLs found in document body or QR codes.")

    # 5. Query Threat Intel for Attachment Hashes
    hash_intels = []
    attachments = parsed.get("attachments", [])
    if attachments:
        print(f"[+] Querying VirusTotal for {len(attachments)} attachment hash(es)...")
        for att in attachments:
            res = check_hash_virustotal(att["sha256"])
            hash_intels.append(res)
    else:
        print("[+] No file attachments to query.")

    # 6. Compute Dynamic Risk Score
    print("[+] Computing composite risk score and matching SOC rules...")
    risk_data = calculate_risk_score(parsed, ip_intel, url_intels, hash_intels, quishing_urls)

    # 7. Generate & Save Markdown Report
    os.makedirs(output_dir, exist_ok=True)
    base_name = os.path.splitext(os.path.basename(file_path))[0]
    report_filename = os.path.join(output_dir, f"triage_report_{base_name}.md")

    report_content = generate_markdown_report(parsed, ip_intel, url_intels, hash_intels, quishing_urls, risk_data)
    with open(report_filename, "w", encoding="utf-8") as f:
        f.write(report_content)

    # 8. Display CLI Summary Box
    print("\n" + "=" * 60)
    print(f"🎯 TRIAGE VERDICT: {risk_data['severity']}")
    print(f"📊 RISK SCORE:     {risk_data['score']}/100")
    print(f"📄 SOC REPORT:     {report_filename}")
    print("=" * 60)
    
    if risk_data["reasons"]:
        print("\nTriggered Threat Signals:")
        for r in risk_data["reasons"]:
            print(f"  • {r}")
    else:
        print("\nNo high-risk threat indicators triggered.")
    print("\n")

def main():
    parser = argparse.ArgumentParser(
        description="Automated SOC Phishing, Quishing & Artifact Triage Engine",
        epilog="Supported formats: .eml, .msg, .pdf, .txt, .log, .csv"
    )
    parser.add_argument("file", help="Path to suspicious file (.eml, .pdf, .txt, etc.)")
    parser.add_argument("-o", "--output", default="output", help="Directory where the Markdown report will be saved (Default: output/)")

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    triage_file(args.file, args.output)

if __name__ == "__main__":
    main()