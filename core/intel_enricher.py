# core/intel_enricher.py
import base64
import requests
import config

def check_ip_abuseipdb(ip_address: str) -> dict:
    """
    Queries AbuseIPDB API v2 for IP reputation and abuse score.
    """
    if not ip_address or config.ABUSEIPDB_API_KEY == "c1bb54990ca560e6f18ffa7833432a9c71e44668be4d7e48945dbaa46121295b8a9541dbaba11446":
        return {"status": "skipped", "abuse_score": 0, "total_reports": 0, "country": "Unknown", "isp": "Unknown"}

    url = "https://api.abuseipdb.com/api/v2/check"
    querystring = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90',
        'verbose': 'true'
    }
    headers = {
        'Accept': 'application/json',
        'Key': config.ABUSEIPDB_API_KEY
    }

    try:
        response = requests.get(url, headers=headers, params=querystring, timeout=10)
        if response.status_code == 200:
            data = response.json().get('data', {})
            return {
                "status": "success",
                "ip": ip_address,
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "country": data.get("countryCode", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "usage_type": data.get("usageType", "Unknown")
            }
        else:
            return {"status": "error", "code": response.status_code, "abuse_score": 0}
    except Exception as e:
        return {"status": "failed", "error": str(e), "abuse_score": 0}


def check_url_virustotal(target_url: str) -> dict:
    """
    Queries VirusTotal v3 API for URL analysis verdict using base64 URL ID.
    """
    if not target_url or config.VIRUSTOTAL_API_KEY == "b0ffff3c2299551401bdfcf35ea9be8283c0aab612cc0241c5d813e4f0f2a393":
        return {"status": "skipped", "malicious_count": 0, "suspicious_count": 0, "total_engines": 0}

    # VirusTotal v3 requires base64-encoded URL string without trailing '=' padding
    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {
        "x-apikey": config.VIRUSTOTAL_API_KEY,
        "Accept": "application/json"
    }

    try:
        response = requests.get(api_url, headers=headers, timeout=10)
        if response.status_code == 200:
            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "status": "success",
                "url": target_url,
                "malicious_count": stats.get("malicious", 0),
                "suspicious_count": stats.get("suspicious", 0),
                "harmless_count": stats.get("harmless", 0),
                "total_engines": sum(stats.values())
            }
        elif response.status_code == 404:
            return {"status": "unseen", "malicious_count": 0, "suspicious_count": 0, "total_engines": 0}
        else:
            return {"status": "error", "code": response.status_code, "malicious_count": 0}
    except Exception as e:
        return {"status": "failed", "error": str(e), "malicious_count": 0}


def check_hash_virustotal(file_hash: str) -> dict:
    """
    Queries VirusTotal v3 API for File Hash (SHA256) reputation.
    """
    if not file_hash or config.VIRUSTOTAL_API_KEY == "YOUR_VIRUSTOTAL_KEY":
        return {"status": "skipped", "malicious_count": 0, "suspicious_count": 0}

    api_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": config.VIRUSTOTAL_API_KEY,
        "Accept": "application/json"
    }

    try:
        response = requests.get(api_url, headers=headers, timeout=10)
        if response.status_code == 200:
            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "status": "success",
                "sha256": file_hash,
                "malicious_count": stats.get("malicious", 0),
                "suspicious_count": stats.get("suspicious", 0),
                "total_engines": sum(stats.values())
            }
        elif response.status_code == 404:
            return {"status": "unseen", "malicious_count": 0, "suspicious_count": 0}
        else:
            return {"status": "error", "code": response.status_code, "malicious_count": 0}
    except Exception as e:
        return {"status": "failed", "error": str(e), "malicious_count": 0}