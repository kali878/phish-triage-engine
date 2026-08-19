import base64
import requests
import config

def check_ip_abuseipdb(ip_address: str) -> dict:
    if not ip_address or not getattr(config, 'ABUSEIPDB_API_KEY', None) or config.ABUSEIPDB_API_KEY == "YOUR_ABUSEIPDB_KEY":
        return {"status": "skipped", "abuse_score": 0, "total_reports": 0, "country": "Unknown", "isp": "Unknown"}

    url = "[https://api.abuseipdb.com/api/v2/check](https://api.abuseipdb.com/api/v2/check)"
    querystring = {'ipAddress': ip_address, 'maxAgeInDays': '90', 'verbose': 'true'}
    headers = {'Accept': 'application/json', 'Key': config.ABUSEIPDB_API_KEY}

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
                "isp": data.get("isp", "Unknown")
            }
        return {"status": "error", "code": response.status_code, "abuse_score": 0}
    except Exception as e:
        return {"status": "failed", "error": str(e), "abuse_score": 0}

def check_url_virustotal(target_url: str) -> dict:
    if not target_url or not getattr(config, 'VIRUSTOTAL_API_KEY', None) or config.VIRUSTOTAL_API_KEY == "YOUR_VIRUSTOTAL_KEY":
        return {"status": "skipped", "malicious_count": 0, "suspicious_count": 0, "total_engines": 0}

    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
    api_url = f"[https://www.virustotal.com/api/v3/urls/](https://www.virustotal.com/api/v3/urls/){url_id}"
    headers = {"x-apikey": config.VIRUSTOTAL_API_KEY, "Accept": "application/json"}

    try:
        response = requests.get(api_url, headers=headers, timeout=10)
        if response.status_code == 200:
            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "status": "success",
                "url": target_url,
                "malicious_count": stats.get("malicious", 0),
                "suspicious_count": stats.get("suspicious", 0),
                "total_engines": sum(stats.values())
            }
        return {"status": "unseen", "malicious_count": 0, "suspicious_count": 0}
    except Exception as e:
        return {"status": "failed", "error": str(e), "malicious_count": 0}

def check_hash_virustotal(file_hash: str) -> dict:
    if not file_hash or not getattr(config, 'VIRUSTOTAL_API_KEY', None) or config.VIRUSTOTAL_API_KEY == "YOUR_VIRUSTOTAL_KEY":
        return {"status": "skipped", "malicious_count": 0, "suspicious_count": 0}

    api_url = f"[https://www.virustotal.com/api/v3/files/](https://www.virustotal.com/api/v3/files/){file_hash}"
    headers = {"x-apikey": config.VIRUSTOTAL_API_KEY, "Accept": "application/json"}

    try:
        response = requests.get(api_url, headers=headers, timeout=10)
        if response.status_code == 200:
            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "status": "success",
                "sha256": file_hash,
                "malicious_count": stats.get("malicious", 0),
                "suspicious_count": stats.get("suspicious", 0)
            }
        return {"status": "unseen", "malicious_count": 0, "suspicious_count": 0}
    except Exception as e:
        return {"status": "failed", "error": str(e), "malicious_count": 0}
