import requests
import ipaddress
import os
from dotenv import load_dotenv
from services.cve_enricher import fetch_cves_by_keyword

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
ABUSE_API_KEY = os.getenv("ABUSE_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

TIMEOUT = 10
# -------------------- VIRUSTOTAL --------------------
def check_virustotal(ip):
    if not VT_API_KEY:
        return {"error": "API key missing"}
    try:
        base_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": VT_API_KEY}
        response = requests.get(base_url, headers=headers, timeout=TIMEOUT)
        if response.status_code != 200:
            return {"error": f"http_{response.status_code}"}
        data = response.json()
        attr = data["data"]["attributes"]
        stats = attr.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        if malicious > 5:
            verdict = "malicious"
        elif malicious > 0 or suspicious > 0:
            verdict = "suspicious"
        else:
            verdict = "clean"
        #réseau
        country = attr.get("country")
        asn = attr.get("asn")
        as_owner = attr.get("as_owner")
        #Tags
        tags = attr.get("tags", [])
        if not tags:
            tags = ["no tags"]
        #Reputation
        reputation = attr.get("reputation", 0)
        #Votes
        votes = attr.get("total_votes", {})
        harmless_votes = votes.get("harmless", 0)
        malicious_votes = votes.get("malicious", 0)
        #Relations
        relations = {}
        try:
            files_url = f"{base_url}/communicating_files"
            res = requests.get(files_url, headers=headers, timeout=TIMEOUT)
            if res.status_code == 200:
                relations["files"] = [
                    f["id"] for f in res.json().get("data", [])[:5]
                ]
        except:
            relations["files"] = []
        try:
            urls_url = f"{base_url}/urls"
            res = requests.get(urls_url, headers=headers, timeout=TIMEOUT)
            if res.status_code == 200:
                relations["urls"] = [
                    u["id"] for u in res.json().get("data", [])[:5]
                ]
        except:
            relations["urls"] = []
        try:
            dns_url = f"{base_url}/resolutions"
            res = requests.get(dns_url, headers=headers, timeout=TIMEOUT)
            if res.status_code == 200:
                relations["domains"] = [
                    d["attributes"]["host_name"]
                    for d in res.json().get("data", [])[:5]
                ]
        except:
            relations["domains"] = []
        return {
            "verdict": verdict,
            "stats": stats,
            "country": country,
            "asn": asn,
            "as_owner": as_owner,
            "tags": tags,
            "reputation": reputation,
            "votes": {
                "harmless": harmless_votes,
                "malicious": malicious_votes
            },
            "relations": relations,
        }
    except Exception as e:
        return {"error": str(e)}

# -------------------- ABUSEIPDB --------------------
def check_abuseipdb(ip):
    if not ABUSE_API_KEY:
        return {"error": "API key missing"}
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSE_API_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip}
        response = requests.get(url, headers=headers, params=params, timeout=TIMEOUT)
        if response.status_code != 200:
            return {"error": f"http_{response.status_code}"}
        data = response.json()
        score = data["data"]["abuseConfidenceScore"]
        verdict = "clean"
        if score > 50:
            verdict = "malicious"
        elif score > 0:
            verdict = "suspicious"
        return {
            "verdict": verdict,
            "abuse_score": score
        }
    except Exception as e:
        return {"error": str(e)}
    
# -------------------- OTX --------------------
def check_otx(ip):
    if not OTX_API_KEY:
        return {"error": "API key missing"}
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        headers = {"X-OTX-API-KEY": OTX_API_KEY}
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code != 200:
            return {"error": f"http_{response.status_code}"}
        data = response.json()
        pulses = data.get("pulse_info", {}).get("count", 0)
        verdict = "suspicious" if pulses > 0 else "clean"
        return {
            "verdict": verdict,
            "pulse_count": pulses
        }
    except Exception as e:
        return {"error": str(e)}

# -------------------- TALOS (Manual Lookup) --------------------
def check_talos(ip):
    return {
        "status": "manual_lookup_required",
        "url": f"https://talosintelligence.com/reputation_center/lookup?search={ip}"
    }

# -------------------- GLOBAL FUNCTION --------------------
def check_ip_reputation(param: str):

    # Validate IP
    try:
        ipaddress.ip_address(param)
    except ValueError:
        return {"error": "Invalid IP address"}
    result = {"ip": param}
    # Call vendors
    vt = check_virustotal(param)
    abuse = check_abuseipdb(param)
    otx = check_otx(param)
    talos = check_talos(param)
    result["virustotal"] = vt
    result["abuseipdb"] = abuse
    result["otx"] = otx
    result["talos"] = talos

    # -------- Final Verdict Logic --------
    malicious_count = 0
    for source in [vt, abuse, otx]:
        if isinstance(source, dict) and source.get("verdict") == "malicious":
            malicious_count += 1
    if malicious_count >= 2:
        final_verdict = "malicious"
    elif malicious_count == 1:
        final_verdict = "suspicious"
    else:
        final_verdict = "clean"
    result["final_verdict"] = final_verdict

    # -------- CVE Enrichment --------
    if final_verdict in ["malicious", "suspicious"]:
     tags = vt.get("tags", []) if isinstance(vt, dict) else []
     abuse_score = abuse.get("abuse_score", 0) if isinstance(abuse, dict) else 0
     pulses = otx.get("pulse_count", 0) if isinstance(otx, dict) else 0
     malicious_count_vt = vt.get("stats", {}).get("malicious", 0) if isinstance(vt, dict) else 0
    #Primary keyword
     if "tor" in tags:
         keyword = "anonymity network"
     elif "phishing" in tags:
        keyword = "phishing"
     elif "botnet" in tags:
        keyword = "botnet"
     elif malicious_count_vt > 10:
        keyword = "remote code execution"
     elif abuse_score > 80:
        keyword = "brute force"
     elif pulses > 20:
        keyword = "malware infrastructure"
     else:
        keyword = "network attack"
    #First attempt
     cve_result = fetch_cves_by_keyword(keyword, max_results=3)
    #FALLBACK if empty
     if cve_result.get("count", 0) == 0:
        fallback_keywords = [
            "remote code execution",
            "privilege escalation",
            "network attack"
        ]
        for fb in fallback_keywords:
            cve_result = fetch_cves_by_keyword(fb, max_results=3)
            if cve_result.get("count", 0) > 0:
                keyword = fb
                break
    #Final result
     if "error" not in cve_result and cve_result.get("count", 0) > 0:
        result["cve_enrichment"] = {
            "status": "contextual",
            "confidence": "high" if malicious_count_vt > 10 or abuse_score > 80 else "medium",
            "keyword_used": keyword,
            "count": cve_result.get("count", 0),
            "cves": cve_result.get("cves", [])
        }
     else:
        result["cve_enrichment"] = {
            "status": "no_relevant_cve_found",
            "message": "No CVEs matched this threat context",
            "suggestion": "Try broader threat categories"
        }
    else:
     result["cve_enrichment"] = {
        "status": "no_cve_data",
        "cves": []
    }
    return result

