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
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": VT_API_KEY}

        response = requests.get(url, headers=headers, timeout=TIMEOUT)

        if response.status_code != 200:
            return {"error": f"http_{response.status_code}"}

        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]

        verdict = "clean"
        if stats["malicious"] > 0:
            verdict = "malicious"
        elif stats["suspicious"] > 0:
            verdict = "suspicious"

        return {
            "verdict": verdict,
            "malicious": stats["malicious"],
            "suspicious": stats["suspicious"],
            "harmless": stats["harmless"]
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
    if final_verdict in ["malicious", "suspicious"]:
     keyword = "remote code execution"
     cve_info = fetch_cves_by_keyword(keyword, max_results=3)
     result["cve_enrichment"] = cve_info

    return result

    