import requests
from datetime import datetime

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TIMEOUT = 10


def fetch_cves_by_keyword(keyword: str, max_results: int = 5):
    """
    Fetch CVEs from NVD API based on a keyword.
    Returns structured CVE data.
    """

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results
    }

    try:
        response = requests.get(NVD_API_URL, params=params, timeout=TIMEOUT)
        response.raise_for_status()

        data = response.json()

        cve_list = []

        for item in data.get("vulnerabilities", []):
            cve_data = item.get("cve", {})

            cve_id = cve_data.get("id")

            # Description
            descriptions = cve_data.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d["lang"] == "en"),
                "No description available"
            )

            # CVSS score (v3 preferred)
            metrics = cve_data.get("metrics", {})
            cvss_score = None

            if "cvssMetricV31" in metrics:
                cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV30" in metrics:
                cvss_score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]

            cve_list.append({
                "id": cve_id,
                "description": description,
                "cvss_score": cvss_score
            })

        return {
            "count": len(cve_list),
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "cves": cve_list
        }

    except requests.exceptions.Timeout:
        return {
            "error": "NVD API timeout",
            "count": 0,
            "cves": []
        }

    except requests.exceptions.RequestException as e:
        return {
            "error": f"NVD API error: {str(e)}",
            "count": 0,
            "cves": []
        }
