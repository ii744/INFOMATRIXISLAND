"""
Threat Intelligence Service

Checks URLs and file hashes against URLhaus and VirusTotal databases.
Each function handles its own errors — a failing API never crashes the scan.
"""

import logging
import hashlib
from urllib.parse import quote

import httpx

from config import (
    VIRUSTOTAL_API_KEY,
    URLHAUS_AUTH_KEY,
    API_REQUEST_TIMEOUT_SECONDS,
)

logger = logging.getLogger("safescan.threat_intel")


async def check_url_with_urlhaus(url: str) -> dict:
    """
    Query URLhaus for known malicious URL data.
    Returns dict with 'is_known_threat', 'details', and optional 'error'.
    """
    result = {"source": "URLhaus", "is_known_threat": False, "details": {}, "error": None}

    try:
        async with httpx.AsyncClient(timeout=API_REQUEST_TIMEOUT_SECONDS) as client:
            headers = {}
            if URLHAUS_AUTH_KEY:
                headers["Auth-Key"] = URLHAUS_AUTH_KEY

            response = await client.post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                data={"url": url},
                headers=headers,
            )
            response.raise_for_status()
            data = response.json()

        # URLhaus returns "ok" when the URL is found in their database
        if data.get("query_status") == "ok":
            result["is_known_threat"] = True
            result["details"] = {
                "threat_type": data.get("threat", "unknown"),
                "url_status": data.get("url_status", "unknown"),
                "date_added": data.get("date_added", "unknown"),
                "tags": data.get("tags", []),
                "blacklists": data.get("blacklists", {}),
                "reporter": data.get("reporter", "unknown"),
                "payloads": _summarize_payloads(data.get("payloads", [])),
            }
        elif data.get("query_status") == "no_results":
            result["details"] = {"message": "URL not found in URLhaus database"}

    except httpx.TimeoutException:
        result["error"] = "URLhaus request timed out"
        logger.warning("URLhaus API timed out for URL: %s", url)
    except Exception as exc:
        result["error"] = f"URLhaus lookup failed: {str(exc)}"
        logger.error("URLhaus API error: %s", exc)

    return result


def _summarize_payloads(payloads: list) -> list:
    """Extract key info from URLhaus payload data to keep response concise."""
    summaries = []
    for payload in payloads[:3]:  # Limit to 3 most relevant payloads
        summaries.append({
            "filename": payload.get("filename", "unknown"),
            "file_type": payload.get("file_type", "unknown"),
            "signature": payload.get("signature"),
            "virustotal_detection": payload.get("virustotal", {}).get("result") if payload.get("virustotal") else None,
        })
    return summaries


async def check_url_with_virustotal(url: str) -> dict:
    """
    Submit URL to VirusTotal for scanning and retrieve results.
    Free tier: 4 requests/minute, 500/day.
    """
    result = {"source": "VirusTotal", "is_known_threat": False, "details": {}, "error": None}

    if not VIRUSTOTAL_API_KEY:
        result["error"] = "VirusTotal API key not configured"
        return result

    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}

        async with httpx.AsyncClient(timeout=API_REQUEST_TIMEOUT_SECONDS) as client:
            # Step 1: Submit URL for analysis
            submit_response = await client.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
            )
            submit_response.raise_for_status()
            analysis_id = submit_response.json()["data"]["id"]

            # Step 2: Retrieve analysis results
            analysis_response = await client.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
            )
            analysis_response.raise_for_status()
            analysis_data = analysis_response.json()["data"]["attributes"]

        stats = analysis_data.get("stats", {})
        malicious_count = stats.get("malicious", 0)
        suspicious_count = stats.get("suspicious", 0)
        total_engines = sum(stats.values()) if stats else 0

        # Any engine flagging it as malicious means it's a known threat
        if malicious_count > 0 or suspicious_count > 0:
            result["is_known_threat"] = True

        result["details"] = {
            "malicious_engines": malicious_count,
            "suspicious_engines": suspicious_count,
            "total_engines": total_engines,
            "detection_ratio": f"{malicious_count}/{total_engines}",
            "status": analysis_data.get("status", "unknown"),
        }

    except httpx.TimeoutException:
        result["error"] = "VirusTotal request timed out"
        logger.warning("VirusTotal API timed out for URL: %s", url)
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 429:
            result["error"] = "VirusTotal rate limit exceeded (free tier: 4 req/min)"
        else:
            result["error"] = f"VirusTotal HTTP error: {exc.response.status_code}"
        logger.warning("VirusTotal HTTP error: %s", exc)
    except Exception as exc:
        result["error"] = f"VirusTotal lookup failed: {str(exc)}"
        logger.error("VirusTotal API error: %s", exc)

    return result


async def check_file_hash_with_virustotal(sha256_hash: str) -> dict:
    """
    Look up a file hash in VirusTotal's database.
    This doesn't upload the file — just checks if the hash is already known.
    """
    result = {"source": "VirusTotal", "is_known_threat": False, "details": {}, "error": None}

    if not VIRUSTOTAL_API_KEY:
        result["error"] = "VirusTotal API key not configured"
        return result

    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}

        async with httpx.AsyncClient(timeout=API_REQUEST_TIMEOUT_SECONDS) as client:
            response = await client.get(
                f"https://www.virustotal.com/api/v3/files/{sha256_hash}",
                headers=headers,
            )

            # 404 means the file hash is not in VirusTotal's database
            if response.status_code == 404:
                result["details"] = {"message": "File hash not found in VirusTotal database"}
                return result

            response.raise_for_status()
            attributes = response.json()["data"]["attributes"]

        stats = attributes.get("last_analysis_stats", {})
        malicious_count = stats.get("malicious", 0)
        suspicious_count = stats.get("suspicious", 0)
        total_engines = sum(stats.values()) if stats else 0

        if malicious_count > 0 or suspicious_count > 0:
            result["is_known_threat"] = True

        result["details"] = {
            "malicious_engines": malicious_count,
            "suspicious_engines": suspicious_count,
            "total_engines": total_engines,
            "detection_ratio": f"{malicious_count}/{total_engines}",
            "file_type": attributes.get("type_description", "unknown"),
            "popular_threat_name": attributes.get("popular_threat_classification", {}).get("suggested_threat_label", None),
            "tags": attributes.get("tags", [])[:5],
        }

    except httpx.TimeoutException:
        result["error"] = "VirusTotal request timed out"
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 429:
            result["error"] = "VirusTotal rate limit exceeded"
        else:
            result["error"] = f"VirusTotal HTTP error: {exc.response.status_code}"
    except Exception as exc:
        result["error"] = f"VirusTotal lookup failed: {str(exc)}"
        logger.error("VirusTotal file hash error: %s", exc)

    return result


def compute_file_sha256(file_bytes: bytes) -> str:
    """Compute SHA-256 hash of file contents for VirusTotal lookup."""
    return hashlib.sha256(file_bytes).hexdigest()


def compute_file_md5(file_bytes: bytes) -> str:
    """Compute MD5 hash of file contents (some APIs still use MD5)."""
    return hashlib.md5(file_bytes).hexdigest()
