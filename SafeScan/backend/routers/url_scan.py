"""
URL Scan Router

Handles the URL analysis endpoint — validates input, orchestrates
threat intel lookups + metadata fetch + AI explanation.
"""

import logging
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException

from models.schemas import URLScanRequest, ScanResponse
from services.threat_intel import check_url_with_urlhaus, check_url_with_virustotal
from services.url_metadata import fetch_url_metadata
from services.ai_explainer import explain_url_threat
from config import MAX_URL_LENGTH

logger = logging.getLogger("safescan.router.url")
router = APIRouter(prefix="/api", tags=["URL Scanning"])


@router.post("/scan/url", response_model=ScanResponse)
async def scan_url(request: URLScanRequest):
    """
    Analyze a suspicious URL for security threats.
    Returns a plain-language explanation of what the URL does.
    """
    url = request.url.strip()

    # --- Input Validation ---
    _validate_url(url)

    # --- Step 1: Gather data from all sources in parallel ---
    # (Using sequential calls to respect rate limits and simplify error handling)
    transparency_log = []

    transparency_log.append({
        "step": "URL received",
        "detail": f"Analyzing: {url}",
    })

    # Fetch URL metadata (title, redirects, SSL)
    transparency_log.append({
        "step": "Fetching URL metadata",
        "detail": "Checking page title, redirect chain, SSL certificate",
    })
    metadata = await fetch_url_metadata(url)

    # Check URLhaus threat database
    transparency_log.append({
        "step": "Checking URLhaus database",
        "detail": "Querying abuse.ch URLhaus for known malicious URL records",
    })
    urlhaus_result = await check_url_with_urlhaus(url)

    # Check VirusTotal
    transparency_log.append({
        "step": "Checking VirusTotal",
        "detail": "Submitting URL to VirusTotal for multi-engine scan",
    })
    vt_result = await check_url_with_virustotal(url)

    threat_intel_results = [urlhaus_result, vt_result]

    # --- Step 2: AI Explanation ---
    transparency_log.append({
        "step": "Generating AI explanation",
        "detail": "Sending all gathered data to Gemini for plain-language analysis",
    })
    ai_explanation = await explain_url_threat(url, metadata, threat_intel_results)

    # --- Step 3: Build response ---
    return ScanResponse(
        scan_type="url",
        target=url,
        threat_level=ai_explanation.get("threat_level", "suspicious"),
        confidence_percent=ai_explanation.get("confidence_percent", 0),
        summary=ai_explanation.get("summary", "Analysis could not be completed"),
        what_it_does=ai_explanation.get("what_it_does", []),
        who_it_targets=ai_explanation.get("who_it_targets", ""),
        what_would_happen=ai_explanation.get("what_would_happen", ""),
        recommendation=ai_explanation.get("recommendation", ""),
        technical_details=ai_explanation.get("technical_details", ""),
        human_review_recommended=ai_explanation.get("human_review_recommended", True),
        ai_transparency_log=ai_explanation.get("ai_transparency_log", transparency_log),
        threat_intel_results=threat_intel_results,
        metadata=metadata,
    )


def _validate_url(url: str):
    """Validate URL format and length before processing."""
    if len(url) > MAX_URL_LENGTH:
        raise HTTPException(
            status_code=400,
            detail=f"URL exceeds maximum length of {MAX_URL_LENGTH} characters",
        )

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(
            status_code=400,
            detail="URL must start with http:// or https://",
        )

    if not parsed.netloc:
        raise HTTPException(
            status_code=400,
            detail="URL must contain a valid domain name",
        )
