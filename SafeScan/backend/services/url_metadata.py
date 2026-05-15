"""
URL Metadata Service

Fetches metadata about a URL to help the AI understand what the page does.
Uses HEAD + limited GET requests — never executes JavaScript.
"""

import logging
import ssl
from urllib.parse import urlparse

import httpx

from config import API_REQUEST_TIMEOUT_SECONDS, MAX_RESPONSE_BODY_BYTES

logger = logging.getLogger("safescan.url_metadata")


async def fetch_url_metadata(url: str) -> dict:
    """
    Gather metadata about a URL without rendering the page.
    Returns title, redirect chain, SSL info, server headers, and domain info.
    """
    metadata = {
        "original_url": url,
        "final_url": url,
        "redirect_chain": [],
        "page_title": None,
        "server": None,
        "content_type": None,
        "ssl_info": None,
        "domain": _extract_domain(url),
        "error": None,
    }

    try:
        # follow_redirects=True so we can capture the full chain
        async with httpx.AsyncClient(
            timeout=API_REQUEST_TIMEOUT_SECONDS,
            follow_redirects=True,
            max_redirects=10,
            verify=False,  # Accept self-signed certs for analysis purposes
        ) as client:
            response = await client.get(
                url,
                headers={"User-Agent": "SafeScan/1.0 Security Analyzer"},
            )

            # Record the redirect chain (phishing sites often use many redirects)
            metadata["redirect_chain"] = [
                str(r.url) for r in response.history
            ]
            metadata["final_url"] = str(response.url)
            metadata["server"] = response.headers.get("server", "unknown")
            metadata["content_type"] = response.headers.get("content-type", "unknown")

            # Extract page title from HTML (limited body read)
            metadata["page_title"] = _extract_title(
                response.text[:MAX_RESPONSE_BODY_BYTES]
            )

        # Get SSL certificate info separately
        metadata["ssl_info"] = _get_ssl_info(url)

    except httpx.TooManyRedirects:
        metadata["error"] = "Too many redirects (>10) — common in phishing"
        metadata["redirect_chain"].append("... exceeded redirect limit")
    except httpx.TimeoutException:
        metadata["error"] = "URL request timed out — site may be down or slow"
    except Exception as exc:
        metadata["error"] = f"Could not fetch URL: {str(exc)}"
        logger.warning("URL metadata fetch failed for %s: %s", url, exc)

    return metadata


def _extract_domain(url: str) -> str:
    """Pull the domain name from a URL for display purposes."""
    try:
        parsed = urlparse(url)
        return parsed.netloc or parsed.path.split("/")[0]
    except Exception:
        return "unknown"


def _extract_title(html_content: str) -> str | None:
    """Extract the <title> tag content from raw HTML."""
    try:
        lower = html_content.lower()
        start = lower.find("<title")
        if start == -1:
            return None

        # Find the closing > of the opening tag
        tag_end = lower.find(">", start)
        if tag_end == -1:
            return None

        # Find </title>
        end = lower.find("</title>", tag_end)
        if end == -1:
            return None

        title = html_content[tag_end + 1:end].strip()
        # Limit length to prevent abuse
        return title[:200] if title else None
    except Exception:
        return None


def _get_ssl_info(url: str) -> dict | None:
    """Check SSL certificate validity for HTTPS URLs."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return {"has_ssl": False, "note": "Site does not use HTTPS encryption"}

    try:
        hostname = parsed.hostname
        port = parsed.port or 443
        context = ssl.create_default_context()
        with ssl.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return {
                    "has_ssl": True,
                    "issuer": _format_cert_field(cert.get("issuer", [])),
                    "subject": _format_cert_field(cert.get("subject", [])),
                    "valid_from": cert.get("notBefore", "unknown"),
                    "valid_until": cert.get("notAfter", "unknown"),
                }
    except ssl.SSLCertVerificationError as exc:
        return {"has_ssl": True, "valid": False, "error": f"Invalid certificate: {exc}"}
    except Exception:
        return {"has_ssl": False, "note": "Could not verify SSL certificate"}


def _format_cert_field(field_tuples: list) -> str:
    """Convert SSL certificate field tuples into a readable string."""
    try:
        parts = []
        for entry in field_tuples:
            for key, value in entry:
                parts.append(f"{key}={value}")
        return ", ".join(parts)
    except Exception:
        return "unknown"
