"""
File Analyzer Service

Performs safe static analysis on uploaded files without executing them.
Uses subprocess calls (file, strings, xxd) with strict timeouts.
Extracts indicators of compromise through pattern matching.
"""

import logging
import math
import os
import re
import subprocess
import tempfile
from collections import Counter

from config import SANDBOX_TIMEOUT_SECONDS

logger = logging.getLogger("safescan.file_analyzer")

# Patterns that suggest malicious intent when found in extracted strings
SUSPICIOUS_PATTERNS = {
    "urls": re.compile(r"https?://[^\s\"'<>]{5,}", re.IGNORECASE),
    "ip_addresses": re.compile(
        r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
    ),
    "email_addresses": re.compile(
        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    ),
    "powershell_commands": re.compile(
        r"powershell|invoke-expression|iex|downloadstring",
        re.IGNORECASE,
    ),
    "registry_access": re.compile(
        r"HKEY_|RegOpenKey|RegSetValue", re.IGNORECASE
    ),
    "credential_access": re.compile(
        r"password|passwd|credential|login\.data|cookies\.sqlite",
        re.IGNORECASE,
    ),
    "base64_blobs": re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"),
    "shell_commands": re.compile(
        r"/bin/sh|/bin/bash|cmd\.exe|command\.com", re.IGNORECASE
    ),
    "network_operations": re.compile(
        r"socket|connect|recv|send|urllib|requests\.|wget|curl",
        re.IGNORECASE,
    ),
    "file_operations": re.compile(
        r"CreateFile|DeleteFile|WriteFile|fopen|os\.remove",
        re.IGNORECASE,
    ),
    "crypto_mining": re.compile(
        r"stratum\+tcp|cryptonight|monero|xmrig|coinhive",
        re.IGNORECASE,
    ),
    "anti_analysis": re.compile(
        r"IsDebuggerPresent|vmware|virtualbox|sandbox",
        re.IGNORECASE,
    ),
}


async def analyze_file(file_bytes: bytes, original_filename: str) -> dict:
    """
    Run static analysis on uploaded file bytes.
    Returns structured results for the AI to interpret.
    """
    analysis = {
        "filename": original_filename,
        "file_size_bytes": len(file_bytes),
        "file_type": "unknown",
        "mime_type": "unknown",
        "suspicious_indicators": [],
        "extracted_urls": [],
        "extracted_ips": [],
        "extracted_emails": [],
        "entropy": 0.0,
        "entropy_assessment": "normal",
        "hex_header": "",
        "string_analysis_summary": {},
        "error": None,
    }

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            delete=False, suffix=_safe_suffix(original_filename)
        ) as tmp:
            tmp.write(file_bytes)
            tmp_path = tmp.name

        analysis["file_type"] = _detect_file_type(tmp_path)
        analysis["mime_type"] = _detect_mime_type(tmp_path)
        analysis["hex_header"] = _read_hex_header(tmp_path)
        analysis["entropy"] = _calculate_entropy(file_bytes)
        analysis["entropy_assessment"] = _assess_entropy(
            analysis["entropy"]
        )

        extracted = _extract_strings(tmp_path)
        matches = _scan_for_patterns(extracted)

        analysis["extracted_urls"] = matches.get("urls", [])[:10]
        analysis["extracted_ips"] = matches.get("ip_addresses", [])[:10]
        analysis["extracted_emails"] = matches.get(
            "email_addresses", []
        )[:5]
        analysis["suspicious_indicators"] = _build_indicators(matches)
        analysis["string_analysis_summary"] = {
            cat: len(items) for cat, items in matches.items() if items
        }

    except Exception as exc:
        analysis["error"] = f"Analysis failed: {str(exc)}"
        logger.error("File analysis error: %s", exc)
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

    return analysis


def _safe_suffix(filename: str) -> str:
    """Extract file extension safely to prevent path traversal."""
    basename = os.path.basename(filename)
    _, ext = os.path.splitext(basename)
    if ext and len(ext) <= 10 and ext[1:].isalnum():
        return ext
    return ".bin"


def _detect_file_type(filepath: str) -> str:
    """Use the `file` command to identify file type."""
    try:
        result = subprocess.run(
            ["file", "--brief", filepath],
            capture_output=True, text=True,
            timeout=SANDBOX_TIMEOUT_SECONDS,
        )
        return result.stdout.strip() or "unknown"
    except subprocess.TimeoutExpired:
        return "analysis timed out"
    except Exception:
        return "detection failed"


def _detect_mime_type(filepath: str) -> str:
    """Use the `file` command with --mime for MIME type."""
    try:
        result = subprocess.run(
            ["file", "--brief", "--mime-type", filepath],
            capture_output=True, text=True,
            timeout=SANDBOX_TIMEOUT_SECONDS,
        )
        return result.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def _read_hex_header(filepath: str) -> str:
    """Read first 64 bytes as hex for magic number identification."""
    try:
        result = subprocess.run(
            ["xxd", "-l", "64", filepath],
            capture_output=True, text=True,
            timeout=SANDBOX_TIMEOUT_SECONDS,
        )
        return result.stdout.strip()
    except Exception:
        return "hex read failed"


def _extract_strings(filepath: str) -> str:
    """Use `strings` command to extract readable text."""
    try:
        result = subprocess.run(
            ["strings", "-n", "6", filepath],
            capture_output=True, text=True,
            timeout=SANDBOX_TIMEOUT_SECONDS,
        )
        return result.stdout[:500_000]
    except subprocess.TimeoutExpired:
        return ""
    except Exception:
        return ""


def _scan_for_patterns(text: str) -> dict:
    """Scan extracted strings for suspicious patterns."""
    matches = {}
    for category, pattern in SUSPICIOUS_PATTERNS.items():
        found = list(set(pattern.findall(text)))
        if found:
            matches[category] = found[:20]
    return matches


def _calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy. High entropy (>7.0) suggests
    encryption, compression, or packing — common in malware.
    """
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 2)


def _assess_entropy(entropy: float) -> str:
    """Interpret entropy value in human terms."""
    if entropy < 1.0:
        return "very low — likely empty or repetitive"
    if entropy < 5.0:
        return "normal — typical for text or code"
    if entropy < 7.0:
        return "moderate — compiled code or structured data"
    if entropy < 7.5:
        return "high — possibly compressed or encrypted"
    return "very high — likely encrypted or obfuscated"


def _build_indicators(pattern_matches: dict) -> list:
    """Convert pattern matches into readable indicator descriptions."""
    indicators = []
    mapping = {
        "powershell_commands": "Contains PowerShell commands",
        "registry_access": "References Windows Registry",
        "credential_access": "References passwords or credentials",
        "shell_commands": "Contains shell command references",
        "network_operations": "Contains network operation code",
        "crypto_mining": "Contains cryptocurrency mining refs",
        "anti_analysis": "Contains anti-analysis/sandbox detection",
        "base64_blobs": "Contains Base64-encoded data",
        "file_operations": "Contains file manipulation code",
    }
    for key, description in mapping.items():
        if pattern_matches.get(key):
            indicators.append(description)

    url_count = len(pattern_matches.get("urls", []))
    if url_count > 0:
        indicators.append(
            f"Contains {url_count} embedded URL(s)"
        )

    return indicators
