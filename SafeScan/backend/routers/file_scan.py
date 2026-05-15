"""
File Scan Router

Handles file upload analysis — validates the upload, runs static analysis,
checks hash against threat intel, then AI explains the findings.
"""

import logging

from fastapi import APIRouter, UploadFile, File, HTTPException

from models.schemas import ScanResponse
from services.file_analyzer import analyze_file
from services.threat_intel import (
    check_file_hash_with_virustotal,
    compute_file_sha256,
    compute_file_md5,
)
from services.ai_explainer import explain_file_threat
from config import MAX_FILE_SIZE_BYTES

logger = logging.getLogger("safescan.router.file")
router = APIRouter(prefix="/api", tags=["File Scanning"])


@router.post("/scan/file", response_model=ScanResponse)
async def scan_file(file: UploadFile = File(...)):
    """
    Analyze an uploaded file for security threats.
    The file is analyzed statically (never executed) and explained in plain English.
    """
    # --- Input Validation ---
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file was uploaded")

    # Read file bytes with size limit enforcement
    file_bytes = await _read_file_with_limit(file)

    # --- Step 1: Compute hashes for threat intel lookup ---
    sha256_hash = compute_file_sha256(file_bytes)
    md5_hash = compute_file_md5(file_bytes)

    file_info = {
        "filename": file.filename,
        "size_bytes": len(file_bytes),
        "sha256": sha256_hash,
        "md5": md5_hash,
    }

    # --- Step 2: Static file analysis (strings, entropy, patterns) ---
    analysis_results = await analyze_file(file_bytes, file.filename)

    # --- Step 3: Check file hash against VirusTotal ---
    vt_result = await check_file_hash_with_virustotal(sha256_hash)
    threat_intel_results = [vt_result]

    # --- Step 4: AI Explanation ---
    ai_explanation = await explain_file_threat(
        file_info, analysis_results, threat_intel_results
    )

    # --- Step 5: Build response ---
    return ScanResponse(
        scan_type="file",
        target=file.filename,
        threat_level=ai_explanation.get("threat_level", "suspicious"),
        confidence_percent=ai_explanation.get("confidence_percent", 0),
        summary=ai_explanation.get("summary", "Analysis could not be completed"),
        what_it_does=ai_explanation.get("what_it_does", []),
        who_it_targets=ai_explanation.get("who_it_targets", ""),
        what_would_happen=ai_explanation.get("what_would_happen", ""),
        recommendation=ai_explanation.get("recommendation", ""),
        technical_details=ai_explanation.get("technical_details", ""),
        human_review_recommended=ai_explanation.get("human_review_recommended", True),
        ai_transparency_log=ai_explanation.get("ai_transparency_log", []),
        threat_intel_results=threat_intel_results,
        metadata={
            "file_info": file_info,
            "static_analysis": {
                "file_type": analysis_results.get("file_type", "unknown"),
                "mime_type": analysis_results.get("mime_type", "unknown"),
                "entropy": analysis_results.get("entropy", 0),
                "entropy_assessment": analysis_results.get("entropy_assessment", ""),
                "suspicious_indicators": analysis_results.get("suspicious_indicators", []),
            },
        },
    )


async def _read_file_with_limit(file: UploadFile) -> bytes:
    """Read uploaded file enforcing the size limit to prevent abuse."""
    file_bytes = await file.read()

    if len(file_bytes) > MAX_FILE_SIZE_BYTES:
        max_mb = MAX_FILE_SIZE_BYTES // (1024 * 1024)
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds maximum size of {max_mb} MB",
        )

    if len(file_bytes) == 0:
        raise HTTPException(
            status_code=400,
            detail="Uploaded file is empty",
        )

    return file_bytes
