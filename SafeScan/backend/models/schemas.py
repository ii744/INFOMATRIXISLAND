"""
SafeScan Data Models

Pydantic schemas for API request validation and response serialization.
Every field has a clear English description for self-documenting API docs.
"""

from pydantic import BaseModel, Field
from typing import Optional


class URLScanRequest(BaseModel):
    """Request body for scanning a suspicious URL."""
    url: str = Field(
        ...,
        description="The suspicious URL to analyze",
        max_length=2048,
        examples=["https://suspicious-site.example.com/login"]
    )


class ThreatIntelResult(BaseModel):
    """Results from a single threat intelligence source."""
    source: str = Field(description="Name of the threat intel provider")
    is_known_threat: bool = Field(description="Whether this source flagged it")
    details: dict = Field(
        default_factory=dict,
        description="Raw details from the source"
    )
    error: Optional[str] = Field(
        default=None,
        description="Error message if this source failed"
    )


class AITransparencyLogEntry(BaseModel):
    """Single entry in the AI decision-making transparency log."""
    step: str = Field(description="What the AI system did at this step")
    detail: str = Field(description="Specifics of the action or data used")


class ScanResponse(BaseModel):
    """
    Unified response for both URL and file scans.
    Designed to give non-technical users a complete picture.
    """
    scan_type: str = Field(description="'url' or 'file'")
    target: str = Field(description="The URL or filename that was scanned")

    # --- Core AI Explanation (the product's main value) ---
    threat_level: str = Field(
        description="Overall assessment: 'safe', 'suspicious', or 'dangerous'"
    )
    confidence_percent: int = Field(
        description="How confident the AI is in its assessment (0-100)"
    )
    summary: str = Field(
        description="1-2 sentence plain English summary of the threat"
    )
    what_it_does: list[str] = Field(
        default_factory=list,
        description="Bullet points explaining what the threat does"
    )
    who_it_targets: str = Field(
        default="",
        description="Who is most at risk from this threat"
    )
    what_would_happen: str = Field(
        default="",
        description="What happens if the user opens/clicks this"
    )
    recommendation: str = Field(
        default="",
        description="What the user should do"
    )
    technical_details: str = Field(
        default="",
        description="Brief technical notes for advanced users"
    )

    # --- Responsible AI Indicators ---
    human_review_recommended: bool = Field(
        default=False,
        description="True when AI confidence is low — human should verify"
    )
    ai_transparency_log: list[AITransparencyLogEntry] = Field(
        default_factory=list,
        description="Step-by-step log of what the AI system checked"
    )

    # --- Raw Data ---
    threat_intel_results: list[ThreatIntelResult] = Field(
        default_factory=list,
        description="Results from each threat intelligence source"
    )
    metadata: dict = Field(
        default_factory=dict,
        description="URL metadata or file info depending on scan type"
    )
