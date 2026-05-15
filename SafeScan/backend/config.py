"""
SafeScan Configuration Module

Loads environment variables and defines application-wide constants.
All secrets come from environment variables — never hardcoded.
"""

import os
import logging
from dotenv import load_dotenv

# Load .env file from project root (one level up from backend/)
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "..", ".env"))

logger = logging.getLogger("safescan")

# --- API Keys (loaded from environment) ---
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
URLHAUS_AUTH_KEY = os.getenv("URLHAUS_AUTH_KEY", "")

# --- Application Constants ---
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB upload limit
SANDBOX_TIMEOUT_SECONDS = 5             # Max time for any subprocess call
MAX_URL_LENGTH = 2048                   # Reject URLs longer than this
API_REQUEST_TIMEOUT_SECONDS = 10        # Timeout for external API calls
MAX_RESPONSE_BODY_BYTES = 1024 * 1024   # 1 MB max when fetching URL content

# --- Gemini Model Configuration ---
GEMINI_MODEL_NAME = "gemini-2.0-flash"

# --- Confidence Thresholds ---
HUMAN_REVIEW_THRESHOLD_PERCENT = 60  # Below this → recommend human review


def validate_api_keys():
    """Log which API integrations are available at startup."""
    available = []
    missing = []

    if GEMINI_API_KEY:
        available.append("Gemini AI")
    else:
        missing.append("Gemini AI (GEMINI_API_KEY)")

    if VIRUSTOTAL_API_KEY:
        available.append("VirusTotal")
    else:
        missing.append("VirusTotal (VIRUSTOTAL_API_KEY)")

    if URLHAUS_AUTH_KEY:
        available.append("URLhaus")
    else:
        missing.append("URLhaus (URLHAUS_AUTH_KEY)")

    if available:
        logger.info("Available integrations: %s", ", ".join(available))
    if missing:
        logger.warning("Missing API keys for: %s", ", ".join(missing))

    return {"available": available, "missing": missing}
