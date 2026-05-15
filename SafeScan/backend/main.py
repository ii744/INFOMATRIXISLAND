"""
SafeScan — AI-Powered Threat Analyzer
Main application entry point.

Assembles the FastAPI app, registers routes, serves the frontend,
and validates configuration at startup.
"""

import logging
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from config import validate_api_keys
from routers.url_scan import router as url_scan_router
from routers.file_scan import router as file_scan_router

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("safescan")

# --- App Initialization ---
app = FastAPI(
    title="SafeScan",
    description="AI-powered file and URL threat analyzer that explains risks in plain English",
    version="1.0.0",
)

# Allow frontend to call the API (for development flexibility)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Route Registration ---
app.include_router(url_scan_router)
app.include_router(file_scan_router)

# --- Static Files (Frontend) ---
frontend_dir = os.path.join(os.path.dirname(__file__), "..", "frontend")
app.mount("/static", StaticFiles(directory=frontend_dir), name="static")


@app.get("/")
async def serve_frontend():
    """Serve the single-page frontend application."""
    return FileResponse(os.path.join(frontend_dir, "index.html"))


@app.get("/health")
async def health_check():
    """Health check endpoint — also reports which integrations are available."""
    api_status = validate_api_keys()
    return {
        "status": "healthy",
        "service": "SafeScan",
        "integrations": api_status,
    }


@app.on_event("startup")
async def startup_event():
    """Log configuration status when the server starts."""
    logger.info("SafeScan starting up...")
    validate_api_keys()
    logger.info("SafeScan ready — serving on http://localhost:8000")
