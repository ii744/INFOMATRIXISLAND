"""
AI Explanation Engine — Gemini Integration

Converts technical threat data into plain-language explanations.
Uses Google Gemini (free tier) to generate human-friendly security assessments.
Every AI call is transparently logged for responsible AI compliance.
"""

import json
import logging
import time

from google import genai

from config import GEMINI_API_KEY, GEMINI_MODEL_NAME, HUMAN_REVIEW_THRESHOLD_PERCENT

logger = logging.getLogger("safescan.ai_explainer")

# Initialize Gemini client at module level
_client = None


def _get_client():
    """Lazy-initialize the Gemini client to avoid import-time errors."""
    global _client
    if _client is None and GEMINI_API_KEY:
        _client = genai.Client(api_key=GEMINI_API_KEY)
    return _client


# System instruction shared by both URL and file analysis prompts
SYSTEM_INSTRUCTION = """You are SafeScan, a cybersecurity expert who explains threats to non-technical users.
You speak simply, clearly, and specifically. Never use unexplained jargon.

IMPORTANT RULES:
1. Be SPECIFIC — not "this is malicious" but "this file tries to read your Chrome saved passwords and send them to a server in Russia"
2. State uncertainty clearly — if you're not sure, say so
3. If your confidence is below 60%, set human_review_recommended to true
4. Never make a final safety verdict alone — you explain, the human decides
5. Base your analysis ONLY on the data provided — do not hallucinate threats

You MUST respond with ONLY a valid JSON object (no markdown, no code fences) containing these fields:
{
  "threat_level": "safe" | "suspicious" | "dangerous",
  "confidence_percent": <number 0-100>,
  "summary": "<1-2 sentence plain English summary>",
  "what_it_does": ["<bullet point 1>", "<bullet point 2>"],
  "who_it_targets": "<who is most at risk>",
  "what_would_happen": "<what happens if user opens/clicks it>",
  "recommendation": "<what the user should do>",
  "technical_details": "<brief technical notes for advanced users>"
}"""


async def explain_url_threat(url: str, metadata: dict, threat_intel: list) -> dict:
    """Generate a plain-language explanation of a URL threat."""
    user_prompt = f"""Analyze this URL for security threats:

URL: {url}
Domain: {metadata.get('domain', 'unknown')}
Final URL after redirects: {metadata.get('final_url', url)}
Redirect chain: {json.dumps(metadata.get('redirect_chain', []))}
Page title: {metadata.get('page_title', 'unknown')}
SSL info: {json.dumps(metadata.get('ssl_info', {}))}
Server: {metadata.get('server', 'unknown')}
Content type: {metadata.get('content_type', 'unknown')}
Metadata errors: {metadata.get('error', 'none')}

Threat intelligence results:
{json.dumps(threat_intel, indent=2)}

Based on all this data, explain what this URL does and whether it's safe."""

    return await _generate_explanation(user_prompt, "url", url)


async def explain_file_threat(file_info: dict, analysis: dict, threat_intel: list) -> dict:
    """Generate a plain-language explanation of a file threat."""
    user_prompt = f"""Analyze this file for security threats:

Filename: {file_info.get('filename', 'unknown')}
File size: {file_info.get('size_bytes', 0)} bytes
SHA-256: {file_info.get('sha256', 'unknown')}

Static analysis results:
- File type: {analysis.get('file_type', 'unknown')}
- MIME type: {analysis.get('mime_type', 'unknown')}
- Entropy: {analysis.get('entropy', 0)} ({analysis.get('entropy_assessment', 'unknown')})
- Suspicious indicators: {json.dumps(analysis.get('suspicious_indicators', []))}
- Embedded URLs found: {json.dumps(analysis.get('extracted_urls', [])[:5])}
- Embedded IPs found: {json.dumps(analysis.get('extracted_ips', [])[:5])}
- Embedded emails: {json.dumps(analysis.get('extracted_emails', [])[:3])}
- Pattern match summary: {json.dumps(analysis.get('string_analysis_summary', {}))}

Threat intelligence (hash lookup):
{json.dumps(threat_intel, indent=2)}

Based on all this data, explain what this file does and whether it's safe."""

    return await _generate_explanation(user_prompt, "file", file_info.get("filename", "unknown"))


async def _generate_explanation(user_prompt: str, scan_type: str, target: str) -> dict:
    """
    Core function that calls Gemini and parses the structured response.
    Returns the AI explanation dict with transparency logging.
    """
    transparency_log = []
    start_time = time.time()

    transparency_log.append({
        "step": "Preparing AI analysis",
        "detail": f"Compiled {scan_type} scan data for {target}",
    })

    client = _get_client()
    if not client:
        return _fallback_response(
            "AI analysis unavailable — Gemini API key not configured",
            transparency_log,
        )

    try:
        transparency_log.append({
            "step": "Calling Gemini AI",
            "detail": f"Model: {GEMINI_MODEL_NAME}, sending compiled threat data for analysis",
        })

        response = client.models.generate_content(
            model=GEMINI_MODEL_NAME,
            contents=user_prompt,
            config=genai.types.GenerateContentConfig(
                system_instruction=SYSTEM_INSTRUCTION,
                temperature=0.3,
                max_output_tokens=1024,
            ),
        )

        elapsed = round(time.time() - start_time, 2)

        transparency_log.append({
            "step": "AI response received",
            "detail": f"Response generated in {elapsed}s using {GEMINI_MODEL_NAME}",
        })

        # Parse the JSON response from Gemini
        explanation = _parse_ai_response(response.text)

        # Enforce human review threshold
        confidence = explanation.get("confidence_percent", 50)
        if confidence < HUMAN_REVIEW_THRESHOLD_PERCENT:
            explanation["human_review_recommended"] = True
            transparency_log.append({
                "step": "Human review flagged",
                "detail": f"Confidence {confidence}% is below {HUMAN_REVIEW_THRESHOLD_PERCENT}% threshold",
            })
        else:
            explanation["human_review_recommended"] = False

        explanation["ai_transparency_log"] = transparency_log
        return explanation

    except Exception as exc:
        logger.error("Gemini API error: %s", exc)
        transparency_log.append({
            "step": "AI error",
            "detail": f"Gemini API call failed: {str(exc)}",
        })
        return _fallback_response(str(exc), transparency_log)


def _parse_ai_response(response_text: str) -> dict:
    """Parse JSON from Gemini response, handling common formatting issues."""
    cleaned = response_text.strip()

    # Remove markdown code fences if present
    if cleaned.startswith("```"):
        lines = cleaned.split("\n")
        # Remove first and last lines (the fences)
        lines = [l for l in lines if not l.strip().startswith("```")]
        cleaned = "\n".join(lines)

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        # Try to extract JSON from the response
        start = cleaned.find("{")
        end = cleaned.rfind("}") + 1
        if start != -1 and end > start:
            try:
                return json.loads(cleaned[start:end])
            except json.JSONDecodeError:
                pass

        # If all parsing fails, return a structured fallback
        return {
            "threat_level": "suspicious",
            "confidence_percent": 30,
            "summary": "AI generated a response but it could not be parsed into structured format.",
            "what_it_does": ["Analysis was inconclusive — raw AI response available in technical details"],
            "who_it_targets": "Unknown",
            "what_would_happen": "Unknown — exercise caution",
            "recommendation": "Have a security professional review this manually",
            "technical_details": f"Raw AI response: {response_text[:500]}",
        }


def _fallback_response(error_message: str, transparency_log: list) -> dict:
    """Return a safe fallback when AI is unavailable."""
    return {
        "threat_level": "suspicious",
        "confidence_percent": 0,
        "summary": f"AI analysis could not be completed: {error_message}",
        "what_it_does": ["Automated analysis was unavailable — manual review required"],
        "who_it_targets": "Cannot determine without AI analysis",
        "what_would_happen": "Cannot determine — treat with caution",
        "recommendation": "Do not open this until a security professional can review it",
        "technical_details": f"AI error: {error_message}",
        "human_review_recommended": True,
        "ai_transparency_log": transparency_log,
    }
