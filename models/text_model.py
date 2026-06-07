# Wrapper for Mistral 7B via Ollama.
# Accepts a security log string (JSON or plain text) and returns a standardised triage JSON object.

import json
import re
import requests
import logging
from typing import Union

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# MITRE ATT&CK tactic vocabulary used to score confidence
# ---------------------------------------------------------------------------
ATTACK_TACTICS = ["Initial Access", "Execution", "Persistence",
                  "Privilege Escalation", "Defense Evasion", "Credential Access",
                  "Discovery", "Lateral Movement", "Collection", "Command and Control",
                  "Exfiltration", "Impact", "Reconnaissance", "Resource Development"]

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "mistral"

# Prompt to instruct LLM to return a structured JSON object with specific keys.
SYSTEM_PROMPT = """ You are a cybersecurity analyst assistant specialising in Windows Event Log triage.

You will be given a security log entry or a JSON object containing Windows Event Log data.
Your task is to analyse it and return a JSON object — nothing else, no preamble, no markdown.

The JSON object must contain exactly these keys:
    - "attack_classification": the single most likely MITRE ATT&CK tactic name from this list:
    [Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion,
    Credential Access, Discovery, Lateral Movement, Collection, Command and Control,
    Exfiltration, Impact, Reconnaissance, Resource Development, Unknown]
    - "severity": an integer from 1 (informational) to 5 (critical)
    - "entities": a JSON array of strings — suspicious usernames, process names, IP addresses,
    file paths, or registry keys found in the log
    - "summary": a single sentence (max 30 words) describing what this log entry indicates
    - "confidence_hint": one of "high", "medium", or "low" — your confidence in the classification

Return only the JSON object. Do not include any other text."""

# Function to convert the model's confidence hint and attack classification into a float score
def build_confidence(confidence_hint: str, attack_classification: str) -> float:
    
    # Convert the model's qualitative confidence hint into a float score
    base = {"high": 0.85, "medium": 0.60, "low": 0.35}.get(
        confidence_hint.lower(), 0.50
    )
    # Discount if the tactic is not in the known vocabulary.
    if attack_classification not in ATTACK_TACTICS:
        base = min(base, 0.40)
    return round(base, 2)

# Function to robustly extract JSON from the model's response, 
# handling cases where it may be wrapped in markdown or contain extraneous text
def extract_json_from_response(raw: str) -> dict:
    """
    Robustly extract the first valid JSON object from the model response.
    Mistral sometimes wraps output in markdown fences despite instructions.
    """
    # Strip markdown fences if present
    cleaned = re.sub(r"```(?:json)?", "", raw).strip()

    # Try direct parse first
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    # Find the first {...} block
    match = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass

    raise ValueError(f"Could not extract valid JSON from model response: {raw[:200]}")

# Function to analyse text and return a standardised result dict.
def analyse_text(log_input: Union[str, dict]) -> dict:
    """
    Analyse a security log using Mistral 7B via Ollama.

    Parameters
    -------------------------------------------------------------------
    log_input : Raw log string or parsed JSON dict from EVTX pipeline.
    -------------------------------------------------------------------

    Returns following dictionary (standardised wrapper output):
    
        Standardised wrapper output:
        {
            "model": "text",
            "confidence": float,
            "entities": list[str],
            "summary": str,
            "raw": str   # raw model response
        }
    """
    # Normalise input to string for the prompt
    if isinstance(log_input, dict):
        log_str = json.dumps(log_input, indent=2)
    else:
        log_str = str(log_input)

    prompt = f"Analyse this security log:\n\n{log_str}"

    payload = {
        "model": MODEL_NAME,
        "system": SYSTEM_PROMPT,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.1,   # Low temp for consistent structured output
            "num_predict": 400,
        },
    }

    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=120)
        response.raise_for_status()
        raw_response = response.json().get("response", "")
    except requests.exceptions.ConnectionError:
        logger.error("Ollama not reachable at %s", OLLAMA_URL)
        return error_result("Ollama service unreachable")
    except requests.exceptions.Timeout:
        logger.error("Ollama request timed out")
        return error_result("Ollama request timed out")
    except Exception as e:
        logger.error("Unexpected error calling Ollama: %s", e)
        return error_result(str(e))

    try:
        parsed = extract_json_from_response(raw_response)
    except ValueError as e:
        logger.warning("JSON extraction failed: %s", e)
        return error_result(f"JSON parse error: {e}", raw=raw_response)

    attack_cls = parsed.get("attack_classification", "Unknown")
    confidence_hint = parsed.get("confidence_hint", "low")
    confidence = build_confidence(confidence_hint, attack_cls)

    return {
        "model": "text",
        "confidence": confidence,
        "entities": parsed.get("entities", []),
        "summary": parsed.get("summary", ""),
        "attack_classification": attack_cls,
        "severity": int(parsed.get("severity", 1)),
        "raw": raw_response,
    }

# Return a safe fallback result on failure, with an error message in the summary and zero confidence
def error_result(message: str, raw: str = "") -> dict:

    return {"model": "text",
            "confidence": 0.0,
            "entities": [],
            "summary": f"[ERROR] {message}",
            "attack_classification": "Unknown",
            "severity": 1,
            "raw": raw}
