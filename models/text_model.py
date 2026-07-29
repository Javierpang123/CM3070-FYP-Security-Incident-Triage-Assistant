# Wrapper for Mistral 7B via Ollama.
# Accepts a security log string (JSON or plain text) and returns a standardised triage JSON object.

import json
import re
import requests
import logging
from typing import Union

logger = logging.getLogger(__name__)

# # Ollama local inference server endpoint runs entirely offline, no external API calls required
OLLAMA_URL = "http://localhost:11434/api/generate"

# Mistral 7B model identifier as registered in Ollama
MODEL_NAME = "mistral"

# ---------------------------------------------------------------------------
# MITRE ATT&CK tactic vocabulary used to score confidence (https://attack.mitre.org/)
# ---------------------------------------------------------------------------
ATTACK_TACTICS = ["Initial Access", "Execution", "Persistence",
                  "Privilege Escalation", "Defense Evasion", "Credential Access",
                  "Discovery", "Lateral Movement", "Collection", "Command and Control",
                  "Exfiltration", "Impact", "Reconnaissance", "Resource Development"]

# -----------------------------------------------------------------------------
# Prompt to instruct LLM to return a structured JSON object with specific keys.
# -----------------------------------------------------------------------------
SYSTEM_PROMPT = """ You are a cybersecurity analyst assistant specialising in Windows Event Log triage.

You will be given a security log entry or a JSON object containing Windows Event Log data.
Your task is to analyse it and return a JSON object - nothing else, no preamble, no markdown.

CLASSIFICATION PRINCIPLE
Classify by the intent and effect of the logged action, not by the mechanism that carried it out.
An event triggered by a normal administrative process or a successful logon is not automatically
"Execution", determine what the action actually changes or enables for the attacker.

COMMON EVENT ID / TACTIC ASSOCIATIONS (use as a guide, not a fixed rule. The actual log content always takes priority over this table):
    - 4794 (DSRM password set), 4723/4724 (password change/reset), 4776 (credential validation),
      4661/4663 (access to LSASS or SAM), credential-dumping tool names (e.g. mimikatz, procdump
      targeting lsass) -> Credential Access
    - 4648 (explicit credential logon to a remote host), 5140/5145 (remote share/file access) -> Lateral Movement
    - 4698/4699/4700/4701 (scheduled task created/modified), 7045 (new service installed),
      4720 (account created) -> Persistence
    - 4672 (special/admin privileges assigned to a logon), 4732/4728 (account added to a
      privileged group) -> Privilege Escalation
    - 4688 (new process created) paired with an unusual binary path or LOLBin
      (e.g. rundll32, regsvr32, powershell -enc), 4103/4104 (PowerShell script block logging) -> Execution
    - 4657 (registry value modified): autorun/persistence keys -> Persistence;
      security/audit-policy keys -> Defense Evasion
    - 1102 (audit log cleared), 4719 (audit policy changed) -> Defense Evasion
    - Unusual outbound connections/DNS lookups to rare or newly-seen domains -> Command and Control

WORKED EXAMPLES:

Example 1
Input log: Event ID 4794, "An attempt was made to set the Directory Services Restore Mode
administrator password", SubjectUserName: administrator, Workstation: 2016DC.
Correct output:{
  "attack_classification": "Credential Access",
  "severity": 4,
  "entities": ["administrator", "2016DC", "HQCORP"],
  "summary": "An attempt was made to reset the DSRM administrator password, establishing an alternate credential for domain controller access.",
  "confidence_hint": "high"}
Why: the event is logged under account management and carried out through a normal
administrative process, but its effect is to plant a usable credential. 
This is Credential Access, not Execution - do not classify credential-manipulation events as Execution just
because a routine process or logon triggered them.

Example 2
Input log: Event ID 4698, "A scheduled task was created", TaskName: \\Microsoft\\Windows\\UpdateHealth,
Command: powershell.exe -enc <base64>, trigger: at system startup.
Correct output:
{
  "attack_classification": "Persistence",
  "severity": 4,
  "entities": ["UpdateHealth", "powershell.exe"],
  "summary": "A scheduled task was created to run an encoded PowerShell command at startup, indicating an attempt to persist across reboots.",
  "confidence_hint": "high"
}
Why: creating the scheduled task is the mechanism for surviving a reboot, so the tactic is
Persistence - even though the payload itself (encoded PowerShell) would be Execution if it
were the standalone action being logged in isolation.

END EXAMPLES - now analyse the actual log entry given to you below using this same
intent-and-effect reasoning.

The JSON object must contain exactly these keys:
    - "attack_classification": the single most likely MITRE ATT&CK tactic name from this list:
    [Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion,
    Credential Access, Discovery, Lateral Movement, Collection, Command and Control,
    Exfiltration, Impact, Reconnaissance, Resource Development, Unknown]
    - "severity": an integer from 1 (informational) to 5 (critical)
    - "entities": a JSON array of strings - suspicious usernames, process names, IP addresses,
    file paths, or registry keys found in the log
    - "summary": a single sentence (max 30 words) describing what this log entry indicates
    - "confidence_hint": one of "high", "medium", or "low" - your confidence in the classification

Return only the JSON object. Do not include any other text."""

# Function to convert model's confidence hint and attack classification into a float score
def build_confidence(confidence_hint: str, attack_classification: str) -> float:
    
    # Convert model's qualitative confidence hint into a float score
    base = {"high": 0.85,
            "medium": 0.60, 
            "low": 0.35}.get(confidence_hint.lower(), 0.50)
    
    # Discount if the tactic is not in the known vocabulary.
    if attack_classification not in ATTACK_TACTICS:
        base = min(base, 0.40)
    return round(base, 2)

# ---------------------------------------------------------------------------
# Log input parsing and condensation
# ---------------------------------------------------------------------------

# Maximum number of events to keep when condensing a multi-event NDJSON
# log, to keep the prompt within the model's context window on incidents
# with very long event chains. If a log exceeds this, the most recent
# events are kept and the truncation is logged so it's visible during
# triage rather than silently dropping context.
MAX_EVENTS = 150


# Function to convert raw uploaded log file content into the log_input
# shape analyse_text() expects, handling single-event, multi-event array,
# and NDJSON (one JSON object per line) uploads.
def parse_log_input(raw_content: str) -> Union[str, dict]:
    """
    Handles three shapes of uploaded log content:
      1. A single JSON object (one Windows Event Log event) - returned as-is.
      2. A JSON array of event objects - condensed via condense_events().
      3. NDJSON - one JSON object per line, as produced by Winlogbeat's
         output.file for a full incident with many logged events -
         parsed line-by-line and condensed via condense_events().

    Falls back to the raw string only if none of the above parse, so a
    genuinely unstructured .txt/.log upload still reaches the model.
    """
    
    # Try whole file JSON parse first: covers a single event object, and
    # also a JSON array of events (as opposed to NDJSON's one-per-line).
    try:
        parsed = json.loads(raw_content)
        if isinstance(parsed, list):
            return condense_events(parsed)
        return parsed
    except json.JSONDecodeError:
        pass

    # Whole-file parse failed - try NDJSON (one JSON object per line).
    events = []
    for line in raw_content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            logger.warning("Skipping unparseable line in NDJSON log upload")
            continue

    if events:
        return condense_events(events)

    # Last resort: genuinely non-JSON content (plain-text .txt/.log upload).
    logger.warning("Log input did not parse as JSON, a JSON array, or NDJSON - "
                   "passing raw text to the model as a last resort.")
    return raw_content


# Function to reduce a list of full Winlogbeat/ECS event objects down to
# the fields that carry classification signal, 
# dropping verbose metadata that don't.
def condense_events(events: list) -> dict:
    """
    Keeps event ID, timestamp, action, host, and the already-structured
    winlog.event_data key/value pairs for each event. Drops the verbose
    human-readable 'message' field (which repeats lengthy static
    boilerplate - e.g. the Token Elevation Type explanation appears in
    full on every single 4688 process-creation event) and Beats/ECS
    wrapper metadata (agent, @metadata, ecs.version) that carries no
    security signal. This keeps multi-event incidents compact enough for
    the model to actually use the full event chain instead of losing the
    signal in repeated boilerplate text.
    """
    if len(events) > MAX_EVENTS:
        logger.warning(
            "Log has %d events - truncating to the most recent %d for the text model",
            len(events), MAX_EVENTS,
        )
        events = events[-MAX_EVENTS:]

    condensed = []
    for evt in events:
        if not isinstance(evt, dict):
            continue

        winlog = evt.get("winlog", {})
        if not isinstance(winlog, dict):
            winlog = {}

        event_info = evt.get("event", {})
        if not isinstance(event_info, dict):
            event_info = {}

        host_info = evt.get("host", {})
        if not isinstance(host_info, dict):
            host_info = {}

        condensed.append({
            "event_id": winlog.get("event_id") or event_info.get("code"),
            "timestamp": evt.get("@timestamp"),
            "action": event_info.get("action") or winlog.get("task"),
            "computer": winlog.get("computer_name") or host_info.get("name"),
            "event_data": winlog.get("event_data", {}),
        })

    return {"event_count": len(condensed), "events": condensed}

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

# Function to analyse text using Mistral 7B via Ollama and return a standardised result dict.
def analyse_text(log_input: Union[str, dict]) -> dict:
    """

    Parameters
    -------------------------------------------------------------------
    log_input : Raw log string or parsed JSON dict from EVTX pipeline.
    -------------------------------------------------------------------
    """
    # Normalise input to string for the prompt
    if isinstance(log_input, dict):
        log_str = json.dumps(log_input, indent=2)
    else:
        log_str = str(log_input)

    # Construct user prompt with the log content added
    prompt = f"Analyse this security log:\n\n{log_str}"

    # Build Ollama request payload with the system prompt and generation options
    ollama_payload = {"model": MODEL_NAME,
               "system": SYSTEM_PROMPT,
               "prompt": prompt,
               "stream": False,
               "options": {"temperature": 0.1,   # Low temp for consistent structured output
                           "num_predict": 400,   # Limit token generation to 400
                           "num_ctx": 32768} 
            }

    # Send the request to Ollama and handle connection-level failures gracefully
    try:
        response = requests.post(OLLAMA_URL, json = ollama_payload, timeout = 120)
        response.raise_for_status()
        raw_response = response.json().get("response", "")
        
    except requests.exceptions.ConnectionError:
        # Ollama process is not running or not reachable on the expected port
        logger.error("Ollama not reachable at %s", OLLAMA_URL)
        return error_result("Ollama service unreachable")
    
    except requests.exceptions.Timeout:
        # Model took too long to respond
        logger.error("Ollama request timed out")
        return error_result("Ollama request timed out")
    
    except Exception as e:
        # Catch unexpected errors to prevent the route from crashing
        logger.error("Unexpected error calling Ollama: %s", e)
        return error_result(str(e))

    # Attempt to extract a valid JSON object from the raw model response
    try:
        parsed = extract_json_from_response(raw_response)
    except ValueError as e:
        # Log warning on failed JSON extraction
        logger.warning("JSON extraction failed: %s", e)
        return error_result(f"JSON parse error: {e}", raw=raw_response)

    # Extract classification fields from the parsed response
    attack_cls = parsed.get("attack_classification", "Unknown")
    confidence_hint = parsed.get("confidence_hint", "low")
    
    # Convert qualitative confidence hint to a numeric score
    confidence = build_confidence(confidence_hint, attack_cls)

    # Return standardised wrapper output
    return {
        "model": "text",
        "confidence": confidence,
        "entities": parsed.get("entities", []),
        "attack_classification": attack_cls,
        "severity": int(parsed.get("severity", 1)),
        "summary": parsed.get("summary", ""),
        "raw": raw_response, # Preserve raw model output
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
