# Late fusion orchestrator for Flashpoint.

"""
Combines standardised outputs from the three model wrappers using
fixed weights (text=0.5, vision=0.3, speech=0.2) to produce a single
triage result.
"""

"""
Fusion strategy: 
weighted voting across modalities for ATT&CK classification and severity, 
with confidence-gated weight redistribution when a modality is absent or failed.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Fixed fusion weights
BASE_WEIGHTS = {"text": 0.5,
                "vision": 0.3,
                "speech": 0.2}

# ---------------------------------------------------------------------------
# MITRE ATT&CK tactic mapped to their respective recommended actions 
# ---------------------------------------------------------------------------
RECOMMENDED_ACTIONS = {
    "Initial Access": [
        "Block the source IP address at the perimeter firewall.",
        "Reset credentials for any accounts involved in failed authentications.",
        "Review VPN and remote access logs for the affected timeframe.",
    ],
    "Execution": [
        "Isolate the affected host from the network immediately.",
        "Capture a memory dump of the affected process before termination.",
        "Review parent-child process relationships in endpoint logs.",
    ],
    "Persistence": [
        "Audit scheduled tasks, registry run keys, and startup folders on affected host.",
        "Remove identified persistence mechanisms and verify removal.",
        "Check for additional hosts with the same persistence artefact.",
    ],
    "Privilege Escalation": [
        "Revoke elevated privileges on the affected account immediately.",
        "Audit recent privilege changes in Active Directory.",
        "Review UAC and token manipulation events (Event IDs 4672, 4673).",
    ],
    "Defense Evasion": [
        "Restore and review tampered or cleared event logs.",
        "Check for disabled security tools or modified audit policies.",
        "Escalate to senior analyst — active attacker likely present.",
    ],
    "Credential Access": [
        "Immediately reset all credentials for accounts on the affected host.",
        "Check for LSASS access events (Event ID 4656, 10) and memory dumps.",
        "Enable additional monitoring on privileged accounts across the domain.",
    ],
    "Discovery": [
        "Flag the source account/host for elevated monitoring.",
        "Review network scan logs and correlate with other suspicious activity.",
        "Check whether discovery activity preceded lateral movement attempts.",
    ],
    "Lateral Movement": [
        "Isolate all hosts involved in lateral movement.",
        "Audit SMB, WMI, and remote service activity across the network.",
        "Identify the original entry point and scope of compromise.",
    ],
    "Collection": [
        "Identify what data was accessed or staged.",
        "Check for compression or archiving tools used on sensitive directories.",
        "Review DLP alerts for the affected timeframe.",
    ],
    "Exfiltration": [
        "Block outbound connections to identified exfiltration endpoints.",
        "Quantify and document the data involved for breach notification assessment.",
        "Engage legal and compliance teams immediately.",
    ],
    "Command and Control": [
        "Block identified C2 domains and IPs at DNS and firewall level.",
        "Search for the same C2 indicators across all endpoints.",
        "Capture network traffic for forensic analysis.",
    ],
    "Impact": [
        "Activate incident response plan and engage IR team.",
        "Isolate affected systems and begin damage assessment.",
        "Preserve all available forensic artefacts before remediation.",
    ],
    "Reconnaissance": [
        "Log and monitor the source for follow-on activity.",
        "Review exposed attack surface that may have been probed.",
        "No immediate containment required — maintain elevated vigilance.",
    ],
    "Resource Development": [
        "Monitor for follow-on intrusion attempts from identified infrastructure.",
        "Share indicators with threat intelligence feeds.",
        "No immediate internal containment required.",
    ],
    "Unknown": [
        "Review the raw log and model outputs manually.",
        "Escalate to a senior analyst for further investigation.",
        "Collect additional context before taking containment action.",
    ],
}


# ---------------------------------------------------------------------------
# CORE FUSION LOGIC FUNCTIONS 
# ---------------------------------------------------------------------------

# Function to compute effective fusion weights based on which modalities are present and
# have non-zero confidence. Absent or failed modalities (confidence=0.0)
# are dropped and their weight redistributed proportionally.
def redistribute_weights(results: dict) -> dict:
    
    # Identify active modalities with non-zero confidence
    active = {modality: BASE_WEIGHTS[modality]
              for modality, result in results.items()
                if result is not None and result.get("confidence", 0.0) > 0.0}

    # If no active modalities, return empty weights 
    if not active:
        return {}

    # Normalize remaining weights to sum to 1 
    total = sum(active.values())
    
    # Return normalized weights rounded to 4 decimal places
    return {modality: round(weight / total, 4) for modality, weight in active.items()}

# Function to fuse severity scores using a weighted average of per-modality severity,
def fuse_severity(results: dict, weights: dict) -> int:
    
    # If no weights meaning all modalities failed, default to lowest severity 1 
    if not weights:
        return 1

    # Compute weighted average severity across active modalities, rounding to nearest integer
    weighted_sum = sum(results[mod]["severity"] * weight
                       for mod, weight in weights.items()
                            if results.get(mod) is not None)
    
    # Return severity and ensure its between 1 and 5
    return int(round(min(5, max(1, weighted_sum))))

# Function to fuse ATT&CK classifications using weighted voting across modalities.
def fuse_attack_classification(results: dict, weights: dict) -> str:
    """
    Each modality casts a vote weighted by its effective fusion weight
    multiplied by its confidence score.
    """
    
    # If no weights meaning all modalities failed, return "Unknown" classification
    if not weights:
        return "Unknown"

    # Tally weighted votes for each tactic across active modalities
    tactic_scores = {}
    for mod, weight in weights.items():
        result = results.get(mod)
        
        # If result is None, skip the modality
        if result is None:
            continue
        
        # Extract the attack classification and confidence, 
        # defaulting to "Unknown" and 0.0 if missing
        tactic = result.get("attack_classification", "Unknown")
        confidence = result.get("confidence", 0.0)
        vote = weight * confidence
        tactic_scores[tactic] = tactic_scores.get(tactic, 0.0) + vote

    # If no tactic scores retrieved then we return "Unknown"
    if not tactic_scores:
        return "Unknown"

    # If Unknown is the only or dominant classification, return it
    best_classification = max(tactic_scores, key=tactic_scores.get)
    return best_classification

# Function to fuse entities by taking the union of all entities across modalities.
def fuse_entities(results: dict) -> list:
    
    # Use a set to track seen entities and preserve order in the final list
    seen = set()
    
    # Iterate through results in modality order and add unique entities to the final list
    entities = []
    for result in results.values():
        
        # If result is None, skip to the next modality
        if result is None:
            continue
        
        # Add entities from this modality to the final list if they haven't been seen before
        for entity in result.get("entities", []):
            if entity not in seen:
                seen.add(entity)
                entities.append(entity)
    # Return list of unique entities across all modalities
    return entities

# Function to compute overall confidence score for fused result 
# as a weighted average of per-modality confidence scores.
def fused_confidence(results: dict, weights: dict) -> float:
    
    # If no weights meaning all modalities failed, return 0.0 confidence
    if not weights:
        return 0.0
    
    # Compute weighted average confidence across active modalities
    score = sum(results[mod]["confidence"] * weight
                for mod, weight in weights.items()
                    if results.get(mod) is not None)
    
    # Ensure confidence is between 0.0 and 1.0, then round to 2 decimal places
    return round(score, 2)



# Function to fuse outputs from the three model wrappers into a single triage result
# Parameters:
# text_result : dict or None (Output from models.text_model.analyse_text())
# vision_result : dict or None (Output from models.vision_model.analyse_image())
# speech_result : dict or None (Output from models.speech_model.analyse_audio())
def late_fusion_orchestrator(text_result: Optional[dict] = None,
         vision_result: Optional[dict] = None,
         speech_result: Optional[dict] = None) -> dict:
    
    # Store results into a single dict for processing easier
    results = {"text": text_result,
               "vision": vision_result,
               "speech": speech_result}

    # Validate that at least one modality is here
    # Any combination of modalities will accepted — absent modalities should be
    # passed as None and their weight is redistributed to active modalities.
    if all(r is None for r in results.values()):
        logger.error("fuse() called with no modality inputs")
        return triage_error("No modality inputs provided")

    # Log any modalities that returned error results
    for mod, result in results.items():
        if result is not None and result.get("confidence", 0.0) == 0.0:
            logger.warning("Modality '%s' has zero confidence — likely an error result. "
                           "Excluding from fusion.", mod)

    # Compute effective fusion weights based on which modalities are present 
    # and have non-zero confidence
    effective_weights = redistribute_weights(results)

    if not effective_weights:
        logger.error("All modalities have zero confidence — cannot fuse")
        return triage_error("All modalities returned errors")

    # Perform fusion to compute final triage result
    severity = fuse_severity(results, effective_weights)
    attack_cls = fuse_attack_classification(results, effective_weights)
    entities = fuse_entities(results)
    confidence = fused_confidence(results, effective_weights)
    actions = RECOMMENDED_ACTIONS.get(attack_cls, RECOMMENDED_ACTIONS["Unknown"])

    # Modality breakdown — expose each wrapper's output, null if absent
    breakdown = {
        mod: (
            {
                "confidence": result["confidence"],
                "attack_classification": result.get("attack_classification", "Unknown"),
                "severity": result.get("severity", 1),
                "summary": result.get("summary", ""),
                "entities": result.get("entities", []),
            }
            if result is not None
            else None
        )
        for mod, result in results.items()
    }

    # Returns a dictionary triage result with the following structure
    return {
        "severity": severity,
        "attack_classification": attack_cls,
        "recommended_actions": actions,
        "confidence": confidence,
        "entities": entities,
        "modality_breakdown": breakdown,
        "fusion_weights": effective_weights,
        "active_modalities": list(effective_weights.keys()),
    }

# Function to generate a triage result in case of fusion errors (e.g. all modalities failed)
def triage_error(message: str) -> dict:
    return {
        "severity": 1,
        "attack_classification": "Unknown",
        "recommended_actions": RECOMMENDED_ACTIONS["Unknown"],
        "confidence": 0.0,
        "entities": [],
        "modality_breakdown": {"text": None, "vision": None, "speech": None},
        "fusion_weights": {},
        "active_modalities": [],
        "error": message,
    }
