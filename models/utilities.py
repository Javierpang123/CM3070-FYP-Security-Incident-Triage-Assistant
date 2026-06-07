# Shared utilities for Flashpoint model wrappers.

import re
# ---------------------------------------------------------------------------
# ATT&CK tactic keyword maps for vision and speech models
# ---------------------------------------------------------------------------

# For vision_model.py — likelly keywords that appear in rendered SIEM/dashboard UI text
SCREEN_KEYWORDS = { 
    "Initial Access": ["phishing", "brute force", "login", "authentication failure", "rdp"],
    "Execution": ["powershell", "cmd", "wscript", "cscript", "rundll32", "mshta", "process create"],
    "Persistence": ["scheduled task", "registry run", "startup", "service install", "autorun"],
    "Privilege Escalation": ["privilege", "elevation", "uac bypass", "token", "impersonation"],
    "Defense Evasion": ["obfuscat", "base64", "encoded", "delete logs", "clear event"],
    "Credential Access": ["lsass", "credential", "mimikatz", "password", "hash", "sam database"],
    "Discovery": ["whoami", "ipconfig", "net user", "net group", "systeminfo", "nmap", "scan"],
    "Lateral Movement": ["psexec", "wmi", "pass the hash", "smb", "remote", "lateral"],
    "Exfiltration": ["upload", "ftp", "exfil", "data transfer", "compress"],
    "Command and Control": ["beacon", "c2", "callback", "dns tunnel", "http tunnel"],
}

# For speech_model.py — likely keywords that appear in spoken analyst language
SPEECH_KEYWORDS = {
    "Credential Access": ["password", "credential", "hash", "lsass", "mimikatz", "kerberos"],
    "Execution": ["powershell", "script", "executed", "ran", "running", "command"],
    "Persistence": ["scheduled task", "registry", "startup", "persistence", "backdoor"],
    "Privilege Escalation": ["privilege", "admin", "elevated", "escalation", "root"],
    "Defense Evasion": ["obfuscated", "encoded", "bypass", "disabled logging", "cleared"],
    "Lateral Movement": ["lateral", "moved to", "pivoted", "remote", "psexec", "wmi"],
    "Discovery": ["scanning", "enumeration", "discovered", "recon", "whoami", "netstat"],
    "Exfiltration": ["exfiltration", "upload", "transfer", "sent data", "exfil"],
    "Command and Control": ["beacon", "callback", "c2", "command and control", "tunnel"],
    "Initial Access": ["phishing", "initial", "entry point", "brute force", "login attempt"],
}

# Shared severity keyword map
SEVERITY_KEYWORDS = {
    5: ["critical", "ransomware", "exfiltration confirmed", "full compromise", "data breach"],
    4: ["high severity", "privilege escalation", "lateral movement", "credential dumped"],
    3: ["suspicious", "unusual", "investigate", "anomalous", "warning"],
    2: ["low", "informational", "benign", "routine"],
}


# Shared function to classify the most likely MITRE ATT&CK tactic from text using a keyword map.
def classify_tactic(text: str, keyword_map: dict) -> str:
    """
    Classify the most likely MITRE ATT&CK tactic from text using a keyword map.
    Returns the highest-scoring tactic name, or 'Unknown'.
    """
    lower = text.lower()
    scores = {}
    for tactic, keywords in keyword_map.items():
        score = sum(1 for kw in keywords if kw in lower)
        if score > 0:
            scores[tactic] = score
    return max(scores, key=scores.get) if scores else "Unknown"

# Shared function to infer severity from text using the shared severity keyword map.
def infer_severity(text: str) -> int:
    """
    Infer severity (1–5) from keywords in text using the shared severity map.
    """
    lower = text.lower()
    for level in [5, 4, 3, 2]:
        if any(kw in lower for kw in SEVERITY_KEYWORDS[level]):
            return level
    return 2

# Shared function to extract candidate security entities from text using regex patterns.
def extract_entities(text: str) -> list:
    """
    Extract candidate security entities from any text:
    IP addresses, .exe process names, hostnames, Event IDs, usernames.
    """
    entities = []

    entities.extend(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text))

    processes = re.findall(r"\b\w+\.exe\b", text, re.IGNORECASE)
    entities.extend([p.lower() for p in processes])

    hostnames = re.findall(r"\b(?:DESKTOP|SERVER|DC|WS|PC|HOST)[-_]?\w+\b", 
                           text, 
                           re.IGNORECASE)
    entities.extend(hostnames)

    event_ids = re.findall(r"(?:event\s+(?:id\s+)?|EventID\s*)(\d{4})", text, re.IGNORECASE)
    entities.extend([f"EventID:{eid}" for eid in event_ids])

    standalone = re.findall(r"\b(4[0-9]{3}|5[0-9]{3})\b", text)
    for s in standalone:
        candidate = f"EventID:{s}"
        if candidate not in entities:
            entities.append(candidate)

    usernames = re.findall(r"(?:user|username|account)\s+([A-Za-z0-9_\-\.]+)", 
                           text, 
                           re.IGNORECASE)
    entities.extend(usernames)

    return list(dict.fromkeys(entities))