"""
Flashpoint Dataset Generation Pipeline
Semi-supervised batch script for EVTX-ATTACK-SAMPLES incidents.
"""

import os
import re
import sys
import json
import time
import shutil
import subprocess
from pathlib import Path

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager

from TTS.api import TTS

# ============================================================
# CONFIGURATION
# ============================================================

WINLOGBEAT_EXE = r"C:\winlogbeat\winlogbeat.exe"
WINLOGBEAT_DATA_DIR = r"C:\winlogbeat\data"
WINLOGBEAT_LOGS_DIR = r"C:\winlogbeat\logs"

DATASET_DIR = (
    r"C:\Users\Javier Pang JunEn\OneDrive - SIM - Singapore Institute of Management"
    r"\CM3070 FYP\FYP-Project-Code\FYP-Dataset"
)
RAW_EVTX_DIR = os.path.join(DATASET_DIR, "raw_evtx")
INCIDENTS_DIR = os.path.join(DATASET_DIR, "incidents")
WINLOGBEAT_OUTPUT_DIR = os.path.join(DATASET_DIR, "winlogbeat_output")

ES_HOST = "https://localhost:9200"
ES_USER = "elastic"
ES_PASSWORD = "J6McavfN8fCApidi2wc4" 
ES_INDEX = "flashpoint-incident-current"

KIBANA_DASHBOARD_URL = "http://localhost:5601/app/dashboards#/view/1477e0cd-e817-4638-b637-980f43289689?_g=(filters:!())"

KIBANA_LOGIN_URL = "http://localhost:5601/login"

# Screenshot dimensions for the dashboard capture
SCREENSHOT_WIDTH = 1280
SCREENSHOT_HEIGHT = 800

# TTS model name for generating voice notes
TTS_MODEL_NAME = "tts_models/en/ljspeech/tacotron2-DDC"


# ============================================================
# INCIDENT MANIFEST
# ============================================================

INCIDENTS = [
    # --- Command-and-Control Incidents ---
    dict(tactic="Command-and-Control", evtx="DE_RDP_Tunnel_5156.evtx",
         incident_id="T1572_rdp_tunnel_5156", attack_class="Command and Control",
         mitre_id="T1572", mitre_sub=None, severity=5,
         voice="High volume of outbound RDP-tunneled traffic detected from the target host to an external endpoint. "
               "The tunneling pattern does not match any approved remote access tool. Possible command and control channel."),
    dict(tactic="Command-and-Control", evtx="DE_RDP_Tunneling_4624.evtx",
         incident_id="T1572_rdp_tunneling_4624", attack_class="Command and Control",
         mitre_id="T1572", mitre_sub=None, severity=5,
         voice="Repeated logon events correlate with an active RDP tunnel to an unrecognized external address. "
               "Session duration and timing suggest automated, non-interactive use. Recommend isolating the host."),
    dict(tactic="Command-and-Control", evtx="DE_RDP_Tunneling_TerminalServices-RemoteConnectionManagerOperational_1149.evtx",
         incident_id="T1572_rdp_tunneling_termsvc_1149", attack_class="Command and Control",
         mitre_id="T1572", mitre_sub=None, severity=5,
         voice="Terminal Services logs show a sustained remote connection consistent with protocol tunneling. "
               "Event volume is significantly above baseline for this host. Possible beaconing over RDP."),
    dict(tactic="Command-and-Control", evtx="DE_sysmon-3-rdp-tun.evtx",
         incident_id="T1572_sysmon_rdp_tunnel", attack_class="Command and Control",
         mitre_id="T1572", mitre_sub=None, severity=5,
         voice="Sysmon network connection events show RDP traffic tunneled through an unexpected process. "
               "The parent process does not normally initiate remote desktop connections. Flagging as possible C2 channel."),
    dict(tactic="Command-and-Control", evtx="tunna_iis_rdp_smb_tunneling_sysmon_3.evtx",
         incident_id="T1572_tunna_iis_tunneling", attack_class="Command and Control",
         mitre_id="T1572", mitre_sub=None, severity=5,
         voice="IIS worker process is observed proxying RDP and SMB traffic to an external host, consistent with "
               "the Tunna tunneling toolkit. This is not expected behavior for a web server process."),

    # --- Credential Access Incidents ---
    dict(tactic="Credential-Access", evtx="4794_DSRM_password_change_t1098.evtx",
         incident_id="T1098_dsrm_password_change", attack_class="Credential Access",
         mitre_id="T1098", mitre_sub=None, severity=4,
         voice="Multiple failed login attempts detected against domain controller 2016dc.hqcorp.local. "
               "An attempt was made to set the Directory Services Restore Mode administrator password. "
               "This action requires immediate investigation."),
    dict(tactic="Credential-Access", evtx="babyshark_mimikatz_powershell.evtx",
         incident_id="T1003_mimikatz_powershell", attack_class="Credential Access",
         mitre_id="T1003", mitre_sub="T1003.001", severity=4,
         voice="PowerShell process spawned with command-line arguments consistent with the Mimikatz credential "
               "dumping tool. Memory access patterns targeting LSASS were observed shortly after. Recommend immediate isolation."),
    dict(tactic="Credential-Access", evtx="kerberos_pwd_spray_4771.evtx",
         incident_id="T1110_kerberos_pwd_spray", attack_class="Credential Access",
         mitre_id="T1110", mitre_sub="T1110.003", severity=3,
         voice="Multiple Kerberos pre-authentication failures observed across several user accounts within a short "
               "window. Pattern is consistent with a password spraying attempt rather than a single account lockout."),
    dict(tactic="Credential-Access", evtx="sysmon_10_11_lsass_memdump.evtx",
         incident_id="T1003_lsass_memdump", attack_class="Credential Access",
         mitre_id="T1003", mitre_sub="T1003.001", severity=4,
         voice="A process was observed requesting memory access to lsass.exe followed by a file creation event "
               "consistent with a memory dump. No legitimate administrative task explains this behavior."),
    dict(tactic="Credential-Access", evtx="CA_keefarce_keepass_credump.evtx",
         incident_id="T1555_keepass_credump", attack_class="Credential Access",
         mitre_id="T1555", mitre_sub=None, severity=4,
         voice="A process injected into the running KeePass password manager and extracted decrypted credential "
               "data shortly afterward. This matches known behavior of the KeeFarce credential extraction tool."),
    dict(tactic="Credential-Access", evtx="Zerologon_VoidSec_CVE-2020-1472_4626_LT3_Anonym_follwedby_4742_DC_Anony_DC.evtx",
         incident_id="T1210_zerologon", attack_class="Credential Access",
         mitre_id="T1210", mitre_sub=None, severity=5,
         voice="An anonymous logon was followed immediately by a computer account password reset against the "
               "domain controller. This sequence matches the Zerologon exploit chain, CVE-2020-1472. Critical priority."),

    # --- Defense Evasion Incidents ---
    dict(tactic="Defense-Evasion", evtx="DE_1102_security_log_cleared.evtx",
         incident_id="T1070_security_log_cleared", attack_class="Defense Evasion",
         mitre_id="T1070", mitre_sub="T1070.001", severity=4,
         voice=" The Windows Security event log was cleared on the target host. Log size dropped to zero entries "
               "immediately following the clearing action. This is a strong indicator of evasion activity."),
    dict(tactic="Defense-Evasion", evtx="de_unmanagedpowershell_psinject_sysmon_7_8_10.evtx",
         incident_id="T1055_process_injection", attack_class="Defense Evasion",
         mitre_id="T1055", mitre_sub=None, severity=4,
         voice=" An un managed PowerShell payload was injected into a legitimate process via reflective loading. "
               "No corresponding PowerShell console process was observed, consistent with in-memory evasion."),
    dict(tactic="Defense-Evasion", evtx="sysmon_13_rdp_settings_tampering.evtx",
         incident_id="T1112_registry_tampering", attack_class="Defense Evasion",
         mitre_id="T1112", mitre_sub=None, severity=3,
         voice=" Registry values controlling RDP security settings were modified outside of a scheduled change "
               "window. The modification weakens authentication requirements for remote desktop access."),
    dict(tactic="Defense-Evasion", evtx="de_powershell_execpolicy_changed_sysmon_13.evtx",
         incident_id="T1562_execpolicy_changed", attack_class="Defense Evasion",
         mitre_id="T1562", mitre_sub="T1562.001", severity=3,
         voice=" PowerShell execution policy was changed to unrestricted on the target host. This removes a "
               "safeguard against unsigned script execution and warrants review."),
    dict(tactic="Defense-Evasion", evtx="DE_UAC_Disabled_Sysmon_12_13.evtx",
         incident_id="T1548_uac_disabled", attack_class="Defense Evasion",
         mitre_id="T1548", mitre_sub="T1548.002", severity=3,
         voice=" User Account Control was disabled via a registry modification on the target host. This lowers "
               "the barrier for subsequent privilege escalation attempts."),
    dict(tactic="Defense-Evasion", evtx="sysmon_2_11_evasion_timestomp_MACE.evtx",
         incident_id="T1070_timestomp", attack_class="Defense Evasion",
         mitre_id="T1070", mitre_sub="T1070.006", severity=3,
         voice=" File time stamps were modified to match a system file, a technique known as time stomping. "
               "This is commonly used to blend malicious files in with legitimate system activity."),

    # --- Discovery Incidents ---
    dict(tactic="Discovery", evtx="dicovery_4661_net_group_domain_admins_target.evtx",
         incident_id="T1069_domain_admins_group_discovery", attack_class="Discovery",
         mitre_id="T1069", mitre_sub="T1069.002", severity=3,
         voice=" A handle was opened against the Domain Admins security group object shortly before an "
               "enumeration query. This behavior is consistent with reconnaissance ahead of a privilege escalation attempt."),
    dict(tactic="Discovery", evtx="discovery_meterpreter_ps_cmd_process_listing_sysmon_10.evtx",
         incident_id="T1057_process_discovery", attack_class="Discovery",
         mitre_id="T1057", mitre_sub=None, severity=2,
         voice=" A process access event shows enumeration of running processes consistent with a Meter preter "
               "post-exploitation module. No legitimate administrative tool explains the access pattern."),
    dict(tactic="Discovery", evtx="discovery_bloodhound.evtx",
         incident_id="T1482_bloodhound_ad_discovery", attack_class="Discovery",
         mitre_id="T1482", mitre_sub=None, severity=4,
         voice=" L D A P query volume from a single host spiked sharply, consistent with the Blood Hound Active "
               " Directory reconnaissance tool. This activity often precedes a targeted lateral movement attempt."),
    dict(tactic="Discovery", evtx="discovery_enum_shares_target_sysmon_3_18.evtx",
         incident_id="T1135_network_share_discovery", attack_class="Discovery",
         mitre_id="T1135", mitre_sub=None, severity=2,
         voice=" Sequential connection attempts were made to multiple administrative shares across the network "
               "from a single host. This pattern is consistent with automated share enumeration."),
    dict(tactic="Discovery", evtx="discovery_psloggedon.evtx",
         incident_id="T1033_system_owner_discovery", attack_class="Discovery",
         mitre_id="T1033", mitre_sub=None, severity=2,
         voice=" A tool was used to enumerate currently and recently logged on users across the network. "
               " This is commonly used by an attacker to identify high value targets for follow-on activity."),
    dict(tactic="Discovery", evtx="discovery_local_user_or_group_windows_security_4799_4798.evtx",
         incident_id="T1069_local_group_discovery", attack_class="Discovery",
         mitre_id="T1069", mitre_sub="T1069.001", severity=2,
         voice=" Local group membership was enumerated on the target host outside of a routine audit window. "
               " The enumerating account does not typically perform this kind of query."),

    # --- Execution Incidents ---
    dict(tactic="Execution", evtx="rogue_msi_url_1040_1042.evtx",
         incident_id="T1218_msiexec_rogue_install", attack_class="Execution",
         mitre_id="T1218", mitre_sub="T1218.007", severity=4,
         voice=" M s i exec was used to install a package fetched directly from a remote URL rather than a local or "
               "approved software repository. This is a common technique for delivering a malicious payload."),
    dict(tactic="Execution", evtx="Sysmon_meterpreter_ReflectivePEInjection_to_notepad_.evtx",
         incident_id="T1055_reflective_injection", attack_class="Execution",
         mitre_id="T1055", mitre_sub=None, severity=4,
         voice=" A reflective injection was observed targeting notepad.exe, consistent with a Meter preter "
               " payload. The target process shows no legitimate reason for the injected memory region."),
    dict(tactic="Execution", evtx="sysmon_exec_from_vss_persistence.evtx",
         incident_id="T1053_scheduled_task_exec", attack_class="Execution",
         mitre_id="T1053", mitre_sub="T1053.005", severity=3,
         voice=" A scheduled task executed a binary from a volume shadow copy path rather than a standard "
               "installation directory. This is an unusual execution source that warrants review."),
    dict(tactic="Execution", evtx="exec_sysmon_1_11_lolbin_rundll32_openurl_FileProtocolHandler.evtx",
         incident_id="T1218_rundll32_lolbin", attack_class="Execution",
         mitre_id="T1218", mitre_sub="T1218.011", severity=3,
         voice=" Rund l l 3 2 was used to invoke the FileProtocolHandler export to open a URL, a known "
               "technique for masking network activity behind a trusted binary."),
    dict(tactic="Execution", evtx="exec_wmic_xsl_internet_sysmon_3_1_11.evtx",
         incident_id="T1220_xsl_script_processing", attack_class="Execution",
         mitre_id="T1220", mitre_sub=None, severity=3,
         voice=" W M I C was used to process an X S L stylesheet retrieved from an internet-facing URL. This technique "
               "allows arbitrary script execution while evading application whitelisting."),
    dict(tactic="Execution", evtx="temp_scheduled_task_4698_4699.evtx",
         incident_id="T1053_scheduled_task_creation", attack_class="Execution",
         mitre_id="T1053", mitre_sub="T1053.005", severity=3,
         voice=" A new scheduled task was created and registered on the target host outside of a maintenance "
               "window. The task action points to a binary in a non-standard location."),

    # --- Lateral Movement Incidents ---
    dict(tactic="Lateral-Movement", evtx="LM_sysmon_3_12_13_1_SharpRDP.evtx",
         incident_id="T1021_sharprdp", attack_class="Lateral Movement",
         mitre_id="T1021", mitre_sub="T1021.001", severity=4,
         voice=" An R D P connection was established programmatically without the usual interactive log on prompt "
               "sequence, consistent with the Sharp R D P lateral movement tool."),
    dict(tactic="Lateral-Movement", evtx="LM_ScheduledTask_ATSVC_target_host.evtx",
         incident_id="T1053_remote_scheduled_task", attack_class="Lateral Movement",
         mitre_id="T1053", mitre_sub=None, severity=4,
         voice=" A scheduled task was created remotely on the target host via the A T S V C interface. Remote task "
               "creation of this kind is commonly used to achieve lateral movement and execution."),
    dict(tactic="Lateral-Movement", evtx="smbmap_upload_exec_sysmon.evtx",
         incident_id="T1021_smb_admin_shares", attack_class="Lateral Movement",
         mitre_id="T1021", mitre_sub="T1021.002", severity=4,
         voice=" A file was uploaded to an administrative S M B share on the target host and executed shortly "
               "afterward. This upload-and-execute pattern is consistent with S M B based lateral movement."),
    dict(tactic="Lateral-Movement", evtx="LM_xp_cmdshell_MSSQL_Events.evtx",
         incident_id="T1210_mssql_xp_cmdshell", attack_class="Lateral Movement",
         mitre_id="T1210", mitre_sub=None, severity=4,
         voice=" The xp_cmdshell stored procedure was enabled and invoked on the target M S S Q L server, allowing "
               "operating system command execution through the database service."),
    dict(tactic="Lateral-Movement", evtx="LM_sysmon_psexec_smb_meterpreter.evtx",
         incident_id="T1021_psexec", attack_class="Lateral Movement",
         mitre_id="T1021", mitre_sub="T1021.002", severity=4,
         voice=" A service was remotely created and started on the target host consistent with PsExec style "
               "lateral movement. The service binary path points to a temporary location."),
    dict(tactic="Lateral-Movement", evtx="LM_wmiexec_impacket_sysmon_whoami.evtx",
         incident_id="T1047_wmiexec", attack_class="Lateral Movement",
         mitre_id="T1047", mitre_sub=None, severity=4,
         voice=" A WMI process call was used to remotely execute a whoami command on the target host, consistent "
               "with the wmiexec tool from the Impacket toolkit."),

    # --- Persistence Incidents ---
    dict(tactic="Persistence", evtx="sysmon_13_1_persistence_via_winlogon_shell.evtx",
         incident_id="T1547_winlogon_helper_dll", attack_class="Persistence",
         mitre_id="T1547", mitre_sub="T1547.004", severity=4,
         voice=" A registry value controlling the Winlogon shell was modified to point to an additional binary. "
               "This grants the attacker persistence that survives a full user log on cycle."),
    dict(tactic="Persistence", evtx="persist_firefox_comhijack_sysmon_11_13_7_1.evtx",
         incident_id="T1546_com_hijacking", attack_class="Persistence",
         mitre_id="T1546", mitre_sub="T1546.015", severity=3,
         voice=" A C O M object registration associated with Firefox was hijacked to point to an attacker-controlled "
               "D L L. This provides persistence that triggers whenever the associated C O M interface is invoked."),
    dict(tactic="Persistence", evtx="sysmon_20_21_1_CommandLineEventConsumer.evtx",
         incident_id="T1546_wmi_event_subscription", attack_class="Persistence",
         mitre_id="T1546", mitre_sub="T1546.003", severity=4,
         voice="A consumer execute a command line whenever a specific system event occurs. "
               "This is a stealthy persistence mechanism that survives reboots."),
    dict(tactic="Persistence", evtx="sysmon_local_account_creation_and_added_admingroup_12_13.evtx",
         incident_id="T1136_account_manipulation", attack_class="Persistence",
         mitre_id="T1136", mitre_sub="T1136.001", severity=4,
         voice=" A new local account was created and immediately added to the local administrators group by a "
               "non-administrative account at an unusual hour. This does not match the baseline for this host."),
    dict(tactic="Persistence", evtx="persistence_security_dcshadow_4742.evtx",
         incident_id="T1207_dcshadow", attack_class="Persistence",
         mitre_id="T1207", mitre_sub=None, severity=5,
         voice=" A computer account object was modified in a manner consistent with the DC Shadow attack, "
               "temporarily registering a rogue domain controller to push unauthorized directory changes. Critical priority."),
    dict(tactic="Persistence", evtx="persist_bitsadmin_Microsoft-Windows-Bits-Client-Operational.evtx",
         incident_id="T1197_bits_jobs", attack_class="Persistence",
         mitre_id="T1197", mitre_sub=None, severity=3,
         voice=" Created to periodically download and execute a file from an external URL. "
               " It can survive reboots and are rarely monitored by defenders."),

    # --- Privilege Escalation Incidents ---
    dict(tactic="Privilege-Escalation", evtx="privesc_unquoted_svc_sysmon_1_11.evtx",
         incident_id="T1574_unquoted_service_path", attack_class="Privilege Escalation",
         mitre_id="T1574", mitre_sub="T1574.009", severity=3,
         voice=" A service was observed with an unquoted binary path containing a space, allowing a planted "
               "executable earlier in the path to be launched with the service's elevated privileges."),
    dict(tactic="Privilege-Escalation", evtx="Sysmon_UACME_22.evtx",
         incident_id="T1548_uac_bypass", attack_class="Privilege Escalation",
         mitre_id="T1548", mitre_sub="T1548.002", severity=4,
         voice=" A known auto-elevating Windows binary was invoked in a sequence consistent with the U A C M E "
               "bypass technique, allowing code execution without a U A C consent prompt."),
    dict(tactic="Privilege-Escalation", evtx="security_4624_4673_token_manip.evtx",
         incident_id="T1134_token_manipulation", attack_class="Privilege Escalation",
         mitre_id="T1134", mitre_sub=None, severity=4,
         voice=" A process was granted a sensitive privilege immediately followed by a token related access "
               "event. This sequence is consistent with token impersonation for privilege escalation."),
    dict(tactic="Privilege-Escalation", evtx="privesc_rotten_potato_from_webshell_metasploit_sysmon_1_8_3.evtx",
         incident_id="T1134_rotten_potato", attack_class="Privilege Escalation",
         mitre_id="T1134", mitre_sub=None, severity=4,
         voice=" A low privileged web shell process spawned a child process running as SYSTEM shortly after a "
               "local relay was observed, consistent with the Rotten Potato privilege escalation technique."),
    dict(tactic="Privilege-Escalation", evtx="RogueWinRM.evtx",
         incident_id="T1134_winrm_privesc", attack_class="Privilege Escalation",
         mitre_id="T1134", mitre_sub=None, severity=3,
         voice=" A rogue Win R M listener was started briefly on the host and then torn down, consistent with an "
               "exploit that abuses the WinRM service startup sequence to gain SYSTEM privileges."),
    dict(tactic="Privilege-Escalation", evtx="CVE-2020-0796_SMBV3Ghost_LocalPrivEsc_Sysmon_3_1_10.evtx",
         incident_id="CVE-2020-0796_smbghost", attack_class="Privilege Escalation",
         mitre_id="CVE-2020-0796", mitre_sub=None, severity=5,
         voice=" Anomalous traffic was observed consistent with the SMB Ghost "
               "vulnerability, CVE 2020 0796, which allows local privilege escalation. Critical priority."),
]


# ============================================================
# WINLOGBEAT CONFIG TEMPLATES (Generated once at start)
# ============================================================

WINLOGBEAT_PASS1_YML = f"""
winlogbeat.registry_file: {WINLOGBEAT_DATA_DIR}\\registry

winlogbeat.event_logs:
  - name: ${{EVTX_FILE}}
    no_more_events: stop

winlogbeat.shutdown_timeout: 10s

queue.mem:
  flush.min_events: 1
  flush.timeout: 0s

output.file:
  path: '{WINLOGBEAT_OUTPUT_DIR}'
  filename: events
  rotate_every_kb: 102400

logging.level: info
logging.to_files: true
logging.files:
  path: {WINLOGBEAT_LOGS_DIR}
  name: winlogbeat_pass1
  keepfiles: 7
  permissions: 0644
"""

WINLOGBEAT_PASS2_YML = f"""
winlogbeat.registry_file: {WINLOGBEAT_DATA_DIR}\\registry

winlogbeat.event_logs:
  - name: ${{EVTX_FILE}}
    no_more_events: stop

winlogbeat.shutdown_timeout: 10s

queue.mem:
  flush.min_events: 1
  flush.timeout: 0s

output.elasticsearch:
  hosts: ["{ES_HOST}"]
  username: "{ES_USER}"
  password: "{ES_PASSWORD}"
  ssl.verification_mode: none
  index: "{ES_INDEX}"

setup.template.name: "flashpoint-incident"
setup.template.pattern: "flashpoint-incident-*"

logging.level: info
logging.to_files: true
logging.files:
  path: {WINLOGBEAT_LOGS_DIR}
  name: winlogbeat_pass2
  keepfiles: 7
  permissions: 0644
"""

PASS1_YML_PATH = os.path.join(os.path.dirname(WINLOGBEAT_EXE), "winlogbeat_pass1.yml")
PASS2_YML_PATH = os.path.join(os.path.dirname(WINLOGBEAT_EXE), "winlogbeat_pass2.yml")


# ============================================================
# HELPERS FUNCTION
# ============================================================

# Function to clear the Winlogbeat registry and output directories before each run
def clear_registry():
    """Critical: must run before every single Pass 1 and Pass 2, or a
    previously-seen .evtx path will silently yield 0 events."""
    if os.path.exists(WINLOGBEAT_DATA_DIR):
        shutil.rmtree(WINLOGBEAT_DATA_DIR, ignore_errors=True)

# Function to run Winlogbeat with a given configuration and EVTX file
def run_winlogbeat(config_path, evtx_path):
    cmd = [WINLOGBEAT_EXE, "-c", config_path, "-E", f"EVTX_FILE={evtx_path}"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    return result

# Function run Pass 1 of the pipeline: 
# Winlogbeat reads EVTX and outputs to a file, which is then copied to log.json
def run_pass1(evtx_path, incident_dir):
    
    # Clear the Winlogbeat registry and output directory to ensure a clean run
    clear_registry()
    
    # Clear the output directory and recreate it to ensure no leftover files
    if os.path.exists(WINLOGBEAT_OUTPUT_DIR):
        shutil.rmtree(WINLOGBEAT_OUTPUT_DIR, ignore_errors=True)
    os.makedirs(WINLOGBEAT_OUTPUT_DIR, exist_ok=True)

    # Run Winlogbeat Pass 1 with the specified configuration and EVTX file
    result = run_winlogbeat(PASS1_YML_PATH, evtx_path)
    if result.returncode != 0:
        print("  [WARN] Winlogbeat Pass 1 non-zero exit:")
        print(result.stderr[-800:])

    # Find the dynamically-named output file (events-YYYYMMDD.ndjson)
    candidates = list(Path(WINLOGBEAT_OUTPUT_DIR).glob("events*"))
    if not candidates:
        return False, "No output file produced by Pass 1"

    # Copy the most recent output file to log.json in the incident directory
    output_file = max(candidates, key=lambda p: p.stat().st_mtime)
    log_json_path = os.path.join(incident_dir, "log.json")
    shutil.copy(output_file, log_json_path)

    # Sanity check at least 1 line
    with open(log_json_path, "r", encoding="utf-8") as f:
        line_count = sum(1 for _ in f)
        
    # If no events were written, return a failure message
    if line_count == 0:
        return False, "log.json is empty (0 events written)"
    
    # Return success with the count of events written to log.json
    return True, f"{line_count} event(s) -> log.json"

# Function to clear the Elasticsearch index before Pass 2
def clear_es_index():
    requests.delete(f"{ES_HOST}/{ES_INDEX}",
                    auth=(ES_USER, ES_PASSWORD),
                    verify=False)

# Function to get the current document count in the Elasticsearch index
def get_es_count():
    # Try to query the Elasticsearch _count API for the specified index
    try:
        r = requests.get(f"{ES_HOST}/{ES_INDEX}/_count",
                         auth=(ES_USER, ES_PASSWORD),
                         verify=False,
                         timeout=10)
        
        # If the request is successful, 
        # return the count of documents; 
        # otherwise, return None
        if r.status_code == 200:
            return r.json().get("count", 0)
        
    # If there's a request exception such as timeout,
    # return None to indicate failure to retrieve the count
    except requests.RequestException:
        pass
    return None

# Function to run Pass 2 of the pipeline:
# Winlogbeat reads EVTX and outputs to Elasticsearch, which is cleared beforehand
def run_pass2(evtx_path):
    
    # Clear the Winlogbeat registry and output directory to ensure a clean run
    clear_registry()
    
    result = run_winlogbeat(PASS2_YML_PATH, evtx_path)
    if result.returncode != 0:
        print("  [WARN] Winlogbeat Pass 2 non-zero exit:")
        print(result.stderr[-800:])

    # Give Elasticsearch a moment to make the doc searchable
    time.sleep(2)
    count = get_es_count()
    
    # If the count is None (failed to retrieve) or 0 (no documents indexed), 
    # return a failure message
    if count is None or count == 0:
        return False, f"Elasticsearch index count is {count} after Pass 2"
    return True, f"{count} event(s) indexed in Elasticsearch"

# Function to log into Kibana using Selenium WebDriver
def kibana_login(driver, wait):
    
    driver.get(KIBANA_LOGIN_URL)
    
    # Try to find the username and password fields, fill them in, and submit the form
    try:
        user_field = wait.until(EC.presence_of_element_located((By.NAME, "username")))
        pass_field = driver.find_element(By.NAME, "password")
        user_field.clear()
        user_field.send_keys(ES_USER)
        pass_field.clear()
        pass_field.send_keys(ES_PASSWORD)
        pass_field.submit()
        time.sleep(3)
    
    except Exception:
        # Already logged in / no login form present - fine
        pass

# Function to start a new Chrome browser session and log into Kibana
def start_browser():
    opts = webdriver.ChromeOptions()
    opts.add_argument(f"--window-size={SCREENSHOT_WIDTH},{SCREENSHOT_HEIGHT}")
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=opts)
    wait = WebDriverWait(driver, 20)
    kibana_login(driver, wait)
    return driver

# Function to check if the session is still alive
def is_session_alive(driver):
    try:
        _ = driver.current_url
        return True
    except Exception:
        return False

# Function to capture a screenshot of the Kibana dashboard
def capture_screenshot(driver_box, incident_dir):
    
    # Check if the browser session is alive; if not, relaunch and re-login
    if not is_session_alive(driver_box[0]):
        print("    [WARNING] Browser session is dead, relaunching and re-logging in...")
        try:
            driver_box[0].quit()
        except Exception:
            pass
        driver_box[0] = start_browser()

    driver = driver_box[0]
    
    # Try to navigate to the Kibana dashboard, refresh, and take a screenshot
    try:
        driver.get(KIBANA_DASHBOARD_URL)
        time.sleep(2)
        driver.refresh()
        time.sleep(6)
        out_path = os.path.join(incident_dir, "screenshot.png")
        driver.save_screenshot(out_path)
        return out_path
    
    # If an exception occurs, log a warning, relaunch the browser, and retry once
    except Exception as e:
        print(f"    [WARNING] Screenshot failed ({e}); relaunching browser and retrying once...")
        
        # Try to quit the existing browser session, ignoring any exceptions
        try:
            driver_box[0].quit()
        # If an exception occurs while quitting, ignore it
        except Exception:
            pass
        
        # Start a new browser session and log into Kibana
        driver_box[0] = start_browser()
        driver = driver_box[0]
        driver.get(KIBANA_DASHBOARD_URL)
        
        # Wait a moment for the page to load, refresh, 
        # and wait again before taking the screenshot
        time.sleep(2)
        driver.refresh()
        time.sleep(6)
        out_path = os.path.join(incident_dir, "screenshot.png")
        driver.save_screenshot(out_path)
        
        # Return the path to the saved screenshot
        return out_path

# Function to generate a voice note using TTS and save it as a WAV file
def generate_voice_note(tts_engine, text, incident_dir):
    wav_path = os.path.join(incident_dir, "voice.wav")
    txt_path = os.path.join(incident_dir, "voice_transcript.txt")
    tts_engine.tts_to_file(text=text, file_path=wav_path)
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(text)
    return wav_path

# Function to write a label.json file for the incident, containing metadata
def write_label(incident, incident_dir):
    
    # Create a dictionary with the relevant incident metadata to be saved in label.json
    label = {"incident_id": incident["incident_id"],
             "attack_class": incident["attack_class"],
             "mitre_id": incident["mitre_id"],
             "mitre_sub": incident["mitre_sub"],
             "severity": incident["severity"],
             "source_evtx": incident["evtx"]}
    
    # Write the label dictionary to a JSON file in the incident directory
    label_path = os.path.join(incident_dir, "label.json")
    with open(label_path, "w", encoding="utf-8") as f:
        json.dump(label, f, indent=2)
    return label_path

# Function to check if an incident is complete by verifying the existence of label.json
def is_complete(incident_dir):
    return os.path.exists(os.path.join(incident_dir, "label.json"))


# ============================================================
# MAIN FUNCTION
# ============================================================

# Function to orchestrate the entire dataset pipeline, processing each incident in sequence
def main():
    print(f"Loaded {len(INCIDENTS)} incidents from manifest.\n")

    # Write the two winlogbeat config files once
    with open(PASS1_YML_PATH, "w", encoding="utf-8") as f:
        f.write(WINLOGBEAT_PASS1_YML)
    with open(PASS2_YML_PATH, "w", encoding="utf-8") as f:
        f.write(WINLOGBEAT_PASS2_YML)
    print(f"Wrote Winlogbeat configs:\n  {PASS1_YML_PATH}\n  {PASS2_YML_PATH}\n")

    # Load TTS model once (slow-ish, do it before the loop)
    print(f"Loading TTS model ({TTS_MODEL_NAME})... this may take a moment.")
    tts_engine = TTS(model_name=TTS_MODEL_NAME, progress_bar=False)
    print("TTS model loaded.\n")

    # Start one persistent browser session for all screenshots
    print("Starting browser session...")
    driver_box = [start_browser()]
    print("Browser session ready.\n")
    print("IMPORTANT: don't click into or close the automated Chrome window "
          "while the script is running - just watch the terminal.\n")

    processed, skipped, failed = 0, 0, 0

    try:
        # Loop through each incident in the INCIDENTS list, processing them one by one
        for i, incident in enumerate(INCIDENTS, start=1):
            incident_dir = os.path.join(INCIDENTS_DIR, incident["tactic"], incident["incident_id"])
            evtx_path = os.path.join(RAW_EVTX_DIR, incident["tactic"], incident["evtx"])

            # Print the current incident being processed, including its index, ID, and tactic
            print(f"[{i}/{len(INCIDENTS)}] {incident['incident_id']}  ({incident['tactic']})")
            
            # Check if the incident is already complete by looking for label.json
            if is_complete(incident_dir):
                print("  Already complete (label.json exists) - skipping.")
                skipped += 1
                continue
            
            # Check if the source .evtx file exists         
            if not os.path.exists(evtx_path):
                print(f"  [ERROR] Source .evtx not found: {evtx_path}")
                failed += 1
                continue

            # Create the incident directory if it doesn't exist    
            os.makedirs(incident_dir, exist_ok=True)

            # Pass 1: log.json
            print("  Running Pass 1 (file output)...")
            ok, msg = run_pass1(evtx_path, incident_dir)
            print(f"    {'OK' if ok else 'FAIL'}: {msg}")
            
            # If Pass 1 fails, increment the failed counter and skip to the next incident
            if not ok:
                failed += 1
                print("  Skipping remaining steps for this incident due to Pass 1 failure.")
                continue

            # Pass 2: Elasticsearch
            print("  Clearing Elasticsearch index before Pass 2...")
            clear_es_index()
            print("  Running Pass 2 (elasticsearch output)...")
            ok, msg = run_pass2(evtx_path)
            print(f"    {'OK' if ok else 'FAIL'}: {msg}")
            
            # If Pass 2 fails, increment the failed counter and skip to the next incident
            if not ok:
                failed += 1
                print("  Skipping remaining steps for this incident due to Pass 2 failure.")
                continue

            # Screenshot the dashboard
            print("  Capturing dashboard screenshot............")
            shot_path = capture_screenshot(driver_box, incident_dir)
            print(f"    Saved: {shot_path}")

            # Synthesize voice note recording
            print("  Generating voice note..................")
            wav_path = generate_voice_note(tts_engine, incident["voice"], incident_dir)
            print(f"    Saved: {wav_path}")

            # Label the incident
            label_path = write_label(incident, incident_dir)
            print(f"  Wrote label: {label_path}")

            # Cleanup index for next incident
            clear_es_index()
            
            # Increment the processed counter to reflect 
            # the successful processing of this incident    
            processed += 1

            # pause the process for me to review
            print(f"\n  Incident folder: {incident_dir}")
            print("  Please check the screenshot and voice note.")
            choice = input("  Press Enter to continue, 's' + Enter to skip next incident, "
                            "'q' + Enter to quit: ").strip().lower()
            if choice == "q":
                break
            elif choice == "s":
                continue

    finally:
        try:
            driver_box[0].quit()
        except Exception:
            pass
        
        print(f"Session summary: {processed} processed, {skipped} already-complete "
              f"(skipped), {failed} failed.")
        


if __name__ == "__main__":
    main()
