"""
risk/mitre_mapping.py

Maps this system's internal attack_type labels to MITRE ATT&CK
(Enterprise) tactic/technique IDs, purely for analyst context — this is
a static reference table, not a classifier. Attach it to alerts/events
so an analyst can jump straight to the matching ATT&CK technique page
instead of re-deriving it from the threat category text.

Reference: https://attack.mitre.org/
"""

MITRE_MAP = {
    "brute_force": {
        "tactic": "Credential Access",
        "technique_id": "T1110",
        "technique": "Brute Force",
    },
    "account_compromise": {
        "tactic": "Initial Access",
        "technique_id": "T1078",
        "technique": "Valid Accounts",
    },
    "probe": {
        "tactic": "Reconnaissance",
        "technique_id": "T1595",
        "technique": "Active Scanning",
    },
    "dos": {
        "tactic": "Impact",
        "technique_id": "T1498",
        "technique": "Network Denial of Service",
    },
    "privilege_escalation": {
        "tactic": "Privilege Escalation",
        "technique_id": "T1068",
        "technique": "Exploitation for Privilege Escalation",
    },
    "data_exfiltration": {
        "tactic": "Exfiltration",
        "technique_id": "T1041",
        "technique": "Exfiltration Over C2 Channel",
    },
    "insider_threat": {
        "tactic": "Collection",
        "technique_id": "T1213",
        "technique": "Data from Information Repositories",
    },
    "ip_spoofing": {
        "tactic": "Defense Evasion",
        "technique_id": "T1090",
        "technique": "Proxy / IP Spoofing",
    },
    "session_hijacking": {
        "tactic": "Lateral Movement",
        "technique_id": "T1563",
        "technique": "Remote Service Session Hijacking",
    },
    "dns_spoofing": {
        "tactic": "Command and Control",
        "technique_id": "T1584.002",
        "technique": "DNS Server Compromise / Cache Poisoning",
    },
    "arp_spoofing": {
        "tactic": "Credential Access",
        "technique_id": "T1557.002",
        "technique": "ARP Cache Poisoning",
    },
    "mitm": {
        "tactic": "Credential Access",
        "technique_id": "T1557",
        "technique": "Adversary-in-the-Middle",
    },
    "none": None,
}


def get_mitre_info(attack_type: str):
    """Returns {"tactic", "technique_id", "technique"} or None if the
    attack type has no mapped technique (e.g. "none", or an unrecognized
    label from a future model version)."""
    return MITRE_MAP.get(attack_type)
