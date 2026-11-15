"""Finding category -> MITRE ATT&CK technique. Hardening-only issues deliberately map to nothing."""

from __future__ import annotations

CATEGORY_TO_ATTACK: dict[str, tuple[str, str]] = {
    "known-vuln": ("T1190", "Exploit Public-Facing Application"),
    "injection": ("T1190", "Exploit Public-Facing Application"),
    "unauth-service": ("T1190", "Exploit Public-Facing Application"),
    "anon-access": ("T1078", "Valid Accounts"),
    "exposed-secret": ("T1552", "Unsecured Credentials"),
    "info-disclosure": ("T1592", "Gather Victim Host Information"),
    "cleartext": ("T1040", "Network Sniffing"),
    "exposure": ("T1133", "External Remote Services"),
}

PHASE_ATTACK = {
    "recon": ("T1595", "Active Scanning"),
    "enumeration": ("T1046", "Network Service Discovery"),
    "vuln_discovery": ("T1595.002", "Vulnerability Scanning"),
}


def attack_for(category: str) -> tuple[str, str] | None:
    return CATEGORY_TO_ATTACK.get(category)
