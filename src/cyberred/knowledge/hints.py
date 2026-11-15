"""Version -> known-issue hints and exposure rules.

These are *candidates* derived from version strings only. Distro back-ports mean a banner version can be
patched while still looking old, so every hint is recorded as ``candidate`` until something confirms it.
The list is intentionally short and high-signal; ``searchsploit_lookup`` covers the long tail.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from ..models import Finding


def vtuple(version: str | None) -> tuple[int, ...]:
    return tuple(int(n) for n in re.findall(r"\d+", version or "")[:4])


@dataclass(frozen=True)
class Rule:
    product: str  # regex matched against the product name (case-insensitive)
    test: Callable[[tuple[int, ...]], bool]
    title: str
    severity: str
    cve: str = ""
    cvss: float | None = None
    detail: str = ""
    fix: str = ""
    category: str = "known-vuln"


def _eq(*v: int) -> Callable[[tuple[int, ...]], bool]:
    return lambda t: t[: len(v)] == v


RULES: list[Rule] = [
    Rule(r"vsftpd", _eq(2, 3, 4), "vsFTPd 2.3.4 backdoor", "critical", "CVE-2011-2523", 9.8,
         "vsFTPd 2.3.4 shipped with a backdoor that opens a shell on port 6200 when a username ends in ':)'.",
         "Upgrade vsFTPd from a trusted source; verify package integrity."),
    Rule(r"openssh", lambda t: len(t) >= 2 and t[:2] <= (7, 7), "OpenSSH user enumeration (<= 7.7)", "medium",
         "CVE-2018-15473", 5.3, "Authentication-timing differences let remote users enumerate valid usernames.",
         "Upgrade OpenSSH; consider restricting SSH exposure."),
    Rule(r"apache( httpd)?|httpd", _eq(2, 4, 49), "Apache httpd 2.4.49 path traversal / RCE", "critical",
         "CVE-2021-41773", 9.8, "Path traversal in 2.4.49 allows file read, and RCE when mod_cgi is enabled.",
         "Upgrade to 2.4.51 or later."),
    Rule(r"apache( httpd)?|httpd", _eq(2, 4, 50), "Apache httpd 2.4.50 path traversal / RCE", "critical",
         "CVE-2021-42013", 9.8, "Incomplete fix for CVE-2021-41773 in 2.4.50.", "Upgrade to 2.4.51 or later."),
    Rule(r"proftpd", _eq(1, 3, 5), "ProFTPD 1.3.5 mod_copy unauthenticated file copy", "high", "CVE-2015-3306", 9.8,
         "mod_copy lets unauthenticated clients use SITE CPFR/CPTO to read and write files (verify mod_copy is loaded).",
         "Upgrade ProFTPD or disable mod_copy."),
    Rule(r"samba|smbd", lambda t: (3, 0, 20) <= t[:3] <= (3, 0, 25), "Samba 'username map script' command execution",
         "high", "CVE-2007-2447", None, "Shell metacharacters in the username reach /bin/sh when 'username map script' is set.",
         "Upgrade Samba."),
    Rule(r"samba|smbd",
         lambda t: len(t) >= 2 and t[:3] >= (3, 5, 0) and (t[:3] < (4, 4, 14) or (4, 5, 0) <= t[:3] < (4, 5, 10) or (4, 6, 0) <= t[:3] < (4, 6, 4)),
         "Samba 'SambaCry' writable-share code execution", "critical", "CVE-2017-7494", 9.8,
         "A writable share lets a client upload a shared library and have smbd load it.", "Upgrade Samba; set 'nt pipe support = no' as a stop-gap."),
    Rule(r"exim", lambda t: (4, 87) <= t[:2] <= (4, 91), "Exim remote command execution (4.87-4.91)", "critical",
         "CVE-2019-10149", 9.8, "Crafted recipient addresses lead to command execution as root.", "Upgrade Exim to 4.92 or later."),
    Rule(r"^php$|php", lambda t: len(t) >= 2 and t[:2] < (8, 1), "End-of-life PHP version", "low", "", None,
         "This PHP branch no longer receives security fixes.", "Upgrade to a supported PHP release.", "hardening"),
    Rule(r"apache( httpd)?|httpd", _eq(2, 2), "End-of-life Apache httpd 2.2", "medium", "", None,
         "Apache 2.2 no longer receives security fixes.", "Upgrade to Apache 2.4.", "hardening"),
    Rule(r"tomcat", lambda t: bool(t) and t[0] < 9, "End-of-life Apache Tomcat", "medium", "", None,
         "This Tomcat branch no longer receives security fixes.", "Upgrade to a supported Tomcat release.", "hardening"),
]


def hints_for(product: str | None, version: str | None, host: str = "", port: int | None = None) -> list[Finding]:
    if not product or not version:
        return []
    vt = vtuple(version)
    if not vt:
        return []
    out: list[Finding] = []
    for r in RULES:
        if re.search(r.product, product, re.I) and r.test(vt):
            out.append(Finding(
                title=r.title, severity=r.severity, description=r.detail, remediation=r.fix, host=host, port=port,
                cve=r.cve, cvss=r.cvss, category=r.category, source="version-hint", status="candidate",
                evidence=f"Service banner reports {product} {version}. Version-based match only; verify before reporting.",
            ))
    return out


# Exposure rules: services that are worth flagging just by being reachable.
_EXPOSURE: dict[int, tuple[str, str, str, str, str]] = {
    # port: (title, severity, detail, fix, category)
    23: ("Telnet service exposed", "medium", "Telnet transmits credentials and data in cleartext.", "Disable Telnet; use SSH.", "cleartext"),
    21: ("FTP service exposed (cleartext protocol)", "low", "FTP sends credentials in cleartext unless wrapped in TLS.", "Prefer SFTP/FTPS.", "cleartext"),
    5900: ("VNC service exposed", "medium", "VNC is frequently weakly authenticated and rarely encrypted.", "Restrict to a management network or tunnel it.", "exposure"),
    3389: ("RDP exposed", "low", "Internet or flat-network RDP is a frequent initial-access vector.", "Restrict by network, require NLA, enable MFA.", "exposure"),
    3306: ("MySQL reachable over the network", "low", "Database ports should not be broadly reachable.", "Bind to localhost or a private segment.", "exposure"),
    5432: ("PostgreSQL reachable over the network", "low", "Database ports should not be broadly reachable.", "Bind to localhost or a private segment.", "exposure"),
    1433: ("MS SQL Server reachable over the network", "low", "Database ports should not be broadly reachable.", "Restrict by network.", "exposure"),
    27017: ("MongoDB reachable over the network", "medium", "MongoDB has a history of unauthenticated exposure.", "Enable auth; bind privately.", "exposure"),
    2375: ("Docker API exposed (unencrypted)", "high", "An open Docker daemon socket is equivalent to root on the host.", "Do not expose 2375; use TLS-authenticated 2376.", "exposure"),
}


def exposure_for(port: int, host: str) -> Finding | None:
    rule = _EXPOSURE.get(port)
    if not rule:
        return None
    title, sev, detail, fix, cat = rule
    return Finding(title=title, severity=sev, description=detail, remediation=fix, host=host, port=port,
                   category=cat, source="exposure-rule", status="confirmed",
                   evidence=f"TCP port {port} accepted a connection.")
