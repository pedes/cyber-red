"""Parsers: raw tool output -> structured records (hosts, services, endpoints, findings)."""

from __future__ import annotations

import base64
import json
import re
import xml.etree.ElementTree as ET
from typing import Any

from ..models import Finding

Data = dict[str, list[dict[str, Any]]]


def _empty() -> Data:
    return {"hosts": [], "services": [], "endpoints": [], "findings": []}


# ----------------------------------------------------------------------------- nmap

_SCRIPT_RULES = [
    # (script id, regex on output, builder)
]


def _script_findings(host: str, port: int | None, sid: str, out: str) -> list[Finding]:
    f: list[Finding] = []
    mk = lambda **kw: Finding(host=host, port=port, source="nmap", status="confirmed", evidence=f"{sid}:\n{out.strip()[:600]}", **kw)  # noqa: E731
    low = out.lower()
    if sid == "ftp-anon" and "anonymous ftp login allowed" in low:
        f.append(mk(title="Anonymous FTP login allowed", severity="medium", category="anon-access",
                    description="The FTP server accepts anonymous logins.", remediation="Disable anonymous access or restrict it to a read-only, non-sensitive area."))
    elif sid == "smb-security-mode":
        if "message_signing: disabled" in low:
            f.append(mk(title="SMB message signing disabled", severity="medium", category="hardening",
                        description="Without signing, SMB traffic can be relayed or tampered with.", remediation="Require SMB signing."))
        elif "message_signing: supported" in low:
            f.append(mk(title="SMB signing not required", severity="low", category="hardening",
                        description="SMB signing is supported but not enforced, which allows relay attacks.", remediation="Require SMB signing."))
    elif sid == "smb2-security-mode" and "not required" in low:
        f.append(mk(title="SMB signing not required", severity="low", category="hardening",
                    description="SMB signing is enabled but not required, which allows relay attacks.", remediation="Require SMB signing."))
    elif sid == "smb-protocols" and ("nt lm 0.12" in low or "smbv1" in low):
        f.append(mk(title="SMBv1 enabled", severity="medium", category="known-vuln",
                    description="SMBv1 is obsolete and the target of wormable exploits.", remediation="Disable SMBv1."))
    elif sid.startswith("smb-vuln-ms17-010") and "state: vulnerable" in low:
        f.append(mk(title="MS17-010 (EternalBlue) vulnerable", severity="critical", category="known-vuln", cve="CVE-2017-0143",
                    cvss=8.1, description="SMBv1 remote code execution (EternalBlue).", remediation="Apply MS17-010; disable SMBv1."))
    elif sid == "nfs-showmount" and "/" in out:
        f.append(mk(title="NFS exports visible to clients", severity="medium", category="exposure",
                    description="The NFS server lists its exports to any client.", remediation="Restrict exports by host and use root_squash."))
    elif sid == "ldap-rootdse" and "namingcontexts" in low:
        f.append(mk(title="LDAP RootDSE readable anonymously", severity="low", category="info-disclosure",
                    description="Directory metadata is available without authentication.", remediation="Require authentication for LDAP queries where possible."))
    elif sid == "dns-zone-transfer" and "axfr" in low and "failed" not in low:
        f.append(mk(title="DNS zone transfer allowed", severity="high", category="info-disclosure",
                    description="AXFR exposes every record in the zone.", remediation="Restrict zone transfers to secondary servers."))
    elif sid == "smb-enum-shares" and re.search(r"anonymous access:\s*(read|write)", low):
        f.append(mk(title="SMB share accessible anonymously", severity="medium", category="anon-access",
                    description="A share allows unauthenticated access.", remediation="Remove anonymous access from shares."))
    return f


def parse_nmap_xml(xml_text: str) -> Data:
    data = _empty()
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return data
    for h in root.findall("host"):
        status = h.find("status")
        if status is not None and status.get("state") != "up":
            continue
        addr = next((a.get("addr") for a in h.findall("address") if a.get("addrtype") in ("ipv4", "ipv6")), None)
        if not addr:
            continue
        hn = h.find("hostnames/hostname")
        hostname = hn.get("name") if hn is not None else None
        osm = h.find("os/osmatch")
        data["hosts"].append({"address": addr, "hostname": hostname, "os": osm.get("name") if osm is not None else None})
        for p in h.findall("ports/port"):
            st = p.find("state")
            if st is None or st.get("state") != "open":
                continue
            svc = p.find("service")
            port = int(p.get("portid", "0"))
            name = svc.get("name") if svc is not None else None
            if svc is not None and svc.get("tunnel") == "ssl" and name == "http":
                name = "https"
            scripts = {s.get("id", ""): s.get("output", "") for s in p.findall("script")}
            data["services"].append({
                "address": addr, "port": port, "proto": p.get("protocol", "tcp"), "name": name,
                "product": svc.get("product") if svc is not None else None,
                "version": svc.get("version") if svc is not None else None,
                "extra": svc.get("extrainfo") if svc is not None else None,
                "banner": "; ".join(f"{k}: {v.strip()[:200]}" for k, v in scripts.items())[:800] or None,
            })
            for sid, out in scripts.items():
                data["findings"].extend(f.to_dict() for f in _script_findings(addr, port, sid, out))
        for s in h.findall("hostscript/script"):  # host-level scripts (smb-os-discovery, ...)
            sid, out = s.get("id", ""), s.get("output", "")
            data["findings"].extend(f.to_dict() for f in _script_findings(addr, None, sid, out))
            if sid == "smb-os-discovery":
                m = re.search(r"OS:\s*(.+)", out)
                if m and data["hosts"]:
                    data["hosts"][-1]["os"] = data["hosts"][-1]["os"] or m.group(1).strip()[:120]
    return data


# ----------------------------------------------------------------------------- nuclei

_NUCLEI_SEV = {"critical", "high", "medium", "low", "info"}


def parse_nuclei(jsonl: str) -> Data:
    data = _empty()
    for line in jsonl.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = r.get("info", {}) or {}
        sev = str(info.get("severity", "info")).lower()
        sev = sev if sev in _NUCLEI_SEV else "info"
        cls = info.get("classification") or {}
        cves = cls.get("cve-id") or []
        cve = (cves[0] if isinstance(cves, list) and cves else cves if isinstance(cves, str) else "") or ""
        cvss = cls.get("cvss-score")
        matched = r.get("matched-at") or r.get("host") or ""
        extracted = r.get("extracted-results")
        data["findings"].append(Finding(
            title=f"{info.get('name', r.get('template-id', 'nuclei finding'))}", severity=sev,
            description=(info.get("description") or "").strip()[:800],
            evidence=f"template: {r.get('template-id', '?')}\nmatched: {matched}" + (f"\nextracted: {extracted}" if extracted else ""),
            url=matched if str(matched).startswith("http") else "", host="" if str(matched).startswith("http") else str(matched),
            cve=str(cve).upper(), cvss=float(cvss) if isinstance(cvss, (int, float)) else None,
            category="known-vuln" if cve else "misconfig", source="nuclei", status="confirmed",
            remediation="; ".join(info.get("reference", [])[:2]) if isinstance(info.get("reference"), list) else "",
        ).to_dict())
    return data


# ----------------------------------------------------------------------------- ffuf

def _b64(s: str) -> str:
    try:
        return base64.b64decode(s).decode(errors="replace")
    except Exception:
        return s


def parse_ffuf(output: str) -> Data:
    """Parses ``ffuf -json`` newline-delimited records."""
    data = _empty()
    seen: set[str] = set()
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = r.get("url")
        if not url or url in seen:
            continue
        seen.add(url)
        data["endpoints"].append({"url": url, "status": r.get("status"), "title": None, "tech": [],
                                  "params": [], "source": "ffuf", "length": r.get("length"),
                                  "word": _b64((r.get("input") or {}).get("FUZZ", ""))})
    return data


# ----------------------------------------------------------------------------- sqlmap

def parse_sqlmap(text: str, url: str) -> Data:
    data = _empty()
    params = re.findall(r"Parameter: ([^\n]+?) \((GET|POST|URI|Cookie|Header)[^)]*\)", text)
    types = re.findall(r"Type: ([^\n]+)", text)
    dbms = re.search(r"back-end DBMS: ([^\n]+)", text)
    if params and re.search(r"is vulnerable|appears to be|injectable|Type:", text):
        p, where = params[0]
        data["findings"].append(Finding(
            title="SQL injection", severity="critical", url=url, category="injection", cvss=9.8,
            description=f"Parameter '{p}' ({where}) is injectable" + (f"; back-end DBMS: {dbms.group(1).strip()}." if dbms else "."),
            evidence="\n".join(f"technique: {t}" for t in types[:5]) or text[-600:], source="sqlmap", status="confirmed",
            remediation="Use parameterised queries / prepared statements; apply least-privilege DB accounts.").to_dict())
    return data


# ----------------------------------------------------------------------------- searchsploit

def parse_searchsploit(text: str) -> list[dict[str, str]]:
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return []
    rows = obj.get("RESULTS_EXPLOIT") or []
    return [{"title": r.get("Title", ""), "edb": str(r.get("EDB-ID", "")), "type": r.get("Type", ""),
             "path": r.get("Path", "")} for r in rows[:25]]
