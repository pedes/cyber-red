"""Playbook: deterministic "what should we do next?" logic.

Given what the engagement has learned so far (hosts, services, endpoints, tech) and which tools are
available, produce an ordered, de-duplicated list of next actions. It drives ``--autopilot`` with no LLM
at all, and is also shown to the LLM each turn so even small models can follow a sound methodology.

Methodology (cheap & broad first, expensive & narrow later):
  recon        resolve names → discover live hosts → port/service scan
  enumeration  protocol-specific checks per service; web: probe → common files → crawl → content discovery
  vuln_disc.   template scanning guided by detected tech; exploit lookup for versioned services
  validation   (T2, opt-in) light input testing and injection confirmation on crawled parameters
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from ..config import Tier
from ..knowledge.banners import TLS_PORTS, is_web
from ..store.db import args_hash
from ..tools import PHASES, ArgError
from .engagement import Engagement

NUCLEI_TAGS = {"apache", "nginx", "php", "wordpress", "tomcat", "jenkins", "drupal", "joomla", "grafana", "gitlab",
               "phpmyadmin", "iis", "spring", "laravel", "django", "nodejs", "express", "angular", "react", "java"}
_TECH_ALIAS = {"microsoft-iis": "iis", "asp.net": "iis", "aspnet": "iis", "node.js": "nodejs"}


@dataclass
class Suggestion:
    tool: str
    args: dict[str, Any]
    reason: str
    phase: str
    priority: int
    display: dict[str, Any] | None = None  # args minus defaults, for human/LLM-friendly display

    @property
    def key(self) -> str:
        return args_hash(self.tool, self.args)

    def short(self) -> str:
        return f"{self.tool} {json.dumps(self.display if self.display is not None else self.args, separators=(',', ':'))[:140]}"


def _origin(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}"


def _url(scheme: str, host: str, port: int) -> str:
    default = 443 if scheme == "https" else 80
    return f"{scheme}://{host}" + ("" if port == default else f":{port}")


def _canon(url: str) -> str:
    """Canonical form so a scope seed and a discovered service produce identical (deduplicated) suggestions."""
    p = urlsplit(url)
    host = (p.hostname or "").lower()
    default = 443 if p.scheme == "https" else 80
    netloc = host if (p.port or default) == default else f"{host}:{p.port}"
    path = "" if p.path in ("", "/") else p.path
    return f"{p.scheme}://{netloc}{path}" + (f"?{p.query}" if p.query else "")


def suggest(eng: Engagement, aggressive: bool = False, thorough: bool = False) -> list[Suggestion]:
    reg, store, cfg = eng.registry, eng.store, eng.cfg
    runner = eng.runner
    out: dict[str, Suggestion] = {}

    def usable(name: str) -> bool:
        t = reg.get(name)
        return bool(t and all(runner.available(b) for b in t.requires) and t.tier in cfg.policy.allowed_tiers
                    and (t.tier != Tier.T2 or aggressive))

    def add(tool: str, args: dict[str, Any], reason: str, phase: str, prio: int) -> None:
        if not usable(tool):
            return
        try:  # normalise exactly like the executor does (fills defaults) so keys match what the store recorded
            args = reg.get(tool).validate(args)  # type: ignore[union-attr]
        except ArgError:
            return
        params = reg.get(tool).params  # type: ignore[union-attr]
        shown = {k: v for k, v in args.items() if not (k in params and params[k].default is not None and v == params[k].default)}
        s = Suggestion(tool, args, reason, phase, prio, shown)
        if s.key in out or store.attempted(tool, args) or s.key in eng.executor.declined:
            return
        out[s.key] = s

    has_nmap = usable("nmap_scan")

    def host_scan(target: str, why: str) -> None:
        if has_nmap:
            add("nmap_scan", {"targets": [target], "scan": "quick"}, why, "recon", 10)
            if thorough:
                add("nmap_scan", {"targets": [target], "scan": "full"}, f"full 65535-port sweep of {target}", "enumeration", 95)
        else:
            add("tcp_port_scan", {"targets": [target], "ports": "top100"}, why, "recon", 10)
            if thorough:
                add("tcp_port_scan", {"targets": [target], "ports": "full"}, f"full 65535-port sweep of {target}", "enumeration", 95)

    eps = store.endpoints()
    tech_by_origin: dict[str, set[str]] = {}
    for e in eps:
        if e.get("tech"):
            tech_by_origin.setdefault(_origin(e["url"]), set()).update(e["tech"].split(","))

    def web_suggestions(url: str, reason: str, tech: list[str]) -> None:
        url = _canon(url)
        tech = sorted(set(tech) | tech_by_origin.get(_origin(url), set()))
        add("http_probe", {"url": url}, f"fingerprint {reason}", "enumeration", 20)
        if url.startswith("https://"):
            p = urlsplit(url)
            add("tls_inspect", {"target": p.hostname, "port": p.port or 443}, f"inspect TLS on {reason}", "enumeration", 22)
        add("web_common_files", {"url": url}, f"look for exposed files on {reason}", "enumeration", 25)
        add("web_crawl", {"url": url}, f"map endpoints and forms on {reason}", "enumeration", 30)
        add("ffuf_discover", {"url": url}, f"content discovery on {reason}", "enumeration", 40)
        tags = sorted({_TECH_ALIAS.get(t, t) for t in tech} & NUCLEI_TAGS)
        tag_s = ",".join(tags + ["cve", "exposure", "misconfig"]) if tags else "cve,exposure,misconfig,tech"
        add("nuclei_scan", {"urls": [url], "tags": tag_s}, f"template scan of {reason}" + (f" (tech: {', '.join(tags)})" if tags else ""), "vuln_discovery", 60)

    # ------------------------------------------------------------ seeds from scope
    already_scanned: set[str] = set()
    for r in store.runs():
        try:
            a = json.loads(r["args"])
        except (TypeError, ValueError):
            continue
        if r["tool"] in ("nmap_scan", "tcp_port_scan"):
            already_scanned.update(a.get("targets", []))

    for kind, value in eng.scope.seeds():
        if kind in ("ip", "host"):
            if kind == "host":
                add("dns_lookup", {"target": value}, f"resolve {value}", "recon", 0)
            host_scan(value, f"find open ports on {value}")
        elif kind == "cidr":
            if has_nmap:
                add("nmap_scan", {"targets": [value], "scan": "discovery"}, f"discover live hosts in {value}", "recon", 5)
            else:
                add("tcp_port_scan", {"targets": [value], "ports": "22,80,443,445,3389,8080,8443"}, f"discover live hosts in {value} (common ports)", "recon", 5)
        elif kind == "url":
            web_suggestions(value, value, [])

    # discovered hosts that have not been scanned yet (e.g. after a ping sweep)
    for h in store.hosts_with_services():
        if h["services"]:
            continue
        names = {h["address"], h.get("hostname") or ""}
        if names & already_scanned:
            continue
        host_scan(h["address"], f"scan discovered host {h['address']}")

    # ------------------------------------------------------------ per-service follow-ups
    by_host: dict[str, list[dict[str, Any]]] = {}
    for s in store.services():
        by_host.setdefault(s["address"], []).append(s)

    for addr, svcs in by_host.items():
        open_ports = {s["port"] for s in svcs}
        label = svcs[0].get("hostname") or addr
        smb_ports = sorted(open_ports & {139, 445})
        if smb_ports:
            add("nmap_scripts", {"targets": [addr], "ports": ",".join(map(str, smb_ports)),
                                 "scripts": ["smb-os-discovery", "smb-security-mode", "smb2-security-mode", "smb-protocols", "smb-vuln-ms17-010"]},
                f"SMB checks on {addr}", "enumeration", 30)
        for s in svcs:
            port, name = s["port"], (s.get("name") or "").lower()
            if is_web(name, port) and not (s.get("product") or "").lower().startswith("elastic") and port != 9200:
                https = name in ("https", "ssl/http") or port in TLS_PORTS
                url = _url("https" if https else "http", label, port)
                web_suggestions(url, f"{label}:{port}", sorted(tech_by_origin.get(url, set())))
            elif name == "ftp" or port == 21:
                add("ftp_anon_check", {"target": addr, "port": port}, f"anonymous FTP on {addr}:{port}", "enumeration", 20)
            elif name in ("redis", "memcached", "elasticsearch") or port in (6379, 11211, 9200):
                svc = name if name in ("redis", "memcached", "elasticsearch") else {6379: "redis", 11211: "memcached", 9200: "elasticsearch"}[port]
                add("exposed_service_check", {"target": addr, "service": svc, "port": port}, f"unauthenticated {svc} on {addr}:{port}", "enumeration", 20)
            elif port in TLS_PORTS and port != 443:
                add("tls_inspect", {"target": label, "port": port}, f"TLS on {addr}:{port}", "enumeration", 35)
            elif name == "smtp" or port in (25, 587):
                add("nmap_scripts", {"targets": [addr], "ports": str(port), "scripts": ["smtp-commands"]}, f"SMTP info on {addr}:{port}", "enumeration", 35)
            elif name == "ldap" or port == 389:
                add("nmap_scripts", {"targets": [addr], "ports": str(port), "scripts": ["ldap-rootdse"]}, f"LDAP RootDSE on {addr}", "enumeration", 35)
            elif port == 3389:
                add("nmap_scripts", {"targets": [addr], "ports": "3389", "scripts": ["rdp-ntlm-info", "rdp-enum-encryption"]}, f"RDP info on {addr}", "enumeration", 35)
            elif port == 2049:
                add("nmap_scripts", {"targets": [addr], "ports": "2049", "scripts": ["nfs-showmount"]}, f"NFS exports on {addr}", "enumeration", 35)
            if s.get("product") and s.get("version"):
                add("searchsploit_lookup", {"query": f"{s['product']} {s['version']}"[:80], "host": addr, "port": port},
                    f"public exploits for {s['product']} {s['version']}", "vuln_discovery", 55)

    # ------------------------------------------------------------ opt-in validation (T2)
    if aggressive:
        with_params = [e for e in eps if e.get("params") and (e.get("method") or "GET") == "GET"][:8]
        for e in with_params:
            url = e["url"] if "?" in e["url"] else f"{e['url']}?" + "&".join(f"{p}=1" for p in e["params"].split(","))
            add("web_param_probe", {"url": url}, f"input testing on {e['url']}", "vuln_discovery", 70)
        for f in store.findings():
            if f["category"] == "injection" and f["url"] and f["status"] == "candidate" and "SQL" in f["title"]:
                add("sqlmap_test", {"url": f["url"]}, "confirm candidate SQL injection (detection only)", "validation", 80)

    return sorted(out.values(), key=lambda s: (PHASES.index(s.phase), s.priority, s.tool))
