"""Wrappers around external security tools (nmap, nuclei, ffuf, sqlmap, searchsploit).

Each wrapper builds an argv list from validated, typed parameters. There is no shell and no free-form
flag injection: values never start with '-', free text is pattern-checked, and dangerous capabilities
(sqlmap --os-shell/--dump/--file-*, nmap brute scripts, ...) simply aren't exposed.
"""

from __future__ import annotations

import re
from typing import Any

from ..config import Tier
from ..models import ToolOutput
from ..parsers import parse_ffuf, parse_nmap_xml, parse_nuclei, parse_searchsploit, parse_sqlmap
from ..policy import Resolved
from .base import Param, Registry, Tool, ToolContext
from .util import PORT_SPEC_RE, flatten_addresses, fmt_services

SAFE_SCRIPTS = (
    "smb-os-discovery", "smb-security-mode", "smb2-security-mode", "smb-protocols", "smb-vuln-ms17-010", "ftp-anon",
    "ssh2-enum-algos", "ssh-hostkey", "smtp-commands", "snmp-info", "ldap-rootdse", "dns-nsid", "nfs-showmount",
    "rdp-ntlm-info", "rdp-enum-encryption", "http-title", "http-headers", "http-methods", "ssl-cert",
)
INTRUSIVE_SCRIPTS = ("smb-enum-shares", "smb-enum-users", "ssh-auth-methods", "dns-zone-transfer", "ldap-search",
                     "nfs-ls", "ssl-enum-ciphers")


def _hosts_map(ctx: ToolContext, res: dict[str, list[Resolved]]) -> dict[str, str]:
    """name -> ip pairs so Docker tools resolve the same addresses the scope engine pinned."""
    out = {k: v.split(",")[0] for k, v in ctx.scope.static_hosts.items()}
    for lst in res.values():
        for r in lst:
            if r.kind in ("host", "url") and not re.fullmatch(r"[\d.:a-fA-F]+", r.host) and r.addresses:
                out[r.host] = r.addresses[0]
    return out


async def _exec(ctx: ToolContext, argv: list[str], timeout: float, res: dict[str, list[Resolved]]):
    return await ctx.runner.run(argv, timeout=timeout, hosts=_hosts_map(ctx, res))


def _fail(r: Any, what: str) -> ToolOutput:
    if r.timed_out:
        return ToolOutput(False, "timed out", f"{what} timed out", exit_code=None)
    msg = (r.stderr or r.stdout or "no output").strip()[-400:]
    return ToolOutput(False, msg, f"{what} failed (exit {r.exit_code}): {msg}", exit_code=r.exit_code)


# --------------------------------------------------------------------------- nmap

async def _nmap_scan(ctx: ToolContext, args: dict[str, Any], res: dict[str, list[Resolved]]) -> ToolOutput:
    try:
        addrs = [a for a, _ in flatten_addresses(res["targets"])]
    except ValueError as e:
        return ToolOutput(False, str(e), f"error: {e}")
    scan = args.get("scan", "quick")
    argv = ["nmap", "-oX", "-", "-n", "--open", "-T3", "--max-rate", str(ctx.cfg.policy.rate_limit.max_packets_per_second)]
    if scan == "discovery":
        argv += ["-sn"]
    else:
        argv += ["-sV", "--version-intensity", "5"]
        if args.get("skip_ping", True):
            argv += ["-Pn"]
        argv += {"quick": ["--top-ports", "100"], "standard": ["--top-ports", "1000"], "full": ["-p-"]}[scan]
    argv += addrs
    r = await _exec(ctx, argv, 3600 if scan == "full" else 1200, res)
    if r.exit_code != 0 or "<nmaprun" not in r.stdout:
        return _fail(r, "nmap")
    data = parse_nmap_xml(r.stdout)
    # keep original host names attached to their addresses
    names = {a: n for a, n in flatten_addresses(res["targets"]) if n}
    for h in data["hosts"]:
        h["hostname"] = h.get("hostname") or names.get(h["address"])
    for s in data["services"]:
        s["hostname"] = names.get(s["address"])
    if scan == "discovery":
        summary = f"{len(data['hosts'])} host(s) up: " + ", ".join(h["address"] for h in data["hosts"][:40])
    else:
        summary = fmt_services(data["services"]) or "no open ports found"
    return ToolOutput(True, r.stdout, summary, data, r.exit_code)


async def _nmap_scripts_impl(ctx: ToolContext, args: dict[str, Any], res: dict[str, list[Resolved]], allowed: tuple[str, ...]) -> ToolOutput:
    try:
        addrs = [a for a, _ in flatten_addresses(res["targets"])]
    except ValueError as e:
        return ToolOutput(False, str(e), f"error: {e}")
    scripts = [s for s in args["scripts"] if s in allowed]
    if not scripts:
        return ToolOutput(False, "no allowed scripts", f"none of the requested scripts are allowed; choose from {list(allowed)}")
    argv = ["nmap", "-oX", "-", "-n", "-Pn", "-sV", "-p", args["ports"].replace(" ", ""), "--script", ",".join(scripts),
            "-T3", "--max-rate", str(ctx.cfg.policy.rate_limit.max_packets_per_second)] + addrs
    r = await _exec(ctx, argv, 1200, res)
    if r.exit_code != 0 or "<nmaprun" not in r.stdout:
        return _fail(r, "nmap scripts")
    data = parse_nmap_xml(r.stdout)
    lines = [f"scripts {', '.join(scripts)} on {len(addrs)} host(s)"]
    lines += [f"  [{f['severity']}] {f['title']} ({f.get('host', '')}:{f.get('port') or ''})" for f in data["findings"]]
    if not data["findings"]:
        lines.append("  no issues flagged by these scripts")
    return ToolOutput(True, r.stdout, "\n".join(lines), data, r.exit_code)


async def _nmap_scripts(ctx, args, res):
    return await _nmap_scripts_impl(ctx, args, res, SAFE_SCRIPTS)


async def _nmap_scripts_intrusive(ctx, args, res):
    return await _nmap_scripts_impl(ctx, args, res, INTRUSIVE_SCRIPTS)


# --------------------------------------------------------------------------- nuclei

def _nuclei_argv(ctx: ToolContext, args: dict[str, Any], res: dict[str, list[Resolved]], intrusive: bool) -> list[str]:
    argv = ["nuclei", "-jsonl", "-silent", "-no-color", "-duc", "-timeout", "8", "-retries", "1", "-c", "10",
            "-rl", str(ctx.cfg.policy.rate_limit.max_http_requests_per_second),
            "-severity", args.get("severity", "low,medium,high,critical"),
            "-etags", "dos" if intrusive else "dos,intrusive,bruteforce,fuzz"]
    if args.get("tags"):
        argv += ["-tags", args["tags"]]
    for r in res["urls"]:
        argv += ["-u", r.url or r.host]
    return argv


async def _nuclei(ctx, args, res, intrusive=False):
    r = await _exec(ctx, _nuclei_argv(ctx, args, res, intrusive), 3600, res)
    if r.exit_code not in (0, None) and not r.stdout.strip():
        return _fail(r, "nuclei")
    data = parse_nuclei(r.stdout)
    fs = data["findings"]
    summary = f"nuclei: {len(fs)} match(es)" + "".join(f"\n  [{f['severity']}] {f['title']} @ {f['url'] or f['host']}" for f in fs[:25])
    return ToolOutput(True, r.stdout, summary, data, r.exit_code)


async def _nuclei_intrusive(ctx, args, res):
    return await _nuclei(ctx, args, res, True)


# --------------------------------------------------------------------------- ffuf

async def _ffuf(ctx: ToolContext, args: dict[str, Any], res: dict[str, list[Resolved]]) -> ToolOutput:
    t = res["url"][0]
    base = (t.url or "").split("?")[0].rstrip("/")
    wl = ctx.workspace / "wordlists" / ("small.txt" if args.get("wordlist", "small") == "small" else "medium.txt")
    if not wl.exists():
        wl = ctx.workspace / "wordlists" / "small.txt"
    argv = ["ffuf", "-u", f"{base}/FUZZ", "-w", ctx.runner.map_path(wl), "-mc", args.get("match_codes", "200,204,301,302,307,401,403"),
            "-ac", "-t", "10", "-timeout", "8", "-rate", str(ctx.cfg.policy.rate_limit.max_http_requests_per_second),
            "-noninteractive", "-json"]
    if args.get("extensions"):
        argv += ["-e", args["extensions"]]
    r = await _exec(ctx, argv, 1800, res)
    if not r.stdout.strip() and r.exit_code not in (0, None):
        return _fail(r, "ffuf")
    data = parse_ffuf(r.stdout)
    eps = data["endpoints"]
    summary = f"ffuf: {len(eps)} path(s) on {base}" + "".join(f"\n  {e['status']} {e['url']}" for e in eps[:30])
    return ToolOutput(True, r.stdout, summary, data, r.exit_code)


# --------------------------------------------------------------------------- sqlmap (T2)

async def _sqlmap(ctx: ToolContext, args: dict[str, Any], res: dict[str, list[Resolved]]) -> ToolOutput:
    t = res["url"][0]
    out_dir = ctx.runner.map_path(ctx.workspace / "sqlmap")
    argv = ["sqlmap", "-u", t.url or "", "--batch", "--level", "1", "--risk", "1", "--threads", "1", "--timeout", "15",
            "--retries", "1", "--time-sec", "5", "--random-agent", "--disable-coloring", "--output-dir", out_dir]
    if args.get("data"):
        argv += ["--data", args["data"]]
    if args.get("param"):
        argv += ["-p", args["param"]]
    r = await _exec(ctx, argv, 900, res)
    data = parse_sqlmap(r.stdout, t.url or "")
    if data["findings"]:
        f = data["findings"][0]
        summary = f"sqlmap: VULNERABLE — {f['description']}"
    elif r.timed_out:
        return _fail(r, "sqlmap")
    else:
        summary = "sqlmap: no injection confirmed at level 1 / risk 1"
    return ToolOutput(True, r.stdout + "\n" + r.stderr[-500:], summary, data, r.exit_code)


# --------------------------------------------------------------------------- searchsploit (T0)

async def _searchsploit(ctx: ToolContext, args: dict[str, Any], res: dict[str, list[Resolved]]) -> ToolOutput:
    terms = args["query"].split()
    if any(t.startswith("-") for t in terms):
        return ToolOutput(False, "bad query", "query terms may not start with '-'")
    r = await ctx.runner.run(["searchsploit", "--json", *terms], timeout=60)
    hits = parse_searchsploit(r.stdout)
    if not hits:
        return ToolOutput(True, r.stdout, f"no public exploits found for '{args['query']}'")
    lines = [f"{len(hits)} public exploit reference(s) for '{args['query']}':"] + [f"  EDB-{h['edb']}: {h['title']}" for h in hits[:12]]
    findings = []
    if args.get("host"):
        findings.append({"title": f"Public exploit references exist for {args['query']}", "severity": "info", "host": args["host"],
                         "port": args.get("port"), "category": "known-vuln", "source": "searchsploit", "status": "candidate",
                         "description": "Exploit-DB lists exploits matching this product/version. Applicability must be verified.",
                         "evidence": "\n".join(f"EDB-{h['edb']}: {h['title']}" for h in hits[:8]),
                         "remediation": "Patch or upgrade the affected software."})
    return ToolOutput(True, r.stdout, "\n".join(lines), {"findings": findings}, r.exit_code)


def register(reg: Registry) -> None:
    tgt = lambda desc: Param("array", desc, max_items=64)  # noqa: E731
    reg.register(Tool(
        "nmap_scan",
        "nmap service/version scan. scan='discovery' (ping sweep), 'quick' (top 100 ports), 'standard' (top 1000), 'full' (all 65535).",
        Tier.T1, ("recon", "enumeration"),
        {"targets": tgt("Hosts/IPs/CIDRs in scope"),
         "scan": Param("string", "Scan depth", required=False, default="quick", enum=("discovery", "quick", "standard", "full")),
         "skip_ping": Param("boolean", "Treat hosts as up (-Pn); recommended for CTF/HTB", required=False, default=True)},
        _nmap_scan, target_args=("targets",), requires=("nmap",), timeout=3600))
    reg.register(Tool(
        "nmap_scripts", "Run a curated set of SAFE nmap NSE scripts (SMB, SSH, FTP anon, SMTP, LDAP, NFS, RDP, SNMP, TLS cert, HTTP).",
        Tier.T1, ("enumeration", "vuln_discovery"),
        {"targets": tgt("Hosts/IPs in scope"), "ports": Param("string", "Ports, e.g. '445' or '22,80'", pattern=PORT_SPEC_RE),
         "scripts": Param("array", "Script names", enum=SAFE_SCRIPTS, max_items=10)},
        _nmap_scripts, target_args=("targets",), requires=("nmap",), timeout=1200))
    reg.register(Tool(
        "nmap_scripts_intrusive", "Run INTRUSIVE nmap scripts (SMB share/user enumeration, zone transfer, LDAP search, cipher enumeration). Requires approval.",
        Tier.T2, ("enumeration", "validation"),
        {"targets": tgt("Hosts/IPs in scope"), "ports": Param("string", "Ports", pattern=PORT_SPEC_RE),
         "scripts": Param("array", "Script names", enum=INTRUSIVE_SCRIPTS, max_items=6)},
        _nmap_scripts_intrusive, target_args=("targets",), requires=("nmap",), timeout=1200))
    reg.register(Tool(
        "nuclei_scan", "Template-based vulnerability scan of web URLs (non-intrusive templates only). Pass tags from detected tech to focus it.",
        Tier.T1, ("vuln_discovery",),
        {"urls": Param("array", "Base URLs in scope", max_items=16),
         "tags": Param("string", "Comma-separated nuclei tags, e.g. 'wordpress,apache'", required=False, pattern=r"[a-z0-9_,\-]{1,120}"),
         "severity": Param("string", "Severities", required=False, default="low,medium,high,critical", pattern=r"(info|low|medium|high|critical)(,(info|low|medium|high|critical))*")},
        _nuclei, target_args=("urls",), requires=("nuclei",), timeout=3600))
    reg.register(Tool(
        "nuclei_scan_intrusive", "Nuclei including intrusive templates (excludes only DoS). Requires approval.",
        Tier.T2, ("validation",),
        {"urls": Param("array", "Base URLs in scope", max_items=8),
         "tags": Param("string", "Nuclei tags", required=False, pattern=r"[a-z0-9_,\-]{1,120}"),
         "severity": Param("string", "Severities", required=False, default="medium,high,critical", pattern=r"(info|low|medium|high|critical)(,(info|low|medium|high|critical))*")},
        _nuclei_intrusive, target_args=("urls",), requires=("nuclei",), timeout=3600))
    reg.register(Tool(
        "ffuf_discover", "Directory/file discovery with ffuf using an auto-calibrated, rate-limited wordlist.",
        Tier.T1, ("enumeration",),
        {"url": Param("string", "Base URL", max_len=1024),
         "wordlist": Param("string", "Wordlist", required=False, default="small", enum=("small", "medium")),
         "extensions": Param("string", "Comma-separated, e.g. '.php,.bak'", required=False, pattern=r"[.\w,]{1,60}", allow_dash=False),
         "match_codes": Param("string", "HTTP codes to keep", required=False, default="200,204,301,302,307,401,403", pattern=r"[0-9,]{1,40}")},
        _ffuf, target_args=("url",), requires=("ffuf",), timeout=1800))
    reg.register(Tool(
        "sqlmap_test", "Confirm SQL injection with sqlmap at level 1 / risk 1 (detection only: no dumping, no shells). Requires approval.",
        Tier.T2, ("validation",),
        {"url": Param("string", "URL with the parameter to test", max_len=1024),
         "param": Param("string", "Parameter name to test", required=False, pattern=r"[\w\-\[\]\.]{1,64}"),
         "data": Param("string", "POST body", required=False, max_len=1024)},
        _sqlmap, target_args=("url",), requires=("sqlmap",), timeout=900))
    reg.register(Tool(
        "searchsploit_lookup", "Search the local Exploit-DB for public exploits matching a product/version (offline; no target contact).",
        Tier.T0, ("enumeration", "vuln_discovery"),
        {"query": Param("string", "e.g. 'vsftpd 2.3.4'", pattern=r"[A-Za-z0-9 ._/\-]{2,80}"),
         "host": Param("string", "Host label to attach the result to", required=False, pattern=r"[A-Za-z0-9.:\-]{1,80}"),
         "port": Param("integer", "Port label", required=False, minimum=1, maximum=65535)},
        _searchsploit, requires=("searchsploit",), timeout=60))
