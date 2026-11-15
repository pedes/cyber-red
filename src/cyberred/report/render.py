"""Report rendering, always generated from the findings store and audit log, never from model memory."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from .. import __version__
from ..knowledge.attack import attack_for
from ..models import SEVERITIES
from ..store import Store, verify_audit_log

_SEV_ICON = {"critical": "🟣", "high": "🔴", "medium": "🟠", "low": "🔵", "info": "⚪"}


def _load_cfg(ws: Path) -> dict[str, Any]:
    p = ws / "config.json"
    return json.loads(p.read_text()) if p.exists() else {}


def _asset(f: dict[str, Any]) -> str:
    if f.get("url"):
        return f["url"]
    return f"{f['host']}:{f['port']}" if f.get("port") else f.get("host", "")


def _bar(n: int, total: int, width: int = 24) -> str:
    return "█" * (round(width * n / total) if total else 0)


def render_markdown(ws: Path, store: Store) -> str:
    cfg, meta = _load_cfg(ws), store
    eng = cfg.get("engagement", {})
    findings = store.findings()
    counts = store.severity_counts()
    total = sum(counts.values())
    ok, nlog, _ = verify_audit_log(ws / "audit.jsonl") if (ws / "audit.jsonl").exists() else (True, 0, None)
    L: list[str] = []
    L += [f"# Security assessment: {eng.get('name', ws.name)}", ""]
    L += ["| | |", "|---|---|",
          f"| **Mode** | {eng.get('mode', '?')} |",
          f"| **Authorization** | {eng.get('authorization') or '—'} |",
          f"| **Started** | {meta.get_meta('started', '?')} |",
          f"| **Finished** | {meta.get_meta('finished', 'in progress')} |",
          f"| **Tool** | CyberRed {__version__} |",
          f"| **Audit log** | {nlog} records, hash chain {'intact ✅' if ok else 'BROKEN ⚠️'} |", ""]
    sc = cfg.get("scope", {})
    L += ["## Scope", "", "**In scope:** " + (", ".join(f"`{x}`" for x in sc.get("include", [])) or "—"), ""]
    if sc.get("exclude"):
        L += ["**Excluded:** " + ", ".join(f"`{x}`" for x in sc["exclude"]), ""]

    L += ["## Executive summary", ""]
    c = store.counts()
    L += [f"CyberRed examined **{c['hosts']} host(s)**, **{c['services']} service(s)** and **{c['endpoints']} web endpoint(s)** "
          f"across **{c['runs']} tool runs**, and recorded **{total} finding(s)**.", ""]
    if total:
        L += ["| Severity | Count | |", "|---|---:|---|"]
        for s in SEVERITIES:
            L.append(f"| {_SEV_ICON[s]} {s.title()} | {counts[s]} | {_bar(counts[s], total)} |")
        L.append("")
        top = [f for f in findings if f["severity"] in ("critical", "high")][:5]
        if top:
            L += ["**Priority items:**", ""] + [f"- **{f['title']}** ({f['severity']}) — `{_asset(f)}`" for f in top] + [""]
    flags = store.flags()
    if flags:
        L += ["## 🚩 Flags", ""] + [f"- `{f['value']}` (from {f['source']})" for f in flags] + [""]

    L += ["## Attack surface", ""]
    for h in store.hosts_with_services():
        L.append(f"### {h['address']}" + (f" ({h['hostname']})" if h.get("hostname") else "") + (f" — {h['os']}" if h.get("os") else ""))
        if h["services"]:
            L += ["", "| Port | Service | Product / version |", "|---:|---|---|"]
            for s in h["services"]:
                L.append(f"| {s['port']}/{s['proto']} | {s['name'] or ''} | {' '.join(x for x in (s['product'], s['version']) if x)} |")
        L.append("")
    eps = store.endpoints()
    if eps:
        L += ["### Web endpoints", "", "| URL | Status | Notes |", "|---|---:|---|"]
        for e in eps[:60]:
            note = " ".join(x for x in (e.get("title") or "", f"tech: {e['tech']}" if e.get("tech") else "", f"params: {e['params']}" if e.get("params") else "") if x)
            L.append(f"| {e['url']} | {e.get('status') or ''} | {note[:90]} |")
        if len(eps) > 60:
            L.append(f"\n_…and {len(eps) - 60} more_")
        L.append("")

    L += ["## Findings", ""]
    if not findings:
        L += ["No findings were recorded.", ""]
    for f in findings:
        L += [f"### {_SEV_ICON[f['severity']]} #{f['id']} · {f['title']}", ""]
        meta_bits = [f"**Severity:** {f['severity']}", f"**Status:** {f['status']}", f"**Asset:** `{_asset(f)}`"]
        if f.get("cve"):
            meta_bits.append(f"**CVE:** {f['cve']}")
        if f.get("cvss") is not None:
            meta_bits.append(f"**CVSS (est.):** {f['cvss']}")
        at = attack_for(f.get("category", ""))
        if at:
            meta_bits.append(f"**ATT&CK:** {at[0]} {at[1]}")
        L += [" · ".join(meta_bits), ""]
        if f.get("description"):
            L += [f["description"], ""]
        if f.get("evidence"):
            L += ["**Evidence**", "", "```text", f["evidence"].strip()[:1200], "```", ""]
        if f.get("remediation"):
            L += [f"**Remediation:** {f['remediation']}", ""]
        L += [f"_Detected by: {f['source']}_", ""]

    attack_rows: dict[str, tuple[str, int]] = {}
    for f in findings:
        at = attack_for(f.get("category", ""))
        if at:
            name, n = attack_rows.get(at[0], (at[1], 0))
            attack_rows[at[0]] = (name, n + 1)
    if attack_rows:
        L += ["## MITRE ATT&CK mapping", "", "| Technique | Name | Findings |", "|---|---|---:|"]
        L += [f"| {tid} | {name} | {n} |" for tid, (name, n) in sorted(attack_rows.items())]
        L.append("")

    runs = store.runs()
    L += ["## Methodology & timeline", "", "| # | Tool | Status | Time |", "|---:|---|---|---:|"]
    L += [f"| {r['id']} | `{r['tool']}` | {r['status']} | {(r['duration'] or 0):.1f}s |" for r in runs[:100]]
    L += ["", "---", "_Generated by CyberRed from the findings database and audit log. Version-based findings are candidates "
          "until independently verified. Use only against systems you are authorized to test._", ""]
    return "\n".join(L)


def render_json(ws: Path, store: Store) -> str:
    return json.dumps({
        "tool": f"cyberred {__version__}", "engagement": _load_cfg(ws).get("engagement", {}),
        "scope": _load_cfg(ws).get("scope", {}), "generated": datetime.now().isoformat(timespec="seconds"),
        "counts": store.counts(), "severity_counts": store.severity_counts(),
        "hosts": store.hosts_with_services(), "endpoints": store.endpoints(), "findings": store.findings(),
        "flags": store.flags(), "runs": [{k: r[k] for k in ("id", "tool", "args", "status", "duration")} for r in store.runs()],
    }, indent=2, default=str)


def render_writeup(ws: Path, store: Store) -> str:
    """Narrative CTF-style write-up reconstructed from the audit log and tool runs."""
    eng = _load_cfg(ws).get("engagement", {})
    L = [f"# Write-up: {eng.get('name', ws.name)}", "", f"_Reconstructed from the audit log by CyberRed {__version__}._", ""]
    flags = store.flags()
    if flags:
        L += ["## 🚩 Flags", ""] + [f"- `{f['value']}`" for f in flags] + [""]
    L += ["## Walkthrough", ""]
    for i, r in enumerate(store.runs(), 1):
        if r["status"] != "ok":
            continue
        L += [f"### Step {i}: `{r['tool']}`", "", f"Arguments: `{r['args']}`", "", "```text", (r["summary"] or "").strip()[:900], "```", ""]
    fs = store.findings()
    if fs:
        L += ["## Issues identified", ""] + [f"- **[{f['severity']}] {f['title']}** at `{_asset(f)}`" for f in fs] + [""]
    return "\n".join(L)
