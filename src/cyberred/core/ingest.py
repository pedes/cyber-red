"""Merge structured tool output into the findings store and derive follow-up findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..knowledge.hints import exposure_for, hints_for
from ..models import Finding
from ..store import Store


@dataclass
class IngestResult:
    new_findings: list[Finding] = field(default_factory=list)
    new_hosts: int = 0
    new_services: int = 0
    new_endpoints: int = 0


def _add(store: Store, f: Finding, res: IngestResult) -> None:
    fid, created = store.add_finding(f)
    if created:
        f.id = fid
        res.new_findings.append(f)


def ingest(store: Store, data: dict[str, list[dict[str, Any]]], tool: str) -> IngestResult:
    res = IngestResult()
    before_hosts = len(store.hosts_with_services())
    for h in data.get("hosts", []):
        store.upsert_host(h["address"], h.get("hostname"), h.get("os"))
    res.new_hosts = len(store.hosts_with_services()) - before_hosts

    for s in data.get("services", []):
        _, changed = store.upsert_service(
            s["address"], int(s["port"]), s.get("proto", "tcp"), s.get("name"), s.get("product"), s.get("version"),
            s.get("banner"), s.get("extra"), s.get("hostname"))
        if not changed:
            continue
        res.new_services += 1
        exp = exposure_for(int(s["port"]), s["address"])
        if exp:
            exp.source = tool
            _add(store, exp, res)
        for hint in hints_for(s.get("product"), s.get("version"), s["address"], int(s["port"])):
            _add(store, hint, res)

    for e in data.get("endpoints", []):
        if store.add_endpoint(e["url"], e.get("status"), e.get("title"), e.get("tech"), e.get("params"),
                              e.get("source") or tool, e.get("method", "GET")):
            res.new_endpoints += 1

    for d in data.get("findings", []):
        f = Finding.from_dict(d)
        f.source = f.source or tool
        _add(store, f, res)
    return res
