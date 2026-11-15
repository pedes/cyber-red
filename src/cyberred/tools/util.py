"""Small helpers shared by tool implementations."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from typing import Any

from ..policy import Resolved

TOP20 = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
TOP100 = sorted(set(TOP20 + [
    81, 88, 119, 123, 161, 179, 389, 427, 465, 500, 513, 514, 515, 543, 544, 548, 554, 587, 631, 636, 873, 990, 1025,
    1080, 1099, 1433, 1521, 1720, 2049, 2121, 2375, 3000, 3128, 3268, 3632, 4443, 4848, 5000, 5060, 5432, 5601,
    5632, 5800, 5985, 5986, 6000, 6379, 6443, 7001, 7070, 8000, 8008, 8081, 8443, 8888, 9000, 9090, 9200, 9300,
    9418, 9999, 10000, 11211, 27017, 50000,
]))


def parse_ports(spec: str) -> list[int]:
    """'top20' | 'top100' | 'full' | '22,80,8000-8100' -> sorted unique ports."""
    spec = spec.strip().lower()
    if spec == "top20":
        return list(TOP20)
    if spec == "top100":
        return list(TOP100)
    if spec in ("full", "all", "-"):
        return list(range(1, 65536))
    ports: set[int] = set()
    for tok in spec.split(","):
        tok = tok.strip()
        if not tok:
            continue
        if "-" in tok:
            a, _, b = tok.partition("-")
            if not (a.isdigit() and b.isdigit()):
                raise ValueError(f"bad port range '{tok}'")
            lo, hi = int(a), int(b)
            if not (1 <= lo <= hi <= 65535):
                raise ValueError(f"port range out of bounds '{tok}'")
            ports.update(range(lo, hi + 1))
        elif tok.isdigit() and 1 <= int(tok) <= 65535:
            ports.add(int(tok))
        else:
            raise ValueError(f"bad port '{tok}'")
    if not ports:
        raise ValueError("no ports given")
    return sorted(ports)


PORT_SPEC_RE = r"(top20|top100|full|[0-9,\- ]{1,200})"


def flatten_addresses(resolved: Iterable[Resolved], cap: int = 4096) -> list[tuple[str, str | None]]:
    """(address, original hostname or None) for every address, de-duplicated."""
    seen: dict[str, str | None] = {}
    for r in resolved:
        for a in r.addresses:
            if a not in seen or (seen[a] is None and r.kind in ("host", "url")):
                seen[a] = r.host if r.kind in ("host", "url") else None
    items = list(seen.items())
    if len(items) > cap:
        raise ValueError(f"too many hosts ({len(items)}); narrow the target list")
    return items


def is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def fmt_services(services: list[dict[str, Any]], limit: int = 40) -> str:
    by_host: dict[str, list[dict[str, Any]]] = {}
    for s in services:
        by_host.setdefault(s["address"], []).append(s)
    lines = []
    for addr, svcs in by_host.items():
        parts = []
        for s in sorted(svcs, key=lambda x: x["port"])[:limit]:
            pv = " ".join(x for x in (s.get("product"), s.get("version")) if x)
            parts.append(f"{s['port']}/{s.get('proto', 'tcp')} {s.get('name') or '?'}" + (f" {pv}" if pv else ""))
        lines.append(f"{addr}: " + "; ".join(parts))
    return "\n".join(lines)


def trunc(s: str, n: int) -> str:
    return s if len(s) <= n else s[: n - 20] + f"\n…[+{len(s) - n + 20} chars]"
