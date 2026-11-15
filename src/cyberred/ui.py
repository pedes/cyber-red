"""Terminal output: a restrained palette, light emoji use, and small rendering helpers.

Set ``NO_COLOR=1`` to disable colour and ``CYBERRED_NO_EMOJI=1`` to disable emoji.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

PALETTE = {
    "brand": "#c4727f",  # muted rose
    "accent": "#7fb0a8",  # soft teal
    "ok": "#93b98f",  # sage
    "warn": "#d8ab62",  # sand
    "err": "#cf6f78",  # dusty red
    "info": "#8ca6c9",  # slate blue
    "muted": "#7b8490",  # grey
    "text": "#d4d7dc",
}

SEV_STYLE = {
    "critical": "bold #c0485c",
    "high": "#cf6f78",
    "medium": "#d8ab62",
    "low": "#8ca6c9",
    "info": "#7b8490",
}
TIER_STYLE = {"T0": "#7fb0a8", "T1": "#8ca6c9", "T2": "#d8ab62", "T3": "#cf6f78"}

THEME = Theme({k: v for k, v in PALETTE.items()} | {"brand": f"bold {PALETTE['brand']}"})

console = Console(theme=THEME, highlight=False)

_EMOJI_ON = not os.environ.get("CYBERRED_NO_EMOJI")
_E = {
    "shield": "🛡️",
    "scan": "🔎",
    "web": "🌐",
    "net": "📡",
    "tool": "🔧",
    "ok": "✅",
    "warn": "⚠️",
    "block": "⛔",
    "flag": "🚩",
    "report": "📝",
    "target": "🎯",
    "brain": "🧠",
    "lock": "🔐",
    "bug": "🐞",
    "stop": "🛑",
    "clock": "⏱️",
    "box": "📦",
    "key": "🔑",
    "spark": "✨",
    "hint": "💡",
    "dns": "🧭",
    "tls": "🔒",
}


def em(name: str) -> str:
    """Return an emoji followed by a space, or '' when emoji are disabled."""
    return f"{_E.get(name, '')} " if _EMOJI_ON else ""


def set_emoji(enabled: bool) -> None:
    global _EMOJI_ON
    _EMOJI_ON = enabled


# --------------------------------------------------------------------------- basics


def banner(version: str, subtitle: str = "offensive-security agent · authorized testing only") -> None:
    title = Text.assemble((em("shield"), ""), ("CyberRed", "brand"), (f"  v{version}", "muted"))
    body = Text(subtitle, style="muted")
    console.print(Panel(body, title=title, title_align="left", border_style="muted", box=box.ROUNDED, padding=(0, 2)))


def rule(title: str, icon: str = "") -> None:
    console.rule(Text(f"{em(icon)}{title}" if icon else title, style="accent"), style="muted")


def info(msg: str, icon: str = "") -> None:
    console.print(f"[info]{em(icon)}{msg}[/]")


def ok(msg: str) -> None:
    console.print(f"[ok]{em('ok')}{msg}[/]")


def warn(msg: str) -> None:
    console.print(f"[warn]{em('warn')}{msg}[/]")


def err(msg: str) -> None:
    console.print(f"[err]{em('block')}{msg}[/]")


def muted(msg: str) -> None:
    console.print(f"[muted]{msg}[/]")


def sev_text(sev: str) -> Text:
    return Text(f"● {sev}", style=SEV_STYLE.get(sev, "muted"))


def tier_text(tier: str) -> Text:
    return Text(tier, style=TIER_STYLE.get(tier, "muted"))


# --------------------------------------------------------------------------- engagement events

_TOOL_ICON = {
    "dns_lookup": "dns",
    "tcp_port_scan": "net",
    "nmap_scan": "net",
    "nmap_scripts": "net",
    "nmap_scripts_intrusive": "net",
    "http_probe": "web",
    "web_common_files": "web",
    "web_crawl": "web",
    "web_param_probe": "bug",
    "ffuf_discover": "web",
    "nuclei_scan": "bug",
    "nuclei_scan_intrusive": "bug",
    "sqlmap_test": "bug",
    "tls_inspect": "tls",
    "ftp_anon_check": "key",
    "exposed_service_check": "key",
    "searchsploit_lookup": "scan",
    "cve_lookup": "scan",
}


def step(n: int, tool: str, target: str, tier: str) -> None:
    icon = em(_TOOL_ICON.get(tool, "tool"))
    line = Text.assemble(
        (f"{n:>3} ", "muted"),
        (icon, ""),
        (f"{tool}", "text"),
        ("  ", ""),
        (target[:70], "info"),
        ("  ", ""),
        (f"[{tier}]", TIER_STYLE.get(tier, "muted")),
    )
    console.print(line)


def result(ok_: bool, text: str, secs: float | None = None) -> None:
    mark = Text("   ↳ ", style="muted")
    style = "ok" if ok_ else "err"
    tail = f"  ({secs:.1f}s)" if secs is not None else ""
    console.print(Text.assemble(mark, (text, style), (tail, "muted")))


def blocked(text: str) -> None:
    console.print(Text.assemble(Text("   ↳ ", style="muted"), (f"{em('block')}{text}", "err")))


def finding_line(sev: str, title: str, asset: str) -> None:
    console.print(
        Text.assemble(Text("   ↳ ", style="muted"), (f"{em('bug')}", ""), sev_text(sev), (f"  {title}", "text"), (f"  {asset}", "muted"))
    )


def flag_line(value: str) -> None:
    console.print(Text.assemble(Text("   ↳ ", style="muted"), (f"{em('flag')}flag captured: ", "warn"), (value, "text")))


def phase_banner(phase: str) -> None:
    rule(f"phase · {phase}", "scan")


def approval_panel(tool: str, tier: str, targets: Sequence[str], reason: str, args_preview: str) -> None:
    body = Text()
    body.append("tool    ", style="muted")
    body.append(f"{tool}\n", style="text")
    body.append("tier    ", style="muted")
    body.append(f"{tier}\n", style=TIER_STYLE.get(tier, "muted"))
    body.append("targets ", style="muted")
    body.append(", ".join(targets)[:200] + "\n", style="info")
    if reason:
        body.append("reason  ", style="muted")
        body.append(f"{reason[:240]}\n", style="text")
    body.append("args    ", style="muted")
    body.append(args_preview[:300], style="muted")
    console.print(
        Panel(body, title=f"{em('lock')}approval required", title_align="left", border_style="warn", box=box.ROUNDED)
    )


# --------------------------------------------------------------------------- tables


def findings_table(findings: Iterable[Mapping[str, Any]], title: str = "Findings") -> Table:
    t = Table(title=f"{em('bug')}{title}", title_justify="left", box=box.SIMPLE_HEAD, header_style="muted", pad_edge=False)
    t.add_column("#", justify="right", style="muted")
    t.add_column("Severity")
    t.add_column("Finding", style="text", overflow="fold")
    t.add_column("Asset", style="info", overflow="fold")
    t.add_column("State", style="muted")
    for f in findings:
        asset = f.get("url") or (f"{f.get('host', '')}:{f['port']}" if f.get("port") else f.get("host", ""))
        t.add_row(str(f.get("id", "")), sev_text(f["severity"]), f["title"], asset, f.get("status", ""))
    return t


def hosts_table(hosts: Iterable[Mapping[str, Any]]) -> Table:
    t = Table(title=f"{em('net')}Attack surface", title_justify="left", box=box.SIMPLE_HEAD, header_style="muted", pad_edge=False)
    t.add_column("Host", style="info")
    t.add_column("Port", justify="right", style="muted")
    t.add_column("Service", style="text")
    t.add_column("Product / version", style="muted", overflow="fold")
    for h in hosts:
        label = h["address"] + (f" ({h['hostname']})" if h.get("hostname") else "")
        services = h.get("services") or []
        if not services:
            t.add_row(label, "", "", "")
        for i, s in enumerate(services):
            pv = " ".join(x for x in (s.get("product"), s.get("version")) if x)
            t.add_row(label if i == 0 else "", f"{s['port']}/{s['proto']}", s.get("name") or "", pv)
    return t


def summary_panel(counts: Mapping[str, int], sev_counts: Mapping[str, int], flags: int, runs: int, secs: float) -> None:
    body = Text()
    body.append(f"{counts.get('hosts', 0)} hosts · {counts.get('services', 0)} services · {counts.get('endpoints', 0)} endpoints · {runs} tool runs · {secs:.0f}s\n", style="muted")
    parts = []
    for sev in ("critical", "high", "medium", "low", "info"):
        n = sev_counts.get(sev, 0)
        if n:
            parts.append(Text(f"{n} {sev}", style=SEV_STYLE[sev]))
    if parts:
        for i, p in enumerate(parts):
            body.append_text(p)
            if i < len(parts) - 1:
                body.append("  ·  ", style="muted")
    else:
        body.append("no findings recorded", style="muted")
    if flags:
        body.append(f"\n{em('flag')}{flags} flag(s) captured", style="warn")
    console.print(Panel(body, title=f"{em('spark')}engagement summary", title_align="left", border_style="accent", box=box.ROUNDED))
