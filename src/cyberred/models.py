"""Plain data models shared across the harness."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITIES = ("critical", "high", "medium", "low", "info")


def sev_rank(sev: str) -> int:
    """Lower is more severe."""
    return SEVERITIES.index(sev) if sev in SEVERITIES else len(SEVERITIES)


@dataclass
class Finding:
    title: str
    severity: str = "info"
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    host: str = ""
    port: int | None = None
    url: str = ""
    category: str = ""  # key into knowledge.attack.CATEGORY_TO_ATTACK
    cve: str = ""
    cvss: float | None = None  # estimated base score; null when unknown
    source: str = ""  # tool that produced it
    status: str = "candidate"  # candidate | confirmed
    id: int | None = None

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            self.severity = "info"

    @property
    def asset(self) -> str:
        if self.url:
            return self.url
        if self.host and self.port:
            return f"{self.host}:{self.port}"
        return self.host

    @property
    def dedupe_key(self) -> str:
        raw = "|".join([self.title.strip().lower(), self.host, str(self.port or ""), self.url])
        return hashlib.sha1(raw.encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Finding:
        known = {k: v for k, v in d.items() if k in cls.__dataclass_fields__}
        return cls(**known)


@dataclass
class ToolOutput:
    """What a tool hands back to the executor."""

    ok: bool
    text: str = ""  # raw output (stored to disk, not sent wholesale to the LLM)
    summary: str = ""  # compact, LLM-facing result
    data: dict[str, list[dict[str, Any]]] = field(default_factory=dict)  # hosts/services/endpoints/findings
    exit_code: int | None = None
