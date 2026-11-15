"""Append-only, hash-chained JSONL audit log.

Each record carries the SHA-256 of the previous record, so editing or deleting a line is detectable
(``cyberred verify-log``). It is the evidence trail behind reports and CTF write-ups.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_SECRET_KEY = re.compile(r"(key|token|secret|password|passwd|authorization|cookie)", re.I)
GENESIS = "0" * 64


def redact(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: ("[redacted]" if _SECRET_KEY.search(str(k)) else redact(v)) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact(v) for v in obj]
    return obj


def _digest(prev: str, record: dict[str, Any]) -> str:
    body = json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256((prev + body).encode()).hexdigest()


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._prev = GENESIS
        self._seq = 0
        if self.path.exists():
            for line in self.path.read_text().splitlines():
                if line.strip():
                    rec = json.loads(line)
                    self._prev = rec["hash"]
                    self._seq = rec["seq"]
        self._fh = self.path.open("a", buffering=1)

    def log(self, type_: str, **fields: Any) -> dict[str, Any]:
        self._seq += 1
        record: dict[str, Any] = {
            "seq": self._seq,
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "type": type_,
            **redact(fields),
            "prev": self._prev,
        }
        record["hash"] = _digest(self._prev, record)
        self._prev = record["hash"]
        self._fh.write(json.dumps(record, default=str) + "\n")
        return record

    def close(self) -> None:
        self._fh.close()


def verify_audit_log(path: Path) -> tuple[bool, int, int | None]:
    """Return (ok, records_checked, first_bad_seq)."""
    prev = GENESIS
    n = 0
    for line in Path(path).read_text().splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        n += 1
        claimed = rec.pop("hash", None)
        if rec.get("prev") != prev or _digest(prev, rec) != claimed:
            return False, n, rec.get("seq")
        prev = claimed
    return True, n, None
