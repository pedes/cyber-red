"""SQLite findings store: hosts, services, endpoints, findings, flags and tool runs."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from ..models import SEVERITIES, Finding, sev_rank

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS hosts (
  id INTEGER PRIMARY KEY, address TEXT UNIQUE NOT NULL, hostname TEXT, os TEXT, first_seen REAL);
CREATE TABLE IF NOT EXISTS services (
  id INTEGER PRIMARY KEY, host_id INTEGER NOT NULL REFERENCES hosts(id),
  port INTEGER NOT NULL, proto TEXT NOT NULL DEFAULT 'tcp',
  name TEXT, product TEXT, version TEXT, banner TEXT, extra TEXT,
  UNIQUE(host_id, port, proto));
CREATE TABLE IF NOT EXISTS endpoints (
  id INTEGER PRIMARY KEY, url TEXT UNIQUE NOT NULL, method TEXT DEFAULT 'GET',
  status INTEGER, title TEXT, tech TEXT, params TEXT, source TEXT);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY, dedupe TEXT UNIQUE NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL,
  description TEXT, evidence TEXT, remediation TEXT, host TEXT, port INTEGER, url TEXT,
  category TEXT, cve TEXT, cvss REAL, source TEXT, status TEXT, created REAL);
CREATE TABLE IF NOT EXISTS flags (id INTEGER PRIMARY KEY, value TEXT UNIQUE, source TEXT, created REAL);
CREATE TABLE IF NOT EXISTS tool_runs (
  id INTEGER PRIMARY KEY, tool TEXT NOT NULL, args TEXT NOT NULL, args_hash TEXT NOT NULL,
  actor TEXT, status TEXT, exit_code INTEGER, summary TEXT, output_path TEXT,
  started REAL, duration REAL);
CREATE INDEX IF NOT EXISTS idx_runs_hash ON tool_runs(args_hash);
"""


def args_hash(tool: str, args: dict[str, Any]) -> str:
    return hashlib.sha1(json.dumps([tool, args], sort_keys=True, default=str).encode()).hexdigest()


class Store:
    def __init__(self, path: Path | str) -> None:
        self.path = str(path)
        self.db = sqlite3.connect(self.path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self.db.commit()

    def close(self) -> None:
        self.db.close()

    # ---------------------------------------------------------------- meta
    def set_meta(self, key: str, value: Any) -> None:
        self.db.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (key, json.dumps(value, default=str)))
        self.db.commit()

    def get_meta(self, key: str, default: Any = None) -> Any:
        row = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return json.loads(row["value"]) if row else default

    # ---------------------------------------------------------------- hosts / services
    def upsert_host(self, address: str, hostname: str | None = None, os_: str | None = None) -> int:
        row = self.db.execute("SELECT id, hostname, os FROM hosts WHERE address=?", (address,)).fetchone()
        if row:
            if (hostname and not row["hostname"]) or (os_ and not row["os"]):
                self.db.execute(
                    "UPDATE hosts SET hostname=COALESCE(hostname,?), os=COALESCE(os,?) WHERE id=?",
                    (hostname, os_, row["id"]),
                )
                self.db.commit()
            return row["id"]
        cur = self.db.execute(
            "INSERT INTO hosts(address, hostname, os, first_seen) VALUES (?,?,?,?)", (address, hostname, os_, time.time())
        )
        self.db.commit()
        return int(cur.lastrowid or 0)

    def upsert_service(self, address: str, port: int, proto: str = "tcp", name: str | None = None,
                       product: str | None = None, version: str | None = None, banner: str | None = None,
                       extra: str | None = None, hostname: str | None = None) -> tuple[int, bool]:
        """Insert or enrich a service. Returns (id, is_new_or_gained_version_info)."""
        host_id = self.upsert_host(address, hostname)
        row = self.db.execute(
            "SELECT * FROM services WHERE host_id=? AND port=? AND proto=?", (host_id, port, proto)
        ).fetchone()
        if not row:
            cur = self.db.execute(
                "INSERT INTO services(host_id,port,proto,name,product,version,banner,extra) VALUES (?,?,?,?,?,?,?,?)",
                (host_id, port, proto, name, product, version, (banner or "")[:2000] or None, (extra or "")[:2000] or None),
            )
            self.db.commit()
            return int(cur.lastrowid or 0), True
        gained = bool((product and not row["product"]) or (version and not row["version"]))
        self.db.execute(
            "UPDATE services SET name=COALESCE(?,name), product=COALESCE(?,product), version=COALESCE(?,version),"
            " banner=COALESCE(?,banner), extra=COALESCE(?,extra) WHERE id=?",
            (name, product, version, (banner or "")[:2000] or None, (extra or "")[:2000] or None, row["id"]),
        )
        self.db.commit()
        return int(row["id"]), gained

    def hosts_with_services(self) -> list[dict[str, Any]]:
        out = []
        for h in self.db.execute("SELECT * FROM hosts ORDER BY address"):
            svcs = [dict(s) for s in self.db.execute("SELECT * FROM services WHERE host_id=? ORDER BY port", (h["id"],))]
            out.append({**dict(h), "services": svcs})
        return out

    def services(self) -> list[dict[str, Any]]:
        rows = self.db.execute(
            "SELECT s.*, h.address, h.hostname FROM services s JOIN hosts h ON h.id=s.host_id ORDER BY h.address, s.port"
        )
        return [dict(r) for r in rows]

    # ---------------------------------------------------------------- endpoints
    def add_endpoint(self, url: str, status: int | None = None, title: str | None = None,
                     tech: list[str] | None = None, params: list[str] | None = None,
                     source: str = "", method: str = "GET") -> bool:
        row = self.db.execute("SELECT * FROM endpoints WHERE url=?", (url,)).fetchone()
        tech_s = ",".join(sorted(set(tech or []))) or None
        params_s = ",".join(sorted(set(params or []))) or None
        if row:
            self.db.execute(
                "UPDATE endpoints SET status=COALESCE(?,status), title=COALESCE(?,title), tech=COALESCE(?,tech),"
                " params=COALESCE(?,params) WHERE id=?",
                (status, title, tech_s, params_s, row["id"]),
            )
            self.db.commit()
            return False
        self.db.execute(
            "INSERT INTO endpoints(url,method,status,title,tech,params,source) VALUES (?,?,?,?,?,?,?)",
            (url, method, status, title, tech_s, params_s, source),
        )
        self.db.commit()
        return True

    def endpoints(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self.db.execute("SELECT * FROM endpoints ORDER BY url")]

    # ---------------------------------------------------------------- findings
    def add_finding(self, f: Finding) -> tuple[int, bool]:
        """Insert, de-duplicating on (title, asset). A later 'confirmed' upgrades a 'candidate'."""
        row = self.db.execute("SELECT id, status, evidence FROM findings WHERE dedupe=?", (f.dedupe_key,)).fetchone()
        if row:
            if f.status == "confirmed" and row["status"] != "confirmed":
                self.db.execute("UPDATE findings SET status='confirmed', evidence=? WHERE id=?",
                                (f.evidence or row["evidence"], row["id"]))
                self.db.commit()
            return int(row["id"]), False
        cur = self.db.execute(
            "INSERT INTO findings(dedupe,title,severity,description,evidence,remediation,host,port,url,category,cve,cvss,"
            "source,status,created) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (f.dedupe_key, f.title, f.severity, f.description, f.evidence[:4000], f.remediation, f.host, f.port, f.url,
             f.category, f.cve, f.cvss, f.source, f.status, time.time()),
        )
        self.db.commit()
        return int(cur.lastrowid or 0), True

    def findings(self) -> list[dict[str, Any]]:
        rows = [dict(r) for r in self.db.execute("SELECT * FROM findings")]
        rows.sort(key=lambda r: (sev_rank(r["severity"]), r["id"]))
        return rows

    def severity_counts(self) -> dict[str, int]:
        counts = {s: 0 for s in SEVERITIES}
        for r in self.db.execute("SELECT severity, COUNT(*) c FROM findings GROUP BY severity"):
            counts[r["severity"]] = r["c"]
        return counts

    # ---------------------------------------------------------------- flags
    def add_flag(self, value: str, source: str = "") -> bool:
        try:
            self.db.execute("INSERT INTO flags(value,source,created) VALUES (?,?,?)", (value, source, time.time()))
            self.db.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def flags(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self.db.execute("SELECT * FROM flags ORDER BY id")]

    # ---------------------------------------------------------------- tool runs
    def start_run(self, tool: str, args: dict[str, Any], actor: str = "agent") -> int:
        cur = self.db.execute(
            "INSERT INTO tool_runs(tool,args,args_hash,actor,status,started) VALUES (?,?,?,?,?,?)",
            (tool, json.dumps(args, sort_keys=True, default=str), args_hash(tool, args), actor, "running", time.time()),
        )
        self.db.commit()
        return int(cur.lastrowid or 0)

    def finish_run(self, run_id: int, status: str, exit_code: int | None, summary: str, output_path: str, duration: float) -> None:
        self.db.execute(
            "UPDATE tool_runs SET status=?, exit_code=?, summary=?, output_path=?, duration=? WHERE id=?",
            (status, exit_code, summary[:6000], output_path, duration, run_id),
        )
        self.db.commit()

    def find_run(self, tool: str, args: dict[str, Any]) -> dict[str, Any] | None:
        row = self.db.execute(
            "SELECT * FROM tool_runs WHERE args_hash=? AND status='ok' ORDER BY id DESC LIMIT 1", (args_hash(tool, args),)
        ).fetchone()
        return dict(row) if row else None

    def attempted(self, tool: str, args: dict[str, Any]) -> bool:
        """True if this exact call already ran, whether it succeeded or failed (used to avoid retry loops)."""
        row = self.db.execute("SELECT 1 FROM tool_runs WHERE args_hash=? AND status IN ('ok','error','aborted','blocked') LIMIT 1",
                              (args_hash(tool, args),)).fetchone()
        return row is not None

    def get_run(self, run_id: int) -> dict[str, Any] | None:
        row = self.db.execute("SELECT * FROM tool_runs WHERE id=?", (run_id,)).fetchone()
        return dict(row) if row else None

    def runs(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self.db.execute("SELECT * FROM tool_runs ORDER BY id")]

    # ---------------------------------------------------------------- overview
    def counts(self) -> dict[str, int]:
        q = lambda t: self.db.execute(f"SELECT COUNT(*) c FROM {t}").fetchone()["c"]  # noqa: E731
        return {"hosts": q("hosts"), "services": q("services"), "endpoints": q("endpoints"),
                "findings": q("findings"), "flags": q("flags"), "runs": q("tool_runs")}
