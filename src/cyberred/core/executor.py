"""The execution pipeline every tool call goes through.

    validate args → scope check → tier policy → dedupe → (approval) → run in sandbox/in-process
    → parse & ingest → flag scan → audit → compact result for the LLM

The model proposes; this pipeline disposes. Nothing here consults the model.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import threading
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .. import ui
from ..config import Config, Tier
from ..models import ToolOutput
from ..policy import Budget, PolicyEngine, Resolved, ScopeEngine, ScopeViolation
from ..sandbox import Runner
from ..store import AuditLog, Store
from ..store.db import args_hash
from ..tools import ArgError, Registry, ToolContext
from ..tools.util import trunc
from .ingest import ingest

MAX_SUMMARY = 3500


@dataclass
class ApprovalRequest:
    tool: str
    tier: Tier
    targets: list[str]
    reason: str
    args: dict[str, Any]


Approver = Callable[[ApprovalRequest], Awaitable[str]]  # returns 'yes' | 'no' | 'always'


@dataclass
class ToolResult:
    ok: bool
    text: str
    status: str  # ok | error | blocked | denied | cached | invalid | hint | aborted
    run_id: int | None = None
    new_findings: list[dict[str, Any]] = field(default_factory=list)


async def deny_all(_: ApprovalRequest) -> str:
    return "no"


class Executor:
    def __init__(self, cfg: Config, scope: ScopeEngine, policy: PolicyEngine, store: Store, audit: AuditLog,
                 runner: Runner, registry: Registry, workspace: Path, ctx: ToolContext, budget: Budget,
                 stop_event: threading.Event, approver: Approver = deny_all, hint: bool = False, verbose: bool = True) -> None:
        self.cfg, self.scope, self.policy, self.store, self.audit = cfg, scope, policy, store, audit
        self.runner, self.registry, self.workspace, self.ctx, self.budget = runner, registry, workspace, ctx, budget
        self.stop_event, self.approver, self.hint, self.verbose = stop_event, approver, hint, verbose
        self._flags = [re.compile(p) for p in cfg.ctf.flag_patterns]
        self.n = 0
        self.blocked_attempts = 0
        self.declined: set[str] = set()  # args hashes the policy or operator refused; never re-suggested

    # ---------------------------------------------------------------- helpers
    def _say(self, fn: Callable[..., None], *a: Any, **k: Any) -> None:
        if self.verbose:
            fn(*a, **k)

    def _scan_flags(self, text: str, run_id: int) -> list[str]:
        found: list[str] = []
        for rx in self._flags:
            for m in rx.finditer(text):
                v = m.group(0)
                if self.store.add_flag(v, f"run#{run_id}"):
                    found.append(v)
                    self.audit.log("flag", value=v, run=run_id)
                    self._say(ui.flag_line, v)
        return found

    def _write_output(self, run_id: int, tool: str, args: dict[str, Any], text: str) -> str:
        d = self.workspace / "runs"
        d.mkdir(parents=True, exist_ok=True)
        p = d / f"{run_id:04d}-{tool}.txt"
        p.write_text(f"# {tool} {json.dumps(args, sort_keys=True)}\n\n{text}")
        return str(p)

    # ---------------------------------------------------------------- main entry
    async def execute(self, name: str, args: dict[str, Any], *, reason: str = "", actor: str = "agent") -> ToolResult:
        tool = self.registry.get(name)
        if tool is None:
            return ToolResult(False, f"unknown tool '{name}'. Use one of: {', '.join(t.name for t in self.registry.all())}", "invalid")
        missing = [b for b in tool.requires if not self.runner.available(b)]
        if missing:
            return ToolResult(False, f"tool '{name}' is unavailable: '{', '.join(missing)}' is not installed in the {self.runner.name} runner", "invalid")
        try:
            clean = tool.validate(args)
        except ArgError as e:
            self.audit.log("invalid_args", tool=name, args=args, error=str(e), actor=actor)
            return ToolResult(False, f"invalid arguments for {name}: {e}", "invalid")

        # ---- scope
        resolved: dict[str, list[Resolved]] = {}
        try:
            for a in tool.target_args:
                v = clean.get(a)
                vals = v if isinstance(v, list) else ([v] if v else [])
                if not vals:
                    raise ScopeViolation(f"'{a}' is empty")
                resolved[a] = [self.scope.check(x) for x in vals]
        except ScopeViolation as e:
            self.blocked_attempts += 1
            self.audit.log("scope_block", tool=name, args=clean, reason=str(e), actor=actor)
            self._say(ui.blocked, f"{name}: {e}")
            return ToolResult(False, f"BLOCKED by scope policy: {e}. That target is out of scope — do not retry it or try variations.", "blocked")

        targets = [r.label for lst in resolved.values() for r in lst] or ["(none)"]

        # ---- policy
        decision = self.policy.decide(name, tool.tier)
        self.audit.log("policy", tool=name, tier=tool.tier.value, action=decision.action, why=decision.reason, actor=actor)
        if decision.action == "deny":
            self._say(ui.blocked, f"{name}: {decision.reason}")
            self.declined.add(args_hash(name, clean))
            return ToolResult(False, f"DENIED by policy: {decision.reason}", "denied")

        # ---- dedupe (efficiency: never repeat an identical successful run)
        prior = self.store.find_run(name, clean)
        if prior:
            self.audit.log("cache_hit", tool=name, run=prior["id"])
            return ToolResult(True, f"(identical call already ran as run #{prior['id']}; reusing its result)\n{prior['summary']}", "cached", prior["id"])

        if self.hint:
            self._say(ui.console.print, f"[muted]   {ui.em('hint')}would run[/] [text]{name}[/] [info]{', '.join(targets)[:80]}[/] [muted][{tool.tier.value}] {reason}[/]")
            return ToolResult(True, "hint mode: suggestion recorded, nothing was executed", "hint")

        if self.stop_event.is_set():
            return ToolResult(False, "engagement stopped by operator", "aborted")

        # ---- approval
        if decision.action == "confirm":
            req = ApprovalRequest(name, tool.tier, targets, reason, clean)
            answer = await self.approver(req)
            self.audit.log("approval", tool=name, tier=tool.tier.value, answer=answer, targets=targets, actor="operator")
            if answer == "no":
                self.declined.add(args_hash(name, clean))
                return ToolResult(False, "DENIED by the human operator. Do not retry; choose a different approach.", "denied")
            if answer == "always":
                self.policy.grant(name, tool.tier)

        # ---- run
        self.n += 1
        self.budget.steps += 1
        run_id = self.store.start_run(name, clean, actor)
        self.ctx.run_id = run_id
        self.audit.log("tool_start", run=run_id, tool=name, args=clean, targets=targets, reason=reason, actor=actor)
        self._say(ui.step, self.n, name, ", ".join(targets), tool.tier.value)
        t0 = time.monotonic()
        status = "ok"
        try:
            out = await self._run_with_stop(tool.run(self.ctx, clean, resolved), tool.timeout)
        except ScopeViolation as e:
            out, status = ToolOutput(False, str(e), f"BLOCKED mid-run by scope policy: {e}"), "blocked"
            self.audit.log("scope_block", tool=name, args=clean, reason=str(e), actor=actor)
        except asyncio.TimeoutError:
            out, status = ToolOutput(False, "timeout", f"{name} timed out after {tool.timeout}s"), "error"
        except _Aborted:
            out, status = ToolOutput(False, "aborted", "aborted by operator"), "aborted"
        except Exception as e:  # noqa: BLE001 - tool bugs must not kill the engagement
            out, status = ToolOutput(False, f"{type(e).__name__}: {e}", f"{name} crashed: {type(e).__name__}: {e}"), "error"
        dur = time.monotonic() - t0
        if not out.ok and status == "ok":
            status = "error"

        # ---- ingest
        new_findings: list[Any] = []
        if out.data:
            ing = ingest(self.store, out.data, name)
            new_findings = ing.new_findings
        flags = self._scan_flags(out.text + "\n" + out.summary, run_id) if status == "ok" else []
        path = self._write_output(run_id, name, clean, out.text or out.summary)
        digest = hashlib.sha256((out.text or "").encode()).hexdigest()[:16]
        self.store.finish_run(run_id, "ok" if status == "ok" else status, out.exit_code, out.summary, path, dur)
        self.audit.log("tool_result", run=run_id, tool=name, status=status, seconds=round(dur, 2), output_sha256=digest,
                       findings=[f.title for f in new_findings], flags=flags)

        if status == "ok":
            self._say(ui.result, True, (out.summary.splitlines() or [""])[0][:110], dur)
        else:
            self._say(ui.result, False, out.summary[:110], dur)
        for f in new_findings:
            self._say(ui.finding_line, f.severity, f.title, f.asset)

        text = f"[run #{run_id} · {name} · {status} · {dur:.1f}s]\n{trunc(out.summary, MAX_SUMMARY)}"
        if new_findings:
            text += f"\nNEW FINDINGS ({len(new_findings)}):\n" + "\n".join(f"  #{f.id} [{f.severity}] {f.title} @ {f.asset}" for f in new_findings[:15])
        if len(out.text) > len(out.summary) + 200:
            text += f"\n(full raw output stored: use read_output run_id={run_id})"
        return ToolResult(status == "ok", text, status, run_id, [f.to_dict() for f in new_findings])

    async def _run_with_stop(self, coro: Awaitable[ToolOutput], timeout: float) -> ToolOutput:
        """Await a tool, aborting promptly on the kill switch (polled) or on timeout."""
        task = asyncio.ensure_future(coro)
        deadline = time.monotonic() + timeout
        try:
            while True:
                done, _ = await asyncio.wait({task}, timeout=0.2)
                if done:
                    return task.result()
                if self.stop_event.is_set():
                    task.cancel()
                    self.runner.kill_all()
                    raise _Aborted()
                if time.monotonic() > deadline:
                    task.cancel()
                    self.runner.kill_all()
                    raise asyncio.TimeoutError()
        finally:
            if not task.done():
                task.cancel()


class _Aborted(Exception):
    pass
