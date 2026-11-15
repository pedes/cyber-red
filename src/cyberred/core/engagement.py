"""Engagement: wires config, scope, policy, store, audit log, runner and executor together."""

from __future__ import annotations

import os
import re
import threading
from datetime import datetime
from importlib import resources
from pathlib import Path

from ..config import Config
from ..policy import Budget, PolicyEngine, RateLimiter, ScopeEngine
from ..sandbox import Runner, select_runner
from ..store import AuditLog, Store
from ..tools import Registry, ToolContext, build_registry
from .executor import Approver, Executor, deny_all


def new_workspace(base: Path, name: str) -> Path:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", name).strip("-") or "engagement"
    ws = Path(base) / f"{slug}-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    ws.mkdir(parents=True, exist_ok=False)
    return ws


class Engagement:
    def __init__(self, cfg: Config, workspace: Path, runner_kind: str = "auto", approver: Approver = deny_all,
                 hint: bool = False, verbose: bool = True, runner: Runner | None = None,
                 registry: Registry | None = None, scope: ScopeEngine | None = None) -> None:
        self.cfg = cfg
        self.ws = Path(workspace)
        self.ws.mkdir(parents=True, exist_ok=True)
        (self.ws / "wordlists").mkdir(exist_ok=True)
        wl = self.ws / "wordlists" / "small.txt"
        if not wl.exists():
            wl.write_text(resources.files("cyberred.data").joinpath("small.txt").read_text())

        self.scope = scope or ScopeEngine(cfg.scope)
        self.policy = PolicyEngine(cfg)
        self.store = Store(self.ws / "findings.db")
        self.audit = AuditLog(self.ws / "audit.jsonl")
        self.runner = runner or select_runner(runner_kind, self.ws)
        self.registry = registry or build_registry()
        rl = cfg.policy.rate_limit
        self.limiter_net = RateLimiter(rl.max_packets_per_second)
        self.limiter_http = RateLimiter(rl.max_http_requests_per_second)
        b = cfg.budgets
        self.budget = Budget(b.max_steps, b.max_cost_usd, b.max_duration_minutes)
        self.stop_event = threading.Event()  # loop-agnostic and safe to set from signal handlers
        self.phase = "recon"
        ctx = ToolContext(cfg, self.scope, self.runner, self.store, self.ws, self.limiter_net, self.limiter_http)
        self.executor = Executor(cfg, self.scope, self.policy, self.store, self.audit, self.runner, self.registry, self.ws,
                                 ctx, self.budget, self.stop_event, approver, hint, verbose)

        (self.ws / "config.json").write_text(cfg.model_dump_json(indent=2))
        (self.ws / "run.pid").write_text(str(os.getpid()))
        self.store.set_meta("name", cfg.engagement.name)
        self.store.set_meta("mode", cfg.engagement.mode)
        self.store.set_meta("started", datetime.now().isoformat(timespec="seconds"))
        self.audit.log("engagement_start", name=cfg.engagement.name, mode=cfg.engagement.mode, runner=self.runner.name,
                       scope=self.scope.describe(), authorization=cfg.engagement.authorization)

    # ---------------------------------------------------------------- kill switch
    def request_stop(self) -> None:
        if not self.stop_event.is_set():
            self.stop_event.set()
            self.audit.log("kill_switch")
        self.runner.kill_all()

    def stop_requested(self) -> bool:
        if (self.ws / "STOP").exists() and not self.stop_event.is_set():
            self.request_stop()
        return self.stop_event.is_set()

    def finish(self) -> None:
        self.store.set_meta("finished", datetime.now().isoformat(timespec="seconds"))
        self.audit.log("engagement_end", steps=self.budget.steps, cost=round(self.budget.cost, 4),
                       blocked_attempts=self.executor.blocked_attempts)
        try:
            (self.ws / "run.pid").unlink()
        except FileNotFoundError:
            pass

    def close(self) -> None:
        self.audit.close()
        self.store.close()

    def available_tools(self):
        return self.registry.available(self.runner, self.cfg.policy.allowed_tiers)
