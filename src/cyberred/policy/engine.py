"""Risk-tier policy, approval rules, time window, rate limiting and budgets."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from datetime import datetime, timezone
from typing import NamedTuple

from ..config import Config, Tier

_RANK = {"deny": 0, "confirm": 1, "auto": 2}

MODE_DEFAULTS: dict[str, dict[Tier, str]] = {
    "lab": {Tier.T0: "auto", Tier.T1: "auto", Tier.T2: "confirm"},
    "ctf": {Tier.T0: "auto", Tier.T1: "auto", Tier.T2: "confirm"},
    # Client work: active probing needs a human nod, and scope.yaml can only make this stricter.
    "engagement": {Tier.T0: "auto", Tier.T1: "confirm", Tier.T2: "confirm"},
}


class Decision(NamedTuple):
    action: str  # auto | confirm | deny
    reason: str = ""


def _utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class PolicyEngine:
    def __init__(self, cfg: Config, clock: Callable[[], datetime] | None = None) -> None:
        self.cfg = cfg
        self.mode = cfg.engagement.mode
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._grants: set[str] = set()

    def default_for(self, tier: Tier) -> str:
        base = MODE_DEFAULTS[self.mode].get(tier, "deny")
        override = self.cfg.policy.approvals.get(tier)
        if override is None:
            return base
        if self.mode == "engagement":  # may only tighten
            return override if _RANK[override] < _RANK[base] else base
        return override

    def in_window(self) -> tuple[bool, str]:
        w = self.cfg.engagement.window
        if not w:
            return True, ""
        now = self._clock()
        if w.start and now < _utc(w.start):
            return False, f"engagement window has not started (starts {_utc(w.start).isoformat()})"
        if w.end and now > _utc(w.end):
            return False, f"engagement window has ended ({_utc(w.end).isoformat()})"
        return True, ""

    def decide(self, tool: str, tier: Tier) -> Decision:
        if tier == Tier.T3:
            return Decision("deny", "T3 actions are forbidden")
        if tier not in self.cfg.policy.allowed_tiers:
            return Decision("deny", f"tier {tier.value} is not allowed by this engagement's policy")
        ok, why = self.in_window()
        if not ok:
            return Decision("deny", why)
        action = self.default_for(tier)
        if action == "confirm" and tool in self._grants and tier in (Tier.T0, Tier.T1):
            return Decision("auto", "previously approved for this session")
        return Decision(action, f"{self.mode} mode policy for {tier.value}")

    def grant(self, tool: str, tier: Tier) -> bool:
        """'Always allow this tool' for the session. Never available for T2."""
        if tier in (Tier.T0, Tier.T1):
            self._grants.add(tool)
            return True
        return False


class RateLimiter:
    """Token bucket. ``await acquire(n)`` sleeps until n tokens are available."""

    def __init__(self, rate_per_sec: float, burst: float | None = None) -> None:
        self.rate = float(rate_per_sec)
        self.capacity = float(burst if burst is not None else max(1.0, rate_per_sec))
        self._tokens = self.capacity
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, n: float = 1.0) -> None:
        async with self._lock:
            n = min(n, self.capacity)
            while True:
                now = time.monotonic()
                self._tokens = min(self.capacity, self._tokens + (now - self._last) * self.rate)
                self._last = now
                if self._tokens >= n:
                    self._tokens -= n
                    return
                await asyncio.sleep((n - self._tokens) / self.rate)


class Budget:
    def __init__(self, max_steps: int, max_cost_usd: float, max_minutes: int) -> None:
        self.max_steps = max_steps
        self.max_cost = max_cost_usd
        self.max_seconds = max_minutes * 60
        self.steps = 0
        self.cost = 0.0
        self.tokens_in = 0
        self.tokens_out = 0
        self.started = time.monotonic()

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.started

    def exhausted(self) -> str | None:
        if self.steps >= self.max_steps:
            return f"step budget reached ({self.max_steps})"
        if self.max_cost and self.cost >= self.max_cost:
            return f"cost budget reached (${self.max_cost:.2f})"
        if self.elapsed >= self.max_seconds:
            return f"time budget reached ({self.max_seconds // 60} min)"
        return None
