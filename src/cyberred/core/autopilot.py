"""Autopilot: run the playbook to completion with no LLM."""

from __future__ import annotations

from .. import ui
from .engagement import Engagement
from .playbook import suggest


async def run_autopilot(eng: Engagement, *, aggressive: bool = False, thorough: bool = False, hint: bool = False) -> None:
    attempted: set[str] = set()
    last_phase = ""
    while True:
        if eng.stop_requested():
            ui.warn("stop requested; ending engagement")
            return
        if (why := eng.budget.exhausted()):
            ui.warn(why)
            return
        pending = [s for s in suggest(eng, aggressive=aggressive, thorough=thorough) if s.key not in attempted]
        if not pending:
            return
        if hint:
            ui.rule("suggested next actions", "hint")
            for i, s in enumerate(pending[:12], 1):
                ui.console.print(f"[muted]{i:>3}[/] [text]{s.short()}[/]  [muted]— {s.reason}[/]")
            return
        s = pending[0]
        if s.phase != last_phase:
            ui.phase_banner(s.phase)
            last_phase = s.phase
            eng.phase = s.phase
        attempted.add(s.key)
        await eng.executor.execute(s.tool, s.args, reason=s.reason, actor="autopilot")
