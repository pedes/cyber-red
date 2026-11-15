"""LLM-driven agent loop.

The model proposes tool calls; every call goes through the Executor (scope → policy → approval → sandbox).
Context stays small: raw output lives on disk, the model sees compact summaries plus a regenerated STATE block
(hosts, services, findings, flags and the playbook's next-step suggestions) instead of an ever-growing history.
"""

from __future__ import annotations

from dataclasses import dataclass

from rich.text import Text

from .. import ui
from ..llm import Message, Provider, ProviderError, ToolCall, ToolSpec
from ..llm.base import estimate_tokens
from ..models import SEVERITIES, Finding
from ..tools import PHASES, phase_index
from . import prompts
from .engagement import Engagement
from .playbook import Suggestion, suggest

META_SPECS = [
    ToolSpec("record_finding", "Record a vulnerability/misconfiguration you have evidence for that the tools did not already record.", {
        "type": "object", "required": ["title", "severity", "description", "evidence"], "additionalProperties": False,
        "properties": {
            "title": {"type": "string"}, "severity": {"type": "string", "enum": list(SEVERITIES)},
            "description": {"type": "string"}, "evidence": {"type": "string", "description": "Concrete tool output supporting this"},
            "host": {"type": "string"}, "port": {"type": "integer"}, "url": {"type": "string"},
            "remediation": {"type": "string"}, "cve": {"type": "string"},
            "confirmed": {"type": "boolean", "description": "true only if you verified it, not just inferred it"}}}),
    ToolSpec("submit_flag", "Record a captured CTF flag.", {
        "type": "object", "required": ["value"], "additionalProperties": False, "properties": {"value": {"type": "string"}}}),
    ToolSpec("advance_phase", "Move to a later phase to unlock its tools.", {
        "type": "object", "required": ["phase"], "additionalProperties": False,
        "properties": {"phase": {"type": "string", "enum": list(PHASES)}}}),
    ToolSpec("read_output", "Read a slice of a previous tool run's stored raw output.", {
        "type": "object", "required": ["run_id"], "additionalProperties": False,
        "properties": {"run_id": {"type": "integer"}, "offset": {"type": "integer"}, "length": {"type": "integer"}}}),
    ToolSpec("finish", "End the engagement when the objective is met or nothing productive remains.", {
        "type": "object", "required": ["summary"], "additionalProperties": False, "properties": {"summary": {"type": "string"}}}),
]
META_NAMES = {s.name for s in META_SPECS}


@dataclass
class AgentResult:
    stopped: str
    summary: str = ""


def build_state(eng: Engagement, aggressive: bool = False, sug: list[Suggestion] | None = None) -> str:
    b, st = eng.budget, eng.store
    L = [f"[STATE] steps {b.steps}/{b.max_steps} · phase: {eng.phase} · {int(b.elapsed)}s elapsed"]
    L += [f"scope {x}" for x in eng.scope.describe()]
    hosts = st.hosts_with_services()
    if hosts:
        L.append("hosts:")
        for h in hosts[:12]:
            svcs = ", ".join(f"{s['port']}/{s['name'] or '?'}" + (f" {s['product']} {s['version'] or ''}".rstrip() if s.get("product") else "")
                             for s in h["services"][:14])
            L.append(f"  {h['address']}" + (f" ({h['hostname']})" if h.get("hostname") else "") + f": {svcs or 'no open ports recorded'}")
    eps = st.endpoints()
    if eps:
        withp = [e for e in eps if e.get("params")]
        L.append(f"web endpoints: {len(eps)} known, {len(withp)} with parameters" + "".join(f"\n  {e['url']} [{e['params']}]" for e in withp[:6]))
    fs = st.findings()
    if fs:
        L.append(f"findings ({len(fs)}):")
        L += [f"  #{f['id']} [{f['severity']}] {f['title']} @ {f['url'] or f['host']}{(':' + str(f['port'])) if f['port'] and not f['url'] else ''} ({f['status']})" for f in fs[:10]]
    flags = st.flags()
    if flags:
        L.append("flags: " + ", ".join(f["value"] for f in flags))
    sug = (suggest(eng, aggressive=aggressive) if sug is None else sug)[:6]
    if sug:
        L.append("Suggested next actions (ready to use):")
        L += [f"  {i}. {s.short()} — {s.reason}" for i, s in enumerate(sug, 1)]
    else:
        L.append("Suggested next actions: none. Consider finishing, or reason about gaps the playbook cannot see.")
    return "\n".join(L)


def compact(messages: list[Message], window: int) -> list[Message]:
    """Shrink history to fit ~60% of the context window: truncate old tool results, then drop oldest turns."""
    budget = int(window * 0.6)
    if estimate_tokens(messages) <= budget:
        return messages
    msgs = [Message(m.role, m.content, m.tool_calls, m.tool_call_id, m.name) for m in messages]
    keep_recent = 8
    for m in msgs[1:-keep_recent]:
        if m.role == "tool" and len(m.content) > 300:
            m.content = m.content[:300] + "\n…[compacted; use read_output for the full result]"
    if estimate_tokens(msgs) <= budget:
        return msgs
    # group into turns (assistant + its tool results) and drop the oldest whole turns
    head, rest = msgs[:1], msgs[1:]
    turns: list[list[Message]] = []
    for m in rest:
        if m.role == "assistant" or not turns:
            turns.append([m])
        else:
            turns[-1].append(m)
    while len(turns) > 3 and estimate_tokens(head + [x for t in turns for x in t]) > budget:
        turns.pop(0)
    note = Message("user", "[earlier steps were omitted to save context; the STATE block and findings list are authoritative]")
    return head + [note] + [x for t in turns for x in t]


class Agent:
    def __init__(self, eng: Engagement, provider: Provider, aggressive: bool = False, goal: str = "") -> None:
        self.eng, self.provider, self.aggressive, self.goal = eng, provider, aggressive, goal
        mode = eng.cfg.engagement.mode
        extra = prompts.CTF_EXTRA if mode == "ctf" else prompts.ENGAGEMENT_EXTRA if mode == "engagement" else ""
        self.system = prompts.SYSTEM_PROMPT.format(mode=mode, scope="\n".join(eng.scope.describe()), extra=extra)
        self._finished: str | None = None

    # ---------------------------------------------------------------- tool menu
    def _specs(self, pinned: set[str] = frozenset()) -> list[ToolSpec]:  # type: ignore[assignment]
        """Tools unlocked by the current phase, plus anything the playbook is currently recommending."""
        cur = phase_index(self.eng.phase)
        specs = []
        for t in self.eng.available_tools():
            if t.name in pinned or min(phase_index(p) for p in t.phases) <= cur:
                tag = {"T0": "passive", "T1": "active", "T2": "INTRUSIVE, needs approval"}[t.tier.value]
                specs.append(ToolSpec(t.name, f"{t.description} [{t.tier.value} {tag}]", t.json_schema()))
        return specs + META_SPECS

    # ---------------------------------------------------------------- meta tools
    def _meta(self, tc: ToolCall) -> str:
        eng, a = self.eng, tc.arguments
        eng.audit.log("meta_tool", tool=tc.name, args=a)
        try:
            if tc.name == "record_finding":
                f = Finding(title=str(a["title"])[:200], severity=a.get("severity", "info"), description=str(a.get("description", ""))[:2000],
                            evidence=str(a.get("evidence", ""))[:3000], remediation=str(a.get("remediation", ""))[:800],
                            host=str(a.get("host", ""))[:200], port=a.get("port"), url=str(a.get("url", ""))[:500],
                            cve=str(a.get("cve", ""))[:30], source="agent", status="confirmed" if a.get("confirmed") else "candidate")
                fid, created = eng.store.add_finding(f)
                if created:
                    f.id = fid
                    ui.finding_line(f.severity, f.title, f.asset)
                return f"finding #{fid} {'recorded' if created else 'already known (merged)'}"
            if tc.name == "submit_flag":
                v = str(a["value"]).strip()[:200]
                if eng.store.add_flag(v, "agent"):
                    ui.flag_line(v)
                    return "flag recorded"
                return "flag already recorded"
            if tc.name == "advance_phase":
                p = a["phase"]
                if p not in PHASES:
                    return f"unknown phase; choose from {list(PHASES)}"
                eng.phase = p
                ui.phase_banner(p)
                return f"phase is now {p}; tools for this phase are unlocked"
            if tc.name == "read_output":
                run = eng.store.get_run(int(a["run_id"]))
                if not run or not run.get("output_path"):
                    return "no stored output for that run id"
                text = open(run["output_path"], errors="replace").read()
                off, ln = max(0, int(a.get("offset", 0))), min(6000, max(200, int(a.get("length", 3000))))
                return f"[run #{run['id']} bytes {off}-{off + ln} of {len(text)}]\n{text[off:off + ln]}"
            if tc.name == "finish":
                self._finished = str(a.get("summary", ""))[:2000]
                return "engagement closing"
        except (KeyError, ValueError, TypeError) as e:
            return f"invalid arguments: {e}"
        return "unknown meta tool"  # pragma: no cover

    # ---------------------------------------------------------------- loop
    async def run(self, max_nudges: int = 2) -> AgentResult:
        eng = self.eng
        goal = self.goal or "Assess every in-scope target following the methodology, record findings with evidence, then finish."
        messages: list[Message] = [Message("user", f"Objective: {goal}")]
        nudges = 0
        while True:
            if eng.stop_requested():
                return AgentResult("operator stop")
            if (why := eng.budget.exhausted()):
                return AgentResult(why)
            sug = suggest(eng, aggressive=self.aggressive)
            if sug and phase_index(sug[0].phase) > phase_index(eng.phase):  # the playbook drives the phase forward, never back
                eng.phase = sug[0].phase
                ui.phase_banner(eng.phase)
            state = build_state(eng, self.aggressive, sug)
            convo = [Message("system", self.system)] + compact(messages, self.provider.context_window) + [Message("user", state)]
            try:
                resp = await self.provider.complete(convo, self._specs({s.tool for s in sug[:6]}))
            except ProviderError as e:
                ui.err(f"LLM provider error: {e}")
                return AgentResult(f"provider error: {e}")
            eng.budget.tokens_in += resp.usage.input_tokens
            eng.budget.tokens_out += resp.usage.output_tokens
            eng.budget.cost += self.provider.cost(resp.usage)
            msg = resp.message
            eng.audit.log("llm_call", model=self.provider.model, provider=self.provider.name, tokens_in=resp.usage.input_tokens,
                          tokens_out=resp.usage.output_tokens, tool_calls=[c.name for c in msg.tool_calls])
            messages.append(msg)
            if msg.content.strip():
                ui.console.print(Text.assemble(("   ", ""), (ui.em("brain"), ""), (msg.content.strip().replace("\n", " ")[:220], "muted")))

            if not msg.tool_calls:
                nudges += 1
                if nudges > max_nudges:
                    return AgentResult("model stopped calling tools", msg.content[:500])
                messages.append(Message("user", "Continue with a tool call, or call `finish` if you are done."))
                continue
            nudges = 0

            for tc in msg.tool_calls:
                if tc.error:
                    text = f"could not parse your arguments: {tc.error}. Send valid JSON matching the tool schema."
                elif tc.name in META_NAMES:
                    text = self._meta(tc)
                else:
                    res = await eng.executor.execute(tc.name, tc.arguments, reason=msg.content.strip()[:240])
                    text = res.text
                    if res.status in ("ok", "cached", "error"):
                        text = f'<tool_output tool="{tc.name}">\n{text.replace("</tool_output>", "")}\n</tool_output>'
                messages.append(Message("tool", text, tool_call_id=tc.id, name=tc.name))
            if self._finished is not None:
                return AgentResult("finished", self._finished)
            if eng.executor.hint:
                return AgentResult("hint mode: first plan shown, nothing executed")
