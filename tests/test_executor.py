import asyncio
import json

from conftest import approve_all, approve_always, run_async
from cyberred.config import Tier
from cyberred.demo import demo_server
from cyberred.models import ToolOutput
from cyberred.store import verify_audit_log
from cyberred.tools import Tool


def test_out_of_scope_target_is_blocked_and_audited(make_eng):
    eng = make_eng(include=["127.0.0.1"])
    r = run_async(eng.executor.execute("tcp_port_scan", {"targets": ["8.8.8.8"], "ports": "80"}))
    assert r.status == "blocked" and "BLOCKED" in r.text
    assert eng.store.runs() == []  # nothing was started
    assert eng.executor.blocked_attempts == 1
    log = (eng.ws / "audit.jsonl").read_text()
    assert '"type":"scope_block"' in log.replace(" ", "") or '"scope_block"' in log


def test_one_bad_target_blocks_the_whole_call(make_eng):
    eng = make_eng(include=["127.0.0.1"])
    r = run_async(eng.executor.execute("tcp_port_scan", {"targets": ["127.0.0.1", "8.8.8.8"], "ports": "80"}))
    assert r.status == "blocked"


def test_invalid_arguments_rejected(make_eng):
    eng = make_eng()
    for args in ({"targets": ["127.0.0.1"], "ports": "80", "bogus": 1}, {"ports": "80"},
                 {"targets": ["-oN /tmp/x"], "ports": "80"}, {"targets": ["127.0.0.1"], "ports": "80; rm -rf /"}):
        r = run_async(eng.executor.execute("tcp_port_scan", args))
        assert r.status in ("invalid", "blocked"), args


def test_unknown_and_unavailable_tools(make_eng):
    eng = make_eng()
    assert run_async(eng.executor.execute("rm_rf", {})).status == "invalid"
    r = run_async(eng.executor.execute("nmap_scan", {"targets": ["127.0.0.1"]}))
    assert r.status == "invalid" and "not installed" in r.text


def test_t2_denied_without_approval_and_allowed_with_it(make_eng):
    with demo_server() as port:
        url = f"http://127.0.0.1:{port}/item?id=1"
        eng = make_eng(include=["127.0.0.1"])
        assert run_async(eng.executor.execute("web_param_probe", {"url": url})).status == "denied"
        eng2 = make_eng(include=["127.0.0.1"], approver=approve_all)
        assert run_async(eng2.executor.execute("web_param_probe", {"url": url})).status == "ok"


def test_always_never_unlocks_t2(make_eng):
    with demo_server() as port:
        url = f"http://127.0.0.1:{port}/search?q=a"
        eng = make_eng(approver=approve_always)
        run_async(eng.executor.execute("web_param_probe", {"url": url}))
        assert eng.policy.decide("web_param_probe", Tier.T2).action == "confirm"


def test_engagement_mode_requires_confirmation_for_active_tools(make_eng):
    seen = []

    async def approver(req):
        seen.append(req.tool)
        return "no"

    eng = make_eng(mode="engagement", approver=approver)
    r = run_async(eng.executor.execute("tcp_port_scan", {"targets": ["127.0.0.1"], "ports": "1"}))
    assert r.status == "denied" and seen == ["tcp_port_scan"]


def test_identical_calls_are_deduplicated(make_eng):
    eng = make_eng()
    a = run_async(eng.executor.execute("tcp_port_scan", {"targets": ["127.0.0.1"], "ports": "1"}))
    b = run_async(eng.executor.execute("tcp_port_scan", {"targets": ["127.0.0.1"], "ports": "1"}))
    assert a.status == "ok" and b.status == "cached" and len(eng.store.runs()) == 1


def test_hint_mode_executes_nothing(make_eng):
    eng = make_eng(hint=True)
    r = run_async(eng.executor.execute("tcp_port_scan", {"targets": ["127.0.0.1"], "ports": "1"}))
    assert r.status == "hint" and eng.store.runs() == []


def test_kill_switch_aborts_a_running_tool(make_eng):
    eng = make_eng()

    async def slow(ctx, args, res):
        await asyncio.sleep(30)
        return ToolOutput(True)

    eng.registry.register(Tool("slow", "slow", Tier.T0, ("recon",), {}, slow, timeout=60))

    async def go():
        task = asyncio.create_task(eng.executor.execute("slow", {}))
        await asyncio.sleep(0.2)
        eng.request_stop()
        return await asyncio.wait_for(task, 5)

    r = run_async(go())
    assert r.status == "aborted" and eng.runner.killed


def test_crashing_tool_does_not_kill_the_engagement(make_eng):
    eng = make_eng()

    async def boom(ctx, args, res):
        raise RuntimeError("kaboom")

    eng.registry.register(Tool("boom", "boom", Tier.T0, ("recon",), {}, boom))
    r = run_async(eng.executor.execute("boom", {}))
    assert r.status == "error" and "kaboom" in r.text


def test_flags_are_captured_from_output(make_eng):
    eng = make_eng(ctf={"flag_patterns": [r"FLAG\{[a-z]+\}"]})

    async def leaky(ctx, args, res):
        return ToolOutput(True, "stuff FLAG{pwned} stuff", "found FLAG{pwned}")

    eng.registry.register(Tool("leaky", "x", Tier.T0, ("recon",), {}, leaky))
    run_async(eng.executor.execute("leaky", {}))
    assert [f["value"] for f in eng.store.flags()] == ["FLAG{pwned}"]


def test_audit_chain_survives_a_full_run_and_detects_tampering(make_eng):
    eng = make_eng()
    run_async(eng.executor.execute("tcp_port_scan", {"targets": ["127.0.0.1"], "ports": "1"}))
    p = eng.ws / "audit.jsonl"
    ok, n, _ = verify_audit_log(p)
    assert ok and n >= 4
    lines = p.read_text().splitlines()
    rec = json.loads(lines[2])
    rec["tool"] = "something_else"
    lines[2] = json.dumps(rec)
    p.write_text("\n".join(lines) + "\n")
    ok, _, bad = verify_audit_log(p)
    assert not ok and bad == rec["seq"]
