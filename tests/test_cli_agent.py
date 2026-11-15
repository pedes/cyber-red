"""`cyberred run` driven by a fake OpenAI-compatible server: proves the provider-agnostic path through the real CLI."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from typer.testing import CliRunner

from cyberred.cli import app
from cyberred.demo import demo_server

runner = CliRunner()


class FakeLLM(BaseHTTPRequestHandler):
    """Speaks Chat Completions. Scripted: probe the demo URL, then try an out-of-scope host, then finish."""

    script: list = []
    requests: list = []

    def log_message(self, *a):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        type(self).requests.append(body)
        step = type(self).script.pop(0) if type(self).script else ("finish", {"summary": "done"})
        name, args = step
        native = "tools" in body
        if native:
            msg = {"content": "", "tool_calls": [{"id": f"c{len(type(self).requests)}", "type": "function",
                                                  "function": {"name": name, "arguments": json.dumps(args)}}]}
        else:  # JSON-protocol fallback: the tool call travels as text
            msg = {"content": json.dumps({"tool": name, "arguments": args})}
        data = json.dumps({"choices": [{"message": msg, "finish_reason": "stop"}], "usage": {"prompt_tokens": 500, "completion_tokens": 40}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture
def fake_llm():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeLLM)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    FakeLLM.requests = []
    yield f"http://127.0.0.1:{srv.server_address[1]}/v1"
    srv.shutdown()
    srv.server_close()


@pytest.mark.parametrize("native", [True, False], ids=["native-tools", "json-fallback"])
def test_agent_via_cli_with_openai_compatible_endpoint(tmp_path, fake_llm, native):
    with demo_server() as port:
        scope = tmp_path / "scope.yaml"
        scope.write_text(f"engagement: {{name: agent-test, mode: lab}}\nscope: {{include: ['http://127.0.0.1:{port}/']}}\n"
                         "budgets: {max_cost_usd: 1.0}\n")
        FakeLLM.script = [("http_probe", {"url": f"http://127.0.0.1:{port}/"}),
                          ("http_probe", {"url": "http://203.0.113.50/"}),  # out of scope: must be blocked
                          ("finish", {"summary": "probe complete"})]
        args = ["--no-emoji", "run", str(scope), "--provider", "openai_compatible", "--model", "fake-model", "--base-url", fake_llm,
                "--workspace-dir", str(tmp_path / "w"), "--runner", "native"]
        if not native:
            args.append("--no-native-tools")
        r = runner.invoke(app, args)
    assert r.exit_code == 0, r.stdout
    assert "agent stopped: finished" in r.stdout and "probe complete" in r.stdout
    assert "out-of-scope attempt(s) were blocked" in r.stdout
    assert "Missing HTTP security headers" in r.stdout
    first = FakeLLM.requests[0]
    assert first["model"] == "fake-model"
    assert ("tools" in first) is native  # the fallback sends no native tool schema
    if not native:
        assert "Tool-calling protocol" in first["messages"][0]["content"]
    ws = next((tmp_path / "w").iterdir())
    log = (ws / "audit.jsonl").read_text()
    assert "scope_block" in log and "llm_call" in log


def test_run_without_llm_falls_back_to_playbook_and_hint_shows_plan(tmp_path):
    with demo_server() as port:
        scope = tmp_path / "scope.yaml"
        scope.write_text(f"scope: {{include: ['http://127.0.0.1:{port}/']}}\n")
        r = runner.invoke(app, ["--no-emoji", "run", str(scope), "--hint", "--workspace-dir", str(tmp_path / "w"), "--runner", "native"])
    assert r.exit_code == 0 and "built-in playbook" in r.stdout and "suggested next actions" in r.stdout and "http_probe" in r.stdout


def test_missing_api_key_is_a_clean_error(tmp_path, monkeypatch):
    monkeypatch.delenv("DEFINITELY_UNSET_KEY", raising=False)
    scope = tmp_path / "scope.yaml"
    scope.write_text("scope: {include: ['10.0.0.1']}\n")
    r = runner.invoke(app, ["run", str(scope), "--provider", "openai_compatible", "--model", "m", "--api-key-env", "DEFINITELY_UNSET_KEY"])
    assert r.exit_code == 2 and "DEFINITELY_UNSET_KEY" in r.stdout


def test_example_scope_file_is_valid():
    from pathlib import Path

    from cyberred.config import Config

    cfg = Config.load(Path(__file__).parent.parent / "examples" / "scope.example.yaml")
    assert cfg.engagement.mode == "ctf" and cfg.llm.orchestrator is not None
