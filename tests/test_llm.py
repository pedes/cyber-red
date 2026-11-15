import json

import httpx
import pytest

from conftest import run_async
from cyberred.config import LLMRoleCfg
from cyberred.llm import (
    AnthropicProvider,
    JsonToolProvider,
    Message,
    MockProvider,
    OpenAICompatProvider,
    ProviderError,
    ToolCall,
    ToolSpec,
    build_provider,
)
from cyberred.llm.jsonproto import parse_reply
from cyberred.llm.mock import text_turn

TOOLS = [ToolSpec("tcp_port_scan", "scan", {"type": "object", "properties": {"targets": {"type": "array"}}, "required": ["targets"]})]


def client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def test_openai_adapter_parses_tool_calls_and_usage():
    seen = {}

    def handler(req: httpx.Request):
        seen["body"] = json.loads(req.content)
        seen["auth"] = req.headers.get("authorization")
        return httpx.Response(200, json={
            "choices": [{"finish_reason": "tool_calls", "message": {"content": None, "tool_calls": [
                {"id": "c1", "type": "function", "function": {"name": "tcp_port_scan", "arguments": '{"targets": ["10.0.0.5"]}'}}]}}],
            "usage": {"prompt_tokens": 120, "completion_tokens": 15}})

    p = OpenAICompatProvider(LLMRoleCfg(model="m", base_url="http://x/v1", price_in_per_mtok=1, price_out_per_mtok=2), client(handler))
    r = run_async(p.complete([Message("system", "s"), Message("user", "u")], TOOLS))
    assert r.message.tool_calls[0].arguments == {"targets": ["10.0.0.5"]}
    assert (r.usage.input_tokens, r.usage.output_tokens) == (120, 15)
    assert seen["body"]["tools"][0]["function"]["name"] == "tcp_port_scan" and seen["auth"] is None
    assert p.cost(r.usage) == pytest.approx(150e-6)


def test_openai_adapter_flags_invalid_json_arguments_and_converts_history():
    seen = {}

    def handler(req):
        seen["msgs"] = json.loads(req.content)["messages"]
        return httpx.Response(200, json={"choices": [{"message": {"content": "", "tool_calls": [
            {"id": "c", "function": {"name": "t", "arguments": "{not json"}}]}}]})

    p = OpenAICompatProvider(LLMRoleCfg(model="m"), client(handler))
    hist = [Message("user", "u"), Message("assistant", "", [ToolCall("a1", "t", {"x": 1})]), Message("tool", "res", tool_call_id="a1", name="t")]
    r = run_async(p.complete(hist, TOOLS))
    assert r.message.tool_calls[0].error and "valid JSON" in r.message.tool_calls[0].error
    assert seen["msgs"][1]["tool_calls"][0]["function"]["arguments"] == '{"x": 1}'
    assert seen["msgs"][2] == {"role": "tool", "tool_call_id": "a1", "content": "res"}


def test_openai_adapter_retries_then_succeeds_and_fails_fast_on_auth(monkeypatch):
    calls = {"n": 0}

    def flaky(req):
        calls["n"] += 1
        return httpx.Response(429, text="slow down") if calls["n"] < 3 else httpx.Response(200, json={"choices": [{"message": {"content": "hi"}}]})

    p = OpenAICompatProvider(LLMRoleCfg(model="m"), client(flaky), backoff=0)
    assert run_async(p.complete([Message("user", "u")])).message.content == "hi" and calls["n"] == 3

    p2 = OpenAICompatProvider(LLMRoleCfg(model="m"), client(lambda r: httpx.Response(401, text="bad key")), backoff=0)
    with pytest.raises(ProviderError, match="401"):
        run_async(p2.complete([Message("user", "u")]))


def test_missing_api_key_env_is_a_clear_error(monkeypatch):
    monkeypatch.delenv("NOPE_KEY", raising=False)
    with pytest.raises(ProviderError, match="NOPE_KEY"):
        OpenAICompatProvider(LLMRoleCfg(model="m", api_key_env="NOPE_KEY"))


def test_anthropic_adapter_wire_format(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    seen = {}

    def handler(req):
        seen["body"], seen["hdr"] = json.loads(req.content), req.headers
        return httpx.Response(200, json={"content": [{"type": "text", "text": "thinking"},
                                                     {"type": "tool_use", "id": "tu1", "name": "tcp_port_scan", "input": {"targets": ["10.0.0.5"]}}],
                                         "usage": {"input_tokens": 10, "output_tokens": 5}, "stop_reason": "tool_use"})

    p = AnthropicProvider(LLMRoleCfg(provider="anthropic", model="m"), client(handler))
    hist = [Message("system", "sys"), Message("user", "go"),
            Message("assistant", "", [ToolCall("t0", "a", {}), ToolCall("t1", "b", {})]),
            Message("tool", "r0", tool_call_id="t0"), Message("tool", "r1", tool_call_id="t1"), Message("user", "STATE")]
    r = run_async(p.complete(hist, TOOLS))
    body = seen["body"]
    assert body["system"] == "sys" and body["tools"][0]["input_schema"]["type"] == "object"
    roles = [m["role"] for m in body["messages"]]
    assert roles == ["user", "assistant", "user"]  # tool results + STATE merged into one user turn
    assert [b["type"] for b in body["messages"][2]["content"]] == ["tool_result", "tool_result", "text"]
    assert seen["hdr"]["x-api-key"] == "k" and "anthropic-version" in seen["hdr"]
    assert r.message.tool_calls[0].name == "tcp_port_scan" and r.message.content == "thinking"


def test_json_protocol_parses_fenced_json_and_prose():
    c = parse_reply('Sure!\n```json\n{"tool": "tcp_port_scan", "arguments": {"targets": ["10.0.0.5"]}}\n```', TOOLS)
    assert c and c.arguments == {"targets": ["10.0.0.5"]}
    assert parse_reply('{"tool": "not_a_tool", "arguments": {}}', TOOLS) is None
    assert parse_reply("just talking", TOOLS) is None


def test_json_protocol_retries_garbage_then_succeeds_and_converts_history():
    inner = MockProvider([text_turn('{"tool": "tcp_port_scan", "arguments": '),  # truncated JSON
                          text_turn('{"tool": "tcp_port_scan", "arguments": {"targets": ["10.0.0.5"]}}')])
    p = JsonToolProvider(inner)
    hist = [Message("system", "sys"), Message("user", "go"), Message("assistant", "", [ToolCall("c", "tcp_port_scan", {"targets": ["a"]})]),
            Message("tool", "result", tool_call_id="c", name="tcp_port_scan")]
    r = run_async(p.complete(hist, TOOLS))
    assert r.message.tool_calls[0].arguments["targets"] == ["10.0.0.5"]
    assert len(inner.calls) == 2
    sent = inner.calls[0][0]
    assert "Tool-calling protocol" in sent[0].content and not inner.calls[0][1]  # tools travel in the prompt
    assert sent[-1].role == "user" and sent[-1].content.startswith("TOOL RESULT")
    assert r.usage.input_tokens == 100  # usage summed across both attempts


def test_json_protocol_passes_plain_text_through():
    r = run_async(JsonToolProvider(MockProvider([text_turn("I am done.")])).complete([Message("user", "x")], TOOLS))
    assert not r.message.tool_calls and r.message.content == "I am done."


def test_factory_wraps_json_fallback_and_supports_mock():
    assert build_provider(LLMRoleCfg(model="m", native_tools=False)).native_tools is False
    assert build_provider(LLMRoleCfg(provider="mock")).name == "mock"
