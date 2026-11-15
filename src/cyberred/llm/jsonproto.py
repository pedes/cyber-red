"""JSON tool-calling fallback for models without native function calling (small local models).

The tool catalogue is described in the system prompt and the model replies with one JSON object per turn:
``{"tool": "<name>", "arguments": {...}}``. Replies are validated and retried on parse failure.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Sequence
from typing import Any

from .base import Message, Provider, Response, ToolCall, ToolSpec, Usage

PROTOCOL_PROMPT = """\
## Tool-calling protocol
You cannot call functions natively. To use a tool, reply with EXACTLY ONE JSON object and nothing else:
{{"tool": "<tool name>", "arguments": {{ ... }}}}
To talk to the user without calling a tool, reply in plain text (no JSON).
Available tools (JSON Schema for arguments):
{catalogue}
"""


def render_catalogue(tools: Sequence[ToolSpec]) -> str:
    lines = []
    for t in tools:
        props = t.parameters.get("properties", {})
        required = set(t.parameters.get("required", []))
        args = ", ".join(f"{k}{'*' if k in required else ''}: {v.get('type', 'any')}" for k, v in props.items())
        lines.append(f"- {t.name}({args}) — {t.description}")
    return "\n".join(lines)


def extract_json_object(text: str) -> dict[str, Any] | None:
    """Find the first decodable JSON object in free text (tolerates code fences and prose)."""
    dec = json.JSONDecoder()
    i = text.find("{")
    while i != -1:
        try:
            obj, _ = dec.raw_decode(text[i:])
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass
        i = text.find("{", i + 1)
    return None


def parse_reply(text: str, tools: Sequence[ToolSpec]) -> ToolCall | None:
    obj = extract_json_object(text)
    if not obj:
        return None
    name = obj.get("tool") or obj.get("name") or obj.get("action")
    args = obj.get("arguments") if "arguments" in obj else obj.get("args", obj.get("parameters", {}))
    if not isinstance(name, str) or name not in {t.name for t in tools}:
        return None
    if not isinstance(args, dict):
        return ToolCall(id=f"call_{uuid.uuid4().hex[:8]}", name=name, arguments={}, error="'arguments' must be an object")
    return ToolCall(id=f"call_{uuid.uuid4().hex[:8]}", name=name, arguments=args)


class JsonToolProvider(Provider):
    """Wrap any provider so tool calls travel as JSON text."""

    def __init__(self, inner: Provider, max_retries: int = 2) -> None:
        self.inner = inner
        self.name = f"{inner.name}+json"
        self.model = inner.model
        self.native_tools = False
        self.context_window = inner.context_window
        self.price_in_per_mtok = inner.price_in_per_mtok
        self.price_out_per_mtok = inner.price_out_per_mtok
        self.max_retries = max_retries

    @staticmethod
    def _flatten(messages: Sequence[Message], tools: Sequence[ToolSpec]) -> list[Message]:
        out: list[Message] = []
        injected = False
        for m in messages:
            if m.role == "system" and not injected:
                out.append(Message("system", m.content + "\n\n" + PROTOCOL_PROMPT.format(catalogue=render_catalogue(tools))))
                injected = True
            elif m.role == "assistant" and m.tool_calls:
                tc = m.tool_calls[0]
                out.append(Message("assistant", json.dumps({"tool": tc.name, "arguments": tc.arguments})))
            elif m.role == "tool":
                out.append(Message("user", f"TOOL RESULT ({m.name or 'tool'}):\n{m.content}"))
            else:
                out.append(Message(m.role, m.content))
        if not injected:
            out.insert(0, Message("system", PROTOCOL_PROMPT.format(catalogue=render_catalogue(tools))))
        return out

    async def complete(self, messages: Sequence[Message], tools: Sequence[ToolSpec] = (), *,
                       max_tokens: int | None = None, temperature: float | None = None) -> Response:
        convo = self._flatten(messages, tools)
        total = Usage()
        resp: Response | None = None
        for _ in range(self.max_retries + 1):
            resp = await self.inner.complete(convo, (), max_tokens=max_tokens, temperature=temperature)
            total.input_tokens += resp.usage.input_tokens
            total.output_tokens += resp.usage.output_tokens
            text = resp.message.content
            call = parse_reply(text, tools)
            if call:
                return Response(Message("assistant", "", [call]), total, resp.stop_reason)
            looks_like_attempt = '"tool"' in text or '"arguments"' in text
            if not looks_like_attempt:
                return Response(Message("assistant", text), total, resp.stop_reason)  # plain-text turn
            convo = convo + [Message("assistant", text), Message(
                "user", 'Invalid tool call. Reply with ONE JSON object: {"tool": "<name>", "arguments": {...}} using only the listed tools.')]
        assert resp is not None
        return Response(Message("assistant", resp.message.content), total, "parse_failed")

    async def aclose(self) -> None:
        await self.inner.aclose()
