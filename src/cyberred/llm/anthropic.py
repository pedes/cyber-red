"""Native Anthropic Messages API adapter."""

from __future__ import annotations

import asyncio
import os
from collections.abc import Sequence
from typing import Any

import httpx

from ..config import LLMRoleCfg
from .base import Message, Provider, ProviderError, Response, ToolCall, ToolSpec, Usage
from .openai_compat import RETRY_STATUS


class AnthropicProvider(Provider):
    name = "anthropic"

    def __init__(self, cfg: LLMRoleCfg, client: httpx.AsyncClient | None = None, backoff: float = 1.0) -> None:
        self.model = cfg.model
        self.base_url = (cfg.base_url or "https://api.anthropic.com").rstrip("/")
        self.native_tools = cfg.native_tools is not False
        self.context_window = cfg.context_window
        self.default_max_tokens = cfg.max_tokens
        self.default_temperature = cfg.temperature
        self.price_in_per_mtok = cfg.price_in_per_mtok
        self.price_out_per_mtok = cfg.price_out_per_mtok
        self._backoff = backoff
        env = cfg.api_key_env or "ANTHROPIC_API_KEY"
        key = os.environ.get(env)
        if not key:
            raise ProviderError(f"environment variable {env} is not set")
        self._headers = {"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"}
        self._client = client or httpx.AsyncClient(timeout=httpx.Timeout(120.0, connect=15.0))

    @staticmethod
    def _to_wire(messages: Sequence[Message]) -> tuple[str, list[dict[str, Any]]]:
        system_parts: list[str] = []
        out: list[dict[str, Any]] = []

        def push(role: str, blocks: list[dict[str, Any]]) -> None:
            if out and out[-1]["role"] == role:  # the API requires strictly alternating roles
                out[-1]["content"].extend(blocks)
            else:
                out.append({"role": role, "content": blocks})

        for m in messages:
            if m.role == "system":
                system_parts.append(m.content)
            elif m.role == "user":
                push("user", [{"type": "text", "text": m.content}])
            elif m.role == "assistant":
                blocks: list[dict[str, Any]] = []
                if m.content:
                    blocks.append({"type": "text", "text": m.content})
                for tc in m.tool_calls:
                    blocks.append({"type": "tool_use", "id": tc.id, "name": tc.name, "input": tc.arguments})
                push("assistant", blocks or [{"type": "text", "text": "(no content)"}])
            elif m.role == "tool":
                push("user", [{"type": "tool_result", "tool_use_id": m.tool_call_id, "content": m.content}])
        return "\n\n".join(system_parts), out

    async def complete(self, messages: Sequence[Message], tools: Sequence[ToolSpec] = (), *,
                       max_tokens: int | None = None, temperature: float | None = None) -> Response:
        system, wire = self._to_wire(messages)
        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens or self.default_max_tokens,
            "temperature": self.default_temperature if temperature is None else temperature,
            "messages": wire,
        }
        if system:
            payload["system"] = system
        if tools:
            payload["tools"] = [{"name": t.name, "description": t.description, "input_schema": t.parameters} for t in tools]
        data = await self._post(f"{self.base_url}/v1/messages", payload)

        text_parts: list[str] = []
        calls: list[ToolCall] = []
        for block in data.get("content", []):
            if block.get("type") == "text":
                text_parts.append(block.get("text", ""))
            elif block.get("type") == "tool_use":
                inp = block.get("input")
                calls.append(ToolCall(id=block["id"], name=block["name"], arguments=inp if isinstance(inp, dict) else {},
                                      error=None if isinstance(inp, dict) else "tool input must be an object"))
        u = data.get("usage") or {}
        return Response(Message("assistant", "\n".join(text_parts), calls),
                        Usage(int(u.get("input_tokens") or 0), int(u.get("output_tokens") or 0)),
                        data.get("stop_reason") or "")

    async def _post(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
        last: Exception | None = None
        for attempt in range(4):
            try:
                r = await self._client.post(url, headers=self._headers, json=payload)
            except (httpx.TimeoutException, httpx.TransportError) as e:
                last = e
            else:
                if r.status_code == 200:
                    return r.json()
                if r.status_code not in RETRY_STATUS and r.status_code != 529:
                    raise ProviderError(f"HTTP {r.status_code}: {r.text[:300]}")
                last = ProviderError(f"HTTP {r.status_code}: {r.text[:200]}")
            await asyncio.sleep(self._backoff * (2 ** attempt))
        raise ProviderError(f"provider unavailable after retries: {last}")

    async def aclose(self) -> None:
        await self._client.aclose()
