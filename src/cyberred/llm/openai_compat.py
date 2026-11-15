"""OpenAI Chat Completions-compatible adapter.

One adapter covers OpenAI, Azure-style gateways, Ollama, vLLM, LM Studio, llama.cpp server, OpenRouter,
Groq, Together and anything else that speaks ``POST {base_url}/chat/completions``.
"""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import Sequence
from typing import Any

import httpx

from ..config import LLMRoleCfg
from .base import Message, Provider, ProviderError, Response, ToolCall, ToolSpec, Usage

RETRY_STATUS = {408, 409, 429, 500, 502, 503, 504}


class OpenAICompatProvider(Provider):
    name = "openai_compatible"

    def __init__(self, cfg: LLMRoleCfg, client: httpx.AsyncClient | None = None, backoff: float = 1.0) -> None:
        self.model = cfg.model
        self.base_url = (cfg.base_url or "https://api.openai.com/v1").rstrip("/")
        self.native_tools = cfg.native_tools is not False
        self.context_window = cfg.context_window
        self.default_max_tokens = cfg.max_tokens
        self.default_temperature = cfg.temperature
        self.price_in_per_mtok = cfg.price_in_per_mtok
        self.price_out_per_mtok = cfg.price_out_per_mtok
        self._backoff = backoff
        key = os.environ.get(cfg.api_key_env) if cfg.api_key_env else None
        if cfg.api_key_env and not key:
            raise ProviderError(f"environment variable {cfg.api_key_env} is not set")
        self._headers = {"Content-Type": "application/json"}
        if key:
            self._headers["Authorization"] = f"Bearer {key}"
        self._client = client or httpx.AsyncClient(timeout=httpx.Timeout(120.0, connect=15.0))

    # ------------------------------------------------------------ conversion
    @staticmethod
    def _to_wire(messages: Sequence[Message]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for m in messages:
            if m.role == "assistant" and m.tool_calls:
                out.append({
                    "role": "assistant",
                    "content": m.content or None,
                    "tool_calls": [
                        {"id": tc.id, "type": "function",
                         "function": {"name": tc.name, "arguments": json.dumps(tc.arguments)}}
                        for tc in m.tool_calls
                    ],
                })
            elif m.role == "tool":
                out.append({"role": "tool", "tool_call_id": m.tool_call_id, "content": m.content})
            else:
                out.append({"role": m.role, "content": m.content})
        return out

    @staticmethod
    def _parse_calls(raw_calls: list[dict[str, Any]] | None) -> list[ToolCall]:
        calls: list[ToolCall] = []
        for i, rc in enumerate(raw_calls or []):
            fn = rc.get("function", {})
            raw_args = fn.get("arguments") or "{}"
            args: dict[str, Any] = {}
            err = None
            try:
                parsed = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
                if isinstance(parsed, dict):
                    args = parsed
                else:
                    err = "tool arguments must be a JSON object"
            except json.JSONDecodeError as e:
                err = f"tool arguments were not valid JSON: {e}"
            calls.append(ToolCall(id=rc.get("id") or f"call_{i}", name=fn.get("name", ""), arguments=args, error=err))
        return calls

    # ------------------------------------------------------------ main call
    async def complete(self, messages: Sequence[Message], tools: Sequence[ToolSpec] = (), *,
                       max_tokens: int | None = None, temperature: float | None = None) -> Response:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": self._to_wire(messages),
            "max_tokens": max_tokens or self.default_max_tokens,
            "temperature": self.default_temperature if temperature is None else temperature,
        }
        if tools:
            payload["tools"] = [{"type": "function", "function": {"name": t.name, "description": t.description,
                                                                  "parameters": t.parameters}} for t in tools]
        data = await self._post(f"{self.base_url}/chat/completions", payload)
        try:
            choice = data["choices"][0]
            msg = choice["message"]
        except (KeyError, IndexError, TypeError) as e:
            raise ProviderError(f"unexpected response shape: {str(data)[:300]}") from e
        usage = data.get("usage") or {}
        return Response(
            message=Message("assistant", content=msg.get("content") or "", tool_calls=self._parse_calls(msg.get("tool_calls"))),
            usage=Usage(int(usage.get("prompt_tokens") or 0), int(usage.get("completion_tokens") or 0)),
            stop_reason=choice.get("finish_reason") or "",
        )

    async def _post(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
        last: Exception | None = None
        for attempt in range(4):
            try:
                r = await self._client.post(url, headers=self._headers, json=payload)
            except (httpx.TimeoutException, httpx.TransportError) as e:
                last = e
            else:
                if r.status_code == 200:
                    try:
                        return r.json()
                    except ValueError as e:
                        raise ProviderError("provider returned non-JSON body") from e
                if r.status_code not in RETRY_STATUS:
                    raise ProviderError(f"HTTP {r.status_code}: {r.text[:300]}")
                last = ProviderError(f"HTTP {r.status_code}: {r.text[:200]}")
            await asyncio.sleep(self._backoff * (2 ** attempt))
        raise ProviderError(f"provider unavailable after retries: {last}")

    async def aclose(self) -> None:
        await self._client.aclose()
