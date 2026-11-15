"""Provider-neutral message, tool-call and response types (see ADR-0001)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any


class ProviderError(RuntimeError):
    """Unrecoverable provider failure (auth, bad request, repeated 5xx)."""


@dataclass
class ToolSpec:
    name: str
    description: str
    parameters: dict[str, Any]  # JSON Schema object


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    error: str | None = None  # set when the model produced unparseable arguments


@dataclass
class Message:
    role: str  # system | user | assistant | tool
    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    tool_call_id: str | None = None  # for role == "tool"
    name: str | None = None  # tool name for role == "tool"


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0


@dataclass
class Response:
    message: Message
    usage: Usage = field(default_factory=Usage)
    stop_reason: str = ""


class Provider(ABC):
    """Adapters implement ``complete``. Everything above this layer is vendor-agnostic."""

    name: str = "provider"
    model: str = ""
    native_tools: bool = True
    context_window: int = 32_000
    price_in_per_mtok: float = 0.0
    price_out_per_mtok: float = 0.0

    @abstractmethod
    async def complete(
        self,
        messages: Sequence[Message],
        tools: Sequence[ToolSpec] = (),
        *,
        max_tokens: int | None = None,
        temperature: float | None = None,
    ) -> Response: ...

    def cost(self, usage: Usage) -> float:
        return (usage.input_tokens * self.price_in_per_mtok + usage.output_tokens * self.price_out_per_mtok) / 1_000_000

    async def aclose(self) -> None:  # pragma: no cover - default no-op
        return None


def estimate_tokens(messages: Sequence[Message]) -> int:
    """Cheap token estimate (~4 chars/token) used for context management."""
    total = 0
    for m in messages:
        total += len(m.content) // 4 + 4
        for tc in m.tool_calls:
            total += len(str(tc.arguments)) // 4 + 8
    return total
