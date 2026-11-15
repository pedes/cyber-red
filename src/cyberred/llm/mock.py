"""Scripted provider for tests, demos and offline development."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Union

from .base import Message, Provider, Response, ToolCall, ToolSpec, Usage

Step = Union[Response, Callable[[Sequence[Message], Sequence[ToolSpec]], Response]]


def tool_turn(name: str, **arguments: object) -> Response:
    return Response(Message("assistant", "", [ToolCall(id=f"call_{name}", name=name, arguments=dict(arguments))]),
                    Usage(100, 20), "tool_calls")


def text_turn(text: str) -> Response:
    return Response(Message("assistant", text), Usage(50, 10), "stop")


class MockProvider(Provider):
    name = "mock"
    model = "mock-1"

    def __init__(self, script: Sequence[Step] = ()) -> None:
        self.script = list(script)
        self.calls: list[tuple[list[Message], list[ToolSpec]]] = []

    async def complete(self, messages: Sequence[Message], tools: Sequence[ToolSpec] = (), *,
                       max_tokens: int | None = None, temperature: float | None = None) -> Response:
        self.calls.append((list(messages), list(tools)))
        if not self.script:
            return text_turn("(mock script exhausted)")
        step = self.script.pop(0)
        return step(messages, tools) if callable(step) else step
