"""Tool abstraction: typed parameters, risk tier, phases and a run callable.

The LLM only ever fills typed parameters. It never supplies a raw shell string, and parameters that name
targets are routed through the scope engine before the tool sees them.
"""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..config import Config, Tier
from ..models import ToolOutput
from ..policy import RateLimiter, Resolved, ScopeEngine

if TYPE_CHECKING:
    from ..sandbox import Runner
    from ..store import Store

PHASES = ("recon", "enumeration", "vuln_discovery", "validation", "reporting")

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


class ArgError(ValueError):
    """Invalid tool arguments (reported back to the model so it can correct itself)."""


@dataclass
class Param:
    type: str  # string | integer | boolean | array
    description: str = ""
    required: bool = True
    default: Any = None
    enum: tuple[str, ...] | None = None
    items: str = "string"
    pattern: str | None = None
    minimum: int | None = None
    maximum: int | None = None
    max_len: int = 512
    max_items: int = 64
    allow_dash: bool = False  # strings starting with '-' are rejected by default (option injection)

    def schema(self) -> dict[str, Any]:
        s: dict[str, Any] = {"type": self.type, "description": self.description}
        if self.type == "array":
            s["items"] = {"type": self.items}
            if self.enum:
                s["items"]["enum"] = list(self.enum)
            s["maxItems"] = self.max_items
        elif self.enum:
            s["enum"] = list(self.enum)
        if self.minimum is not None:
            s["minimum"] = self.minimum
        if self.maximum is not None:
            s["maximum"] = self.maximum
        if self.default is not None:
            s["default"] = self.default
        return s

    def _check_str(self, name: str, v: Any) -> str:
        if not isinstance(v, str):
            raise ArgError(f"'{name}' must be a string")
        if len(v) > self.max_len:
            raise ArgError(f"'{name}' is too long (max {self.max_len})")
        if _CONTROL.search(v):
            raise ArgError(f"'{name}' contains control characters")
        if not self.allow_dash and v.lstrip().startswith("-"):
            raise ArgError(f"'{name}' may not start with '-'")
        if self.enum and v not in self.enum:
            raise ArgError(f"'{name}' must be one of {list(self.enum)}")
        if self.pattern and not re.fullmatch(self.pattern, v):
            raise ArgError(f"'{name}' has an invalid format")
        return v

    def coerce(self, name: str, v: Any) -> Any:
        if self.type == "string":
            return self._check_str(name, v)
        if self.type == "integer":
            if isinstance(v, bool) or not isinstance(v, (int, str)) or (isinstance(v, str) and not re.fullmatch(r"-?\d+", v.strip())):
                raise ArgError(f"'{name}' must be an integer")
            n = int(v)
            if self.minimum is not None and n < self.minimum or self.maximum is not None and n > self.maximum:
                raise ArgError(f"'{name}' must be between {self.minimum} and {self.maximum}")
            return n
        if self.type == "boolean":
            if isinstance(v, bool):
                return v
            if isinstance(v, str) and v.lower() in ("true", "false"):
                return v.lower() == "true"
            raise ArgError(f"'{name}' must be a boolean")
        if self.type == "array":
            if isinstance(v, str):
                v = [v]
            if not isinstance(v, list):
                raise ArgError(f"'{name}' must be an array")
            if len(v) > self.max_items:
                raise ArgError(f"'{name}' has too many items (max {self.max_items})")
            return [self._check_str(f"{name}[{i}]", x) for i, x in enumerate(v)]
        raise ArgError(f"unsupported parameter type {self.type}")  # pragma: no cover


@dataclass
class ToolContext:
    cfg: Config
    scope: ScopeEngine
    runner: Runner
    store: Store
    workspace: Path
    limiter_net: RateLimiter
    limiter_http: RateLimiter
    run_id: int = 0


RunFn = Callable[[ToolContext, dict[str, Any], dict[str, list[Resolved]]], Awaitable[ToolOutput]]


@dataclass
class Tool:
    name: str
    description: str
    tier: Tier
    phases: tuple[str, ...]
    params: dict[str, Param]
    run: RunFn
    target_args: tuple[str, ...] = ()
    requires: tuple[str, ...] = ()  # external binaries
    timeout: int = 600
    # Heuristic input for the playbook / UI
    category: str = "misc"

    def __post_init__(self) -> None:
        if self.tier == Tier.T3:
            raise ValueError("T3 tools cannot be registered")

    def validate(self, args: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(args, dict):
            raise ArgError("arguments must be an object")
        unknown = set(args) - set(self.params)
        if unknown:
            raise ArgError(f"unknown argument(s): {', '.join(sorted(unknown))}. Valid: {', '.join(self.params)}")
        clean: dict[str, Any] = {}
        for name, p in self.params.items():
            if name in args and args[name] is not None:
                clean[name] = p.coerce(name, args[name])
            elif p.required:
                raise ArgError(f"missing required argument '{name}'")
            elif p.default is not None:
                clean[name] = p.default
        return clean

    def json_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {k: p.schema() for k, p in self.params.items()},
            "required": [k for k, p in self.params.items() if p.required],
            "additionalProperties": False,
        }

    def target_values(self, args: dict[str, Any]) -> list[str]:
        vals: list[str] = []
        for a in self.target_args:
            v = args.get(a)
            if isinstance(v, list):
                vals.extend(v)
            elif v:
                vals.append(v)
        return vals


class Registry:
    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> Tool:
        if tool.name in self._tools:
            raise ValueError(f"duplicate tool {tool.name}")
        self._tools[tool.name] = tool
        return tool

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def all(self) -> list[Tool]:
        return list(self._tools.values())

    def __contains__(self, name: str) -> bool:
        return name in self._tools

    def available(self, runner: Runner, allowed: Sequence[Tier] | None = None) -> list[Tool]:
        out = []
        for t in self._tools.values():
            if allowed is not None and t.tier not in allowed:
                continue
            if all(runner.available(b) for b in t.requires):
                out.append(t)
        return out


def phase_index(phase: str) -> int:
    return PHASES.index(phase) if phase in PHASES else 0
