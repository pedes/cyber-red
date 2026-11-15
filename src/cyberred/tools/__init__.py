from __future__ import annotations

from . import external, netpy, webpy
from .base import PHASES, ArgError, Param, Registry, Tool, ToolContext, phase_index


def build_registry() -> Registry:
    reg = Registry()
    netpy.register(reg)
    webpy.register(reg)
    external.register(reg)
    return reg


__all__ = ["ArgError", "PHASES", "Param", "Registry", "Tool", "ToolContext", "build_registry", "phase_index"]
