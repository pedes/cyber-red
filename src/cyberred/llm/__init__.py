from __future__ import annotations

from ..config import LLMRoleCfg
from .anthropic import AnthropicProvider
from .base import Message, Provider, ProviderError, Response, ToolCall, ToolSpec, Usage
from .jsonproto import JsonToolProvider
from .mock import MockProvider
from .openai_compat import OpenAICompatProvider


def build_provider(cfg: LLMRoleCfg) -> Provider:
    """Create a provider from config, adding the JSON fallback when native tool calling is disabled."""
    if cfg.provider == "mock":
        return MockProvider()
    inner: Provider = AnthropicProvider(cfg) if cfg.provider == "anthropic" else OpenAICompatProvider(cfg)
    return inner if cfg.native_tools is not False else JsonToolProvider(inner)


__all__ = [
    "AnthropicProvider", "JsonToolProvider", "Message", "MockProvider", "OpenAICompatProvider", "Provider",
    "ProviderError", "Response", "ToolCall", "ToolSpec", "Usage", "build_provider",
]
