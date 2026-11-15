"""Engagement configuration (``scope.yaml``) schema and loading."""

from __future__ import annotations

import re
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Tier(str, Enum):
    T0 = "T0"  # passive
    T1 = "T1"  # active, non-destructive
    T2 = "T2"  # intrusive, approval-gated
    T3 = "T3"  # forbidden, never available


Approval = Literal["auto", "confirm", "deny"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class WindowCfg(_Strict):
    start: datetime | None = None
    end: datetime | None = None


class EngagementCfg(_Strict):
    name: str = "engagement"
    mode: Literal["lab", "ctf", "engagement"] = "lab"
    authorization: str | None = None
    window: WindowCfg | None = None

    @field_validator("name")
    @classmethod
    def _safe_name(cls, v: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9_.\- ]{1,64}", v):
            raise ValueError("name may only contain letters, digits, space, '_', '.', '-' (max 64)")
        return v


class ScopeCfg(_Strict):
    include: list[str] = Field(min_length=1)
    exclude: list[str] = Field(default_factory=list)
    # Static name -> IP mapping (like /etc/hosts). Used for CTF vhosts and to pin resolution.
    hosts: dict[str, str] = Field(default_factory=dict)


class RateLimitCfg(_Strict):
    max_packets_per_second: int = Field(500, ge=1, le=100_000)
    max_http_requests_per_second: int = Field(20, ge=1, le=10_000)


class PolicyCfg(_Strict):
    allowed_tiers: list[Tier] = Field(default_factory=lambda: [Tier.T0, Tier.T1, Tier.T2])
    approvals: dict[Tier, Approval] = Field(default_factory=dict)
    rate_limit: RateLimitCfg = Field(default_factory=RateLimitCfg)

    @field_validator("allowed_tiers")
    @classmethod
    def _no_t3(cls, v: list[Tier]) -> list[Tier]:
        if Tier.T3 in v:
            raise ValueError("T3 (forbidden) can never be allowed")
        return v


class CtfCfg(_Strict):
    flag_patterns: list[str] = Field(default_factory=lambda: [r"\b[a-fA-F0-9]{32}\b", r"(?i)flag\{[^}\s]{1,100}\}", r"HTB\{[^}\s]{1,100}\}", r"THM\{[^}\s]{1,100}\}"])

    @field_validator("flag_patterns")
    @classmethod
    def _compile(cls, v: list[str]) -> list[str]:
        for p in v:
            re.compile(p)
        return v


class LLMRoleCfg(_Strict):
    provider: Literal["openai_compatible", "anthropic", "mock"] = "openai_compatible"
    base_url: str | None = None
    model: str = "unset"
    api_key_env: str | None = None  # name of the env var holding the key; keys never live in this file
    native_tools: bool | None = None  # None = assume native tool calling; false = JSON-protocol fallback
    context_window: int = Field(32_000, ge=2_000)
    max_tokens: int = Field(2_048, ge=64)
    temperature: float = Field(0.2, ge=0, le=2)
    price_in_per_mtok: float = Field(0.0, ge=0)
    price_out_per_mtok: float = Field(0.0, ge=0)


class LLMCfg(_Strict):
    orchestrator: LLMRoleCfg | None = None


class BudgetCfg(_Strict):
    max_steps: int = Field(200, ge=1)
    max_cost_usd: float = Field(5.0, ge=0)
    max_duration_minutes: int = Field(180, ge=1)


class Config(_Strict):
    engagement: EngagementCfg = Field(default_factory=EngagementCfg)
    scope: ScopeCfg
    policy: PolicyCfg = Field(default_factory=PolicyCfg)
    ctf: CtfCfg = Field(default_factory=CtfCfg)
    llm: LLMCfg = Field(default_factory=LLMCfg)
    budgets: BudgetCfg = Field(default_factory=BudgetCfg)

    @model_validator(mode="after")
    def _engagement_needs_authorization(self) -> Config:
        if self.engagement.mode == "engagement" and not (self.engagement.authorization or "").strip():
            raise ValueError("engagement.authorization is required when mode is 'engagement'")
        return self

    @classmethod
    def load(cls, path: str | Path) -> Config:
        data = yaml.safe_load(Path(path).read_text()) or {}
        return cls.model_validate(data)


SCOPE_TEMPLATE = """\
# CyberRed engagement scope. Only test systems you own or are explicitly authorized to test.
engagement:
  name: {name}
  mode: {mode}                   # lab | ctf | engagement
{auth_line}
scope:
  include:
{includes}
  exclude: []                    # exclusions always win
  hosts: {{}}                    # optional static name->IP map, e.g. {{target.htb: 10.10.11.5}}

policy:
  allowed_tiers: [T0, T1, T2]    # T3 is never allowed
  approvals:
    T2: confirm                  # auto | confirm | deny
  rate_limit:
    max_packets_per_second: 500
    max_http_requests_per_second: 20

budgets:
  max_steps: 200
  max_cost_usd: 5.0
  max_duration_minutes: 180

# LLM is optional: without it, `cyberred run --autopilot` follows the built-in playbook.
# llm:
#   orchestrator:
#     provider: openai_compatible   # openai_compatible | anthropic
#     base_url: http://localhost:11434/v1
#     model: your-model
#     api_key_env: OPENAI_API_KEY   # name of the env var, never the key itself
"""
