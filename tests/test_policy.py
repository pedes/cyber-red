import asyncio
import time
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from cyberred.config import Config, Tier
from cyberred.policy.engine import Budget, PolicyEngine, RateLimiter


def cfg(mode="lab", **extra):
    data = {"engagement": {"name": "t", "mode": mode, "authorization": "SOW-1"}, "scope": {"include": ["10.0.0.0/24"]}}
    data.update(extra)
    return Config.model_validate(data)


def test_mode_defaults():
    assert PolicyEngine(cfg("lab")).decide("x", Tier.T1).action == "auto"
    assert PolicyEngine(cfg("lab")).decide("x", Tier.T2).action == "confirm"
    assert PolicyEngine(cfg("engagement")).decide("x", Tier.T1).action == "confirm"


def test_t3_always_denied():
    assert PolicyEngine(cfg()).decide("x", Tier.T3).action == "deny"
    with pytest.raises(ValidationError):
        cfg(policy={"allowed_tiers": ["T0", "T3"]})


def test_lab_can_loosen_but_engagement_cannot():
    assert PolicyEngine(cfg("ctf", policy={"approvals": {"T2": "auto"}})).decide("x", Tier.T2).action == "auto"
    assert PolicyEngine(cfg("engagement", policy={"approvals": {"T2": "auto", "T1": "auto"}})).decide("x", Tier.T2).action == "confirm"
    assert PolicyEngine(cfg("engagement", policy={"approvals": {"T1": "auto"}})).decide("x", Tier.T1).action == "confirm"
    assert PolicyEngine(cfg("engagement", policy={"approvals": {"T2": "deny"}})).decide("x", Tier.T2).action == "deny"


def test_disallowed_tier():
    p = PolicyEngine(cfg(policy={"allowed_tiers": ["T0", "T1"]}))
    assert p.decide("x", Tier.T2).action == "deny"


def test_engagement_requires_authorization():
    with pytest.raises(ValidationError):
        Config.model_validate({"engagement": {"mode": "engagement"}, "scope": {"include": ["10.0.0.1"]}})


def test_unknown_keys_rejected():
    with pytest.raises(ValidationError):
        cfg(polcy={})


def test_time_window():
    now = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)
    window = {"start": (now - timedelta(hours=1)).isoformat(), "end": (now + timedelta(hours=1)).isoformat()}
    c = cfg(engagement={"name": "t", "mode": "lab", "window": window})
    assert PolicyEngine(c, clock=lambda: now).decide("x", Tier.T1).action == "auto"
    assert PolicyEngine(c, clock=lambda: now + timedelta(hours=2)).decide("x", Tier.T1).action == "deny"
    assert PolicyEngine(c, clock=lambda: now - timedelta(hours=2)).decide("x", Tier.T1).action == "deny"


def test_grants_apply_to_t1_not_t2():
    p = PolicyEngine(cfg("engagement"))
    assert p.grant("nmap_scan", Tier.T1)
    assert p.decide("nmap_scan", Tier.T1).action == "auto"
    assert not p.grant("sqlmap_test", Tier.T2)
    assert p.decide("sqlmap_test", Tier.T2).action == "confirm"


def test_rate_limiter_throttles():
    async def go():
        rl = RateLimiter(50, burst=5)
        t = time.monotonic()
        for _ in range(15):
            await rl.acquire()
        return time.monotonic() - t

    assert asyncio.run(go()) >= 0.15  # 10 tokens beyond the burst at 50/s


def test_budget():
    b = Budget(2, 1.0, 1)
    assert b.exhausted() is None
    b.steps = 2
    assert "step" in b.exhausted()
    b.steps, b.cost = 0, 1.5
    assert "cost" in b.exhausted()
