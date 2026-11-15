"""Scope-aware HTTP fetching.

* Redirects are followed manually and every hop is re-checked against scope.
* The connected peer address is compared with the pinned resolution (detects DNS rebinding).
* Bodies are size-capped; TLS verification is off because labs are full of self-signed certificates
  (certificate quality is assessed separately by ``tls_inspect``).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from urllib.parse import urljoin

import httpx

from ..policy import ScopeViolation
from .base import ToolContext

UA = "Mozilla/5.0 (compatible; CyberRed/0.1; authorized-security-testing)"
MAX_BYTES = 300_000


@dataclass
class Fetched:
    url: str
    status: int | None = None
    headers: httpx.Headers = field(default_factory=httpx.Headers)
    text: str = ""
    redirects: list[str] = field(default_factory=list)
    blocked: str | None = None  # scope / rebinding block reason
    error: str | None = None
    set_cookies: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.status is not None and self.blocked is None and self.error is None


def make_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(verify=False, follow_redirects=False, timeout=httpx.Timeout(10.0, connect=6.0),
                             headers={"User-Agent": UA, "Accept": "*/*"})


def _same_ip(a: str, b: str) -> bool:
    try:
        return ipaddress.ip_address(a) == ipaddress.ip_address(b)
    except ValueError:
        return False


async def fetch(ctx: ToolContext, client: httpx.AsyncClient, url: str, *, method: str = "GET",
                headers: dict[str, str] | None = None, data: dict[str, str] | str | None = None,
                max_redirects: int = 5) -> Fetched:
    cur = url
    redirects: list[str] = []
    for hop in range(max_redirects + 1):
        try:
            target = ctx.scope.check(cur)
        except ScopeViolation as e:
            return Fetched(cur, redirects=redirects, blocked=f"out of scope: {e}")
        await ctx.limiter_http.acquire()
        try:
            async with client.stream(method, cur, headers=headers, data=data) as r:  # type: ignore[arg-type]
                ns = r.extensions.get("network_stream")
                peer = None
                try:
                    peer = ns.get_extra_info("server_addr") if ns else None
                except Exception:
                    peer = None
                if peer and target.addresses and not any(_same_ip(peer[0], a) for a in target.addresses):
                    return Fetched(cur, redirects=redirects,
                                   blocked=f"connected to {peer[0]} which is not in the pinned resolution {list(target.addresses)} (possible DNS rebinding)")
                body = bytearray()
                async for chunk in r.aiter_bytes():
                    body.extend(chunk)
                    if len(body) >= MAX_BYTES:
                        break
                status, hdrs = r.status_code, r.headers
                text = bytes(body).decode(r.encoding or "utf-8", errors="replace")
        except (httpx.HTTPError, OSError) as e:
            return Fetched(cur, redirects=redirects, error=f"{type(e).__name__}: {e}")
        if status in (301, 302, 303, 307, 308) and "location" in hdrs and hop < max_redirects:
            cur = urljoin(cur, hdrs["location"])
            redirects.append(cur)
            method, data = ("GET", None) if status in (301, 302, 303) else (method, data)
            continue
        return Fetched(cur, status, hdrs, text, redirects, set_cookies=hdrs.get_list("set-cookie"))
    return Fetched(cur, redirects=redirects, error="too many redirects")
