"""Scope enforcement.

Every target a tool is asked to touch is parsed, resolved and checked here *before* anything runs.
The LLM never gets a say: a malicious banner or web page cannot talk the harness out of scope.

Rules (exclusions always win):
  * IP / CIDR includes match by address.
  * Hostname includes (exact or ``*.glob``) match by name, but the resolved addresses must still avoid
    excluded ranges and may not be loopback / link-local / multicast unless an include network covers them.
  * A bare hostname with no name include is only in scope if *every* resolved address is inside an include network.
  * URL includes scope a host+port+path prefix; paths are normalised so ``/app/../admin`` can't escape.
  * Userinfo tricks (``http://good@evil/``), backslashes, whitespace and pseudo-IP forms
    (``2130706433``, ``0x7f.1``) are rejected outright.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import posixpath
import re
import socket
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

from ..config import ScopeCfg

MAX_EXPAND = 1024

_BAD_CHARS = re.compile(r"[\x00-\x20\x7f\\]")
_HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?(\.[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)*$")
_PSEUDO_IP = re.compile(r"^(0x[0-9a-f]+|[0-9]+)(\.(0x[0-9a-f]+|[0-9]+))*$", re.I)

Network = ipaddress.IPv4Network | ipaddress.IPv6Network
Address = ipaddress.IPv4Address | ipaddress.IPv6Address


class ScopeViolation(Exception):
    """Raised when a target is out of scope or malformed."""


@dataclass(frozen=True)
class Resolved:
    original: str
    kind: str  # ip | host | url | cidr
    host: str
    addresses: tuple[str, ...]
    port: int | None = None
    scheme: str | None = None
    path: str = "/"
    url: str | None = None

    @property
    def label(self) -> str:
        return self.url or self.host


@dataclass(frozen=True)
class _Parsed:
    kind: str
    host: str
    port: int | None = None
    scheme: str | None = None
    path: str = "/"
    network: Network | None = None


def _default_resolver(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    seen: list[str] = []
    for info in infos:
        addr = info[4][0].split("%")[0]
        if addr not in seen:
            seen.append(addr)
    return seen


def _norm_path(path: str) -> str:
    p = path or "/"
    for _ in range(3):  # defeat double-encoded dot segments
        q = unquote(p)
        if q == p:
            break
        p = q
    norm = posixpath.normpath(p)
    if not norm.startswith("/"):
        norm = "/" + norm
    if norm.startswith("//"):
        norm = "/" + norm.lstrip("/")
    return norm


class ScopeEngine:
    def __init__(self, cfg: ScopeCfg, resolver: Callable[[str], list[str]] | None = None) -> None:
        self._resolver = resolver or _default_resolver
        self._cache: dict[str, tuple[str, ...]] = {}
        self.static_hosts: dict[str, str] = {k.lower(): v for k, v in cfg.hosts.items()}

        self._inc_nets: list[Network] = []
        self._inc_names: list[str] = []
        self._inc_urls: list[_Parsed] = []
        self._exc_nets: list[Network] = []
        self._exc_names: list[str] = []
        self._exc_urls: list[_Parsed] = []
        self._seeds: list[tuple[str, str]] = []
        self._exc_resolved = False

        for raw in cfg.include:
            self._add_entry(raw, include=True)
        for raw in cfg.exclude:
            self._add_entry(raw, include=False)

    # ------------------------------------------------------------------ construction

    def _add_entry(self, raw: str, include: bool) -> None:
        raw = raw.strip()
        if "*" in raw and "://" not in raw and "/" not in raw:
            (self._inc_names if include else self._exc_names).append(raw.lower())
            if include:
                self._seeds.append(("pattern", raw.lower()))
            return
        p = self._parse(raw)
        if p.kind == "cidr":
            assert p.network is not None
            (self._inc_nets if include else self._exc_nets).append(p.network)
            if include:
                self._seeds.append(("cidr", str(p.network)))
        elif p.kind == "ip":
            net = ipaddress.ip_network(p.host)
            (self._inc_nets if include else self._exc_nets).append(net)
            if include:
                self._seeds.append(("ip", p.host))
        elif p.kind == "host":
            (self._inc_names if include else self._exc_names).append(p.host)
            if include:
                self._seeds.append(("host", p.host))
        elif p.kind == "url":
            (self._inc_urls if include else self._exc_urls).append(p)
            if include:
                self._seeds.append(("url", raw))

    def seeds(self) -> list[tuple[str, str]]:
        """Include entries as (kind, value); the autopilot starts from these."""
        return list(self._seeds)

    def describe(self) -> list[str]:
        inc = [f"{k}:{v}" for k, v in self._seeds]
        exc = [str(n) for n in self._exc_nets] + self._exc_names + [f"url:{u.host}{u.path}" for u in self._exc_urls]
        return [f"include: {', '.join(inc) or '-'}", f"exclude: {', '.join(exc) or '-'}"]

    # ------------------------------------------------------------------ parsing

    def _parse(self, raw: str) -> _Parsed:
        s = (raw or "").strip()
        if not s:
            raise ScopeViolation("empty target")
        if len(s) > 2048:
            raise ScopeViolation("target too long")
        if _BAD_CHARS.search(s):
            raise ScopeViolation("target contains whitespace, control characters or backslashes")
        if s.startswith("-"):
            raise ScopeViolation("target may not start with '-'")

        if "://" in s:
            parts = urlsplit(s)
            scheme = parts.scheme.lower()
            if scheme not in ("http", "https"):
                raise ScopeViolation(f"unsupported URL scheme '{scheme}'")
            if "@" in parts.netloc:
                raise ScopeViolation("userinfo in URL is not allowed")
            try:
                port = parts.port
            except ValueError as e:
                raise ScopeViolation("invalid port in URL") from e
            host = (parts.hostname or "").lower()
            if not host:
                raise ScopeViolation("URL has no host")
            return _Parsed("url", host, port or (443 if scheme == "https" else 80), scheme, _norm_path(parts.path))

        if "/" in s:
            try:
                return _Parsed("cidr", str(ipaddress.ip_network(s, strict=False)), network=ipaddress.ip_network(s, strict=False))
            except ValueError as e:
                raise ScopeViolation(f"invalid CIDR '{s}'") from e

        try:
            return _Parsed("ip", str(ipaddress.ip_address(s)))
        except ValueError:
            pass

        host, port = s, None
        if s.count(":") == 1:
            host, _, p = s.partition(":")
            if not p.isdigit() or not (0 < int(p) < 65536):
                raise ScopeViolation("invalid port")
            port = int(p)
        host = host.lower().rstrip(".")
        try:
            return _Parsed("ip", str(ipaddress.ip_address(host)), port)
        except ValueError:
            pass
        if _PSEUDO_IP.match(host):
            raise ScopeViolation("non-canonical numeric host (looks like an obfuscated IP)")
        if not _HOST_RE.match(host):
            raise ScopeViolation(f"invalid hostname '{host}'")
        return _Parsed("host", host, port)

    # ------------------------------------------------------------------ resolution

    def resolve_name(self, host: str) -> tuple[str, ...]:
        """Resolve once and cache, so every later check in the engagement sees the same answer."""
        host = host.lower()
        try:
            return (str(ipaddress.ip_address(host)),)
        except ValueError:
            pass
        if host in self._cache:
            return self._cache[host]
        if host in self.static_hosts:
            addrs = tuple(a.strip() for a in self.static_hosts[host].split(",") if a.strip())
        else:
            try:
                addrs = tuple(self._resolver(host))
            except OSError as e:
                raise ScopeViolation(f"cannot resolve '{host}': {e}") from e
        if not addrs:
            raise ScopeViolation(f"'{host}' did not resolve to any address")
        try:
            addrs = tuple(str(ipaddress.ip_address(a)) for a in addrs)
        except ValueError as e:
            raise ScopeViolation(f"resolver returned an invalid address for '{host}'") from e
        self._cache[host] = addrs
        return addrs

    # ------------------------------------------------------------------ predicates

    @staticmethod
    def _in_nets(ip: Address, nets: Sequence[Network]) -> bool:
        return any(ip.version == n.version and ip in n for n in nets)

    @staticmethod
    def _special(ip: Address) -> bool:
        return ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved

    def _name_match(self, host: str, patterns: Sequence[str]) -> bool:
        return any(fnmatch.fnmatchcase(host, pat) for pat in patterns)

    def _ensure_excluded_resolved(self) -> None:
        if self._exc_resolved:
            return
        self._exc_resolved = True
        for name in self._exc_names:
            if "*" in name:
                continue
            try:
                for a in self.resolve_name(name):
                    self._exc_nets.append(ipaddress.ip_network(a))
            except ScopeViolation:
                continue

    def _url_matches(self, p: _Parsed, entries: Sequence[_Parsed]) -> bool:
        for u in entries:
            if u.host != p.host or u.port != p.port or u.scheme != p.scheme:
                continue
            base = u.path.rstrip("/")
            if base == "" or p.path == base or p.path.startswith(base + "/"):
                return True
        return False

    # ------------------------------------------------------------------ public API

    def check(self, raw: str) -> Resolved:
        """Return a Resolved target or raise ScopeViolation."""
        p = self._parse(raw)
        self._ensure_excluded_resolved()

        if p.kind == "cidr":
            return self._check_cidr(raw, p)

        if p.kind != "ip" and self._name_match(p.host, self._exc_names):
            raise ScopeViolation(f"'{p.host}' is explicitly excluded")

        addrs = self.resolve_name(p.host)
        ips = [ipaddress.ip_address(a) for a in addrs]
        for ip in ips:
            if self._in_nets(ip, self._exc_nets):
                raise ScopeViolation(f"{p.host} resolves to excluded address {ip}")

        host_ok = self._host_included(p, ips)
        url_ok = p.kind == "url" and self._url_matches(p, self._inc_urls)
        if not (host_ok or url_ok):
            raise ScopeViolation(f"'{p.host}' ({', '.join(addrs)}) is not in scope")
        if p.kind == "url" and self._url_matches(p, self._exc_urls):
            raise ScopeViolation(f"URL path is explicitly excluded: {p.host}{p.path}")

        url = None
        if p.kind == "url":
            default = 443 if p.scheme == "https" else 80
            netloc = p.host if p.port == default else f"{p.host}:{p.port}"
            query = urlsplit(raw.strip()).query
            url = f"{p.scheme}://{netloc}{p.path}" + (f"?{query}" if query else "")
        return Resolved(raw.strip(), p.kind, p.host, addrs, p.port, p.scheme, p.path, url)

    def _host_included(self, p: _Parsed, ips: list[Address]) -> bool:
        if p.kind == "ip":
            return self._in_nets(ips[0], self._inc_nets)
        if self._name_match(p.host, self._inc_names):
            for ip in ips:
                if self._special(ip) and not self._in_nets(ip, self._inc_nets):
                    raise ScopeViolation(
                        f"'{p.host}' resolves to special-use address {ip} that is not covered by an include network"
                    )
            return True
        return all(self._in_nets(ip, self._inc_nets) for ip in ips)

    def _check_cidr(self, raw: str, p: _Parsed) -> Resolved:
        net = p.network
        assert net is not None
        if not any(net.version == inc.version and net.subnet_of(inc) for inc in self._inc_nets):  # type: ignore[arg-type]
            raise ScopeViolation(f"network {net} is not fully inside an include range")
        if net.num_addresses > MAX_EXPAND * 4:
            raise ScopeViolation(f"network {net} is too large to enumerate (max about {MAX_EXPAND} hosts)")
        hosts: list[str] = []
        for ip in net.hosts() if net.num_addresses > 2 else net:
            if self._in_nets(ip, self._exc_nets):
                continue
            hosts.append(str(ip))
            if len(hosts) > MAX_EXPAND:
                raise ScopeViolation(f"network {net} expands to more than {MAX_EXPAND} hosts; use a smaller range")
        if not hosts:
            raise ScopeViolation(f"network {net} has no in-scope hosts after exclusions")
        return Resolved(raw.strip(), "cidr", str(net), tuple(hosts))

    def check_many(self, raws: Sequence[str]) -> list[Resolved]:
        return [self.check(r) for r in raws]

    def is_in_scope(self, raw: str) -> bool:
        try:
            self.check(raw)
            return True
        except ScopeViolation:
            return False
