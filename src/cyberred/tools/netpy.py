"""Pure-Python network tools: they work with no external binaries installed."""

from __future__ import annotations

import asyncio
import ssl
import time
from datetime import datetime, timezone
from typing import Any

from ..config import Tier
from ..knowledge.banners import TLS_PORTS, parse_banner
from ..knowledge.hints import hints_for
from ..models import Finding, ToolOutput
from ..policy import Resolved
from .base import Param, Registry, Tool, ToolContext
from .util import PORT_SPEC_RE, flatten_addresses, fmt_services, is_ip, parse_ports

HTTPISH = {80, 81, 3000, 5000, 5601, 8000, 8008, 8080, 8081, 8888, 9000, 9090, 9200, 10000}


# --------------------------------------------------------------------------- dns_lookup

async def _dns_lookup(ctx: ToolContext, args: dict[str, Any], res: dict[str, list[Resolved]]) -> ToolOutput:
    lines, hosts = [], []
    for r in res["target"]:
        lines.append(f"{r.host} → {', '.join(r.addresses)}")
        for a in r.addresses:
            hosts.append({"address": a, "hostname": r.host if r.kind == "host" else None})
    return ToolOutput(True, "\n".join(lines), "\n".join(lines), {"hosts": hosts})


# --------------------------------------------------------------------------- tcp_port_scan

async def _probe(ctx: ToolContext, ip: str, port: int, sem: asyncio.Semaphore, connect_timeout: float) -> dict[str, Any] | None:
    async with sem:
        await ctx.limiter_net.acquire()
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), connect_timeout)
        except (OSError, asyncio.TimeoutError):
            return None
        banner = ""
        try:
            if port not in TLS_PORTS:
                try:
                    banner = (await asyncio.wait_for(reader.read(512), 1.2)).decode("latin-1")
                except asyncio.TimeoutError:
                    pass
                if not banner:  # silent service: nmap-style light HTTP probe (harmless on non-HTTP ports)
                    writer.write(b"HEAD / HTTP/1.0\r\nUser-Agent: CyberRed\r\n\r\n")
                    await writer.drain()
                    try:
                        banner = (await asyncio.wait_for(reader.read(1024), 1.5)).decode("latin-1")
                    except asyncio.TimeoutError:
                        pass
        except OSError:
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
        return {"port": port, "banner": banner}


async def _tcp_port_scan(ctx: ToolContext, args: dict[str, Any], res: dict[str, list[Resolved]]) -> ToolOutput:
    try:
        ports = parse_ports(args.get("ports", "top100"))
        hosts = flatten_addresses(res["targets"])
    except ValueError as e:
        return ToolOutput(False, str(e), f"error: {e}")
    timeout = args.get("connect_timeout_ms", 1500) / 1000
    sem = asyncio.Semaphore(200)
    t0 = time.monotonic()

    async def one(ip: str, host: str | None, port: int):
        r = await _probe(ctx, ip, port, sem, timeout)
        return (ip, host, r) if r else None

    results = await asyncio.gather(*(one(ip, h, p) for ip, h in hosts for p in ports))
    services, host_recs = [], []
    seen_hosts: set[str] = set()
    for item in filter(None, results):
        ip, hostname, r = item
        name, product, version = parse_banner(r["port"], r["banner"])
        services.append({"address": ip, "hostname": hostname, "port": r["port"], "proto": "tcp", "name": name,
                         "product": product, "version": version, "banner": r["banner"].strip()[:300] or None})
        if ip not in seen_hosts:
            seen_hosts.add(ip)
            host_recs.append({"address": ip, "hostname": hostname})
    summary = fmt_services(services) if services else f"no open ports among {len(ports)} port(s) on {len(hosts)} host(s)"
    summary += f"\n[{len(hosts)} host(s) × {len(ports)} port(s) in {time.monotonic() - t0:.1f}s]"
    return ToolOutput(True, summary, summary, {"hosts": host_recs, "services": services})


# --------------------------------------------------------------------------- raw TCP helpers

async def _talk(ip: str, port: int, send: list[bytes], limiter, timeout: float = 4.0) -> list[bytes]:
    """Connect, optionally send lines, and collect one response per step (first read = banner)."""
    await limiter.acquire()
    reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
    out: list[bytes] = []
    try:
        try:
            out.append(await asyncio.wait_for(reader.read(1024), timeout))
        except asyncio.TimeoutError:
            out.append(b"")
        for data in send:
            writer.write(data)
            await writer.drain()
            try:
                out.append(await asyncio.wait_for(reader.read(2048), timeout))
            except asyncio.TimeoutError:
                out.append(b"")
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
    return out


# --------------------------------------------------------------------------- ftp_anon_check

async def _ftp_anon(ctx: ToolContext, args: dict[str, Any], res: dict[str, list[Resolved]]) -> ToolOutput:
    r = res["target"][0]
    ip, port = r.addresses[0], args.get("port", 21)
    try:
        banner, user, pwd, _ = await _talk(ip, port, [b"USER anonymous\r\n", b"PASS cyberred@example.com\r\n", b"QUIT\r\n"], ctx.limiter_net)
    except (OSError, asyncio.TimeoutError) as e:
        return ToolOutput(False, str(e), f"connection failed: {e}")
    b, p = banner.decode(errors="replace").strip(), pwd.decode(errors="replace").strip()
    findings, svc = [], []
    name, product, version = parse_banner(port, b)
    svc.append({"address": ip, "hostname": r.host if r.kind == "host" else None, "port": port, "proto": "tcp",
                "name": "ftp", "product": product, "version": version, "banner": b[:200]})
    if p.startswith("230"):
        findings.append(Finding("Anonymous FTP login allowed", "medium", "The FTP server accepts anonymous logins.",
                                f"USER anonymous → {user.decode(errors='replace').strip()}\nPASS → {p}",
                                "Disable anonymous access or restrict it to a read-only, non-sensitive area.",
                                host=ip, port=port, category="anon-access", source="ftp_anon_check", status="confirmed").to_dict())
        summary = f"{ip}:{port} anonymous login ACCEPTED ({b[:80]})"
    else:
        summary = f"{ip}:{port} anonymous login refused ({p[:60] or 'no reply'})"
    return ToolOutput(True, summary, summary, {"services": svc, "findings": findings})


# --------------------------------------------------------------------------- exposed_service_check

async def _exposed(ctx: ToolContext, args: dict[str, Any], res: dict[str, list[Resolved]]) -> ToolOutput:
    r = res["target"][0]
    ip, svc = r.addresses[0], args["service"]
    port = args.get("port") or {"redis": 6379, "memcached": 11211, "elasticsearch": 9200}[svc]
    f: list[dict[str, Any]] = []
    try:
        if svc == "redis":
            ping, info = (await _talk(ip, port, [b"PING\r\n", b"INFO server\r\n"], ctx.limiter_net))[1:3]
            if ping.startswith(b"+PONG"):
                ver = ""
                for line in info.decode(errors="replace").splitlines():
                    if line.startswith("redis_version:"):
                        ver = line.split(":", 1)[1].strip()
                f.append(Finding("Redis accessible without authentication", "high",
                                 "Anyone who can reach this port can read/write data and often achieve code execution.",
                                 f"PING → +PONG; redis_version={ver or '?'}", "Set requirepass/ACLs, bind to localhost, firewall the port.",
                                 host=ip, port=port, category="unauth-service", source="exposed_service_check", status="confirmed", cvss=9.8).to_dict())
                summary = f"redis on {ip}:{port} answers PING without auth (version {ver or '?'})"
            else:
                summary = f"redis on {ip}:{port} requires authentication ({ping[:40]!r})"
        elif svc == "memcached":
            ver = (await _talk(ip, port, [b"version\r\n"], ctx.limiter_net))[1].decode(errors="replace").strip()
            if ver.startswith("VERSION"):
                f.append(Finding("Memcached accessible without authentication", "medium",
                                 "Open memcached leaks cached data and can be abused for amplification.", ver,
                                 "Bind to localhost/private network; enable SASL.", host=ip, port=port, category="unauth-service",
                                 source="exposed_service_check", status="confirmed").to_dict())
                summary = f"memcached on {ip}:{port} open ({ver})"
            else:
                summary = f"{ip}:{port} did not answer like memcached"
        else:  # elasticsearch
            resp = (await _talk(ip, port, [b"GET / HTTP/1.0\r\nHost: x\r\n\r\n"], ctx.limiter_net))[1].decode(errors="replace")
            if '"cluster_name"' in resp:
                f.append(Finding("Elasticsearch API accessible without authentication", "high",
                                 "The cluster API answers unauthenticated requests, exposing indices and data.",
                                 resp.split("\r\n\r\n", 1)[-1][:300], "Enable security (auth/TLS) and firewall port 9200.",
                                 host=ip, port=port, category="unauth-service", source="exposed_service_check", status="confirmed", cvss=9.1).to_dict())
                summary = f"elasticsearch on {ip}:{port} answers unauthenticated"
            else:
                summary = f"{ip}:{port} did not expose an open Elasticsearch API"
    except (OSError, asyncio.TimeoutError) as e:
        return ToolOutput(False, str(e), f"connection failed: {e}")
    return ToolOutput(True, summary, summary, {"findings": f})


# --------------------------------------------------------------------------- tls_inspect

def _ctx(verify: bool, ver: ssl.TLSVersion | None = None) -> ssl.SSLContext:
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.check_hostname = False
    if verify:
        c.load_default_certs()
        c.verify_mode = ssl.CERT_REQUIRED
    else:
        c.verify_mode = ssl.CERT_NONE
    if ver is not None:
        try:
            c.set_ciphers("ALL:@SECLEVEL=0")
            c.minimum_version = ver
            c.maximum_version = ver
        except (ssl.SSLError, ValueError):
            raise
    return c


async def _tls_handshake(ip: str, port: int, hostname: str | None, c: ssl.SSLContext, timeout: float = 6.0):
    reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port, ssl=c, server_hostname=hostname), timeout)
    obj = writer.get_extra_info("ssl_object")
    info = {"version": obj.version(), "cipher": obj.cipher(), "cert": obj.getpeercert()}
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return info


async def _tls_inspect(ctx: ToolContext, args: dict[str, Any], res: dict[str, list[Resolved]]) -> ToolOutput:
    r = res["target"][0]
    ip, port = r.addresses[0], args.get("port", 443)
    hostname = r.host if not is_ip(r.host) else None
    await ctx.limiter_net.acquire()
    findings: list[Finding] = []
    lines: list[str] = []
    verify_error = None
    info = None
    try:
        info = await _tls_handshake(ip, port, hostname, _ctx(True))
    except ssl.SSLCertVerificationError as e:
        verify_error = e.verify_message or str(e)
    except (OSError, asyncio.TimeoutError, ssl.SSLError) as e:
        return ToolOutput(False, str(e), f"TLS handshake failed: {e}")
    if info is None:
        try:
            info = await _tls_handshake(ip, port, hostname, _ctx(False))
        except (OSError, asyncio.TimeoutError, ssl.SSLError) as e:
            return ToolOutput(False, str(e), f"TLS handshake failed: {e}")
    lines.append(f"{ip}:{port} negotiated {info['version']} / {info['cipher'][0] if info['cipher'] else '?'}")
    mk = lambda **kw: Finding(host=ip, port=port, source="tls_inspect", status="confirmed", category="tls", **kw)  # noqa: E731
    if verify_error:
        low = verify_error.lower()
        if "expired" in low:
            findings.append(mk(title="TLS certificate expired", severity="medium", description="The presented certificate is past its notAfter date.",
                               evidence=verify_error, remediation="Renew and deploy a valid certificate."))
        elif "self-signed" in low or "self signed" in low:
            findings.append(mk(title="Self-signed TLS certificate", severity="low", description="The certificate is not issued by a trusted CA.",
                               evidence=verify_error, remediation="Use a certificate from a trusted CA."))
        elif "hostname" in low or "ip address mismatch" in low:
            findings.append(mk(title="TLS certificate hostname mismatch", severity="low", description="The certificate does not match the host name.",
                               evidence=verify_error, remediation="Issue a certificate covering this name."))
        else:
            findings.append(mk(title="Untrusted TLS certificate", severity="low", description="The certificate chain could not be validated.",
                               evidence=verify_error, remediation="Install a certificate that chains to a trusted root."))
        lines.append(f"certificate: {verify_error}")
    else:
        cert = info["cert"] or {}
        na = cert.get("notAfter")
        if na:
            days = (datetime.fromtimestamp(ssl.cert_time_to_seconds(na), timezone.utc) - datetime.now(timezone.utc)).days
            lines.append(f"certificate valid, expires in {days} days")
            if days < 14:
                findings.append(mk(title="TLS certificate expires soon", severity="low", description=f"Certificate expires in {days} days.",
                                   evidence=f"notAfter={na}", remediation="Renew the certificate."))
    for label, ver in (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)):
        try:
            await ctx.limiter_net.acquire()
            await _tls_handshake(ip, port, hostname, _ctx(False, ver), timeout=4.0)
            findings.append(mk(title="Deprecated TLS protocol supported", severity="medium",
                               description=f"The server accepts {label}, which is deprecated (RFC 8996).",
                               evidence=f"{label} handshake succeeded", remediation="Disable TLS 1.0/1.1; require TLS 1.2+."))
            lines.append(f"accepts deprecated {label}")
        except (OSError, asyncio.TimeoutError, ssl.SSLError, ValueError):
            continue
    summary = "\n".join(lines)
    return ToolOutput(True, summary, summary, {"findings": [f.to_dict() for f in findings]})


# --------------------------------------------------------------------------- cve_lookup

async def _cve_lookup(ctx: ToolContext, args: dict[str, Any], res: dict[str, list[Resolved]]) -> ToolOutput:
    hits = hints_for(args["product"], args["version"])
    if not hits:
        s = f"no built-in hints for {args['product']} {args['version']} (try searchsploit_lookup if available)"
        return ToolOutput(True, s, s)
    s = "\n".join(f"[{h.severity}] {h.title} {h.cve} — {h.description}" for h in hits)
    return ToolOutput(True, s, s + "\n(version-based; verify before reporting)")


def register(reg: Registry) -> None:
    reg.register(Tool(
        "dns_lookup", "Resolve a host name to addresses (no packets reach the target). Good first step for names.",
        Tier.T0, ("recon",), {"target": Param("string", "Host name to resolve")}, _dns_lookup, target_args=("target",), timeout=30))
    reg.register(Tool(
        "tcp_port_scan",
        "TCP connect scan with banner grabbing. Works without nmap. ports: 'top20', 'top100', 'full' or a list like '22,80,8000-8100'.",
        Tier.T1, ("recon", "enumeration"),
        {"targets": Param("array", "Hosts/IPs/CIDRs to scan (must be in scope)", max_items=64),
         "ports": Param("string", "Port spec", required=False, default="top100", pattern=PORT_SPEC_RE, allow_dash=True),
         "connect_timeout_ms": Param("integer", "Per-port connect timeout", required=False, default=1500, minimum=200, maximum=10000)},
        _tcp_port_scan, target_args=("targets",), timeout=1800))
    reg.register(Tool(
        "ftp_anon_check", "Check whether an FTP server allows anonymous login (also records the FTP banner/version).",
        Tier.T1, ("enumeration",),
        {"target": Param("string", "Host or IP"), "port": Param("integer", "FTP port", required=False, default=21, minimum=1, maximum=65535)},
        _ftp_anon, target_args=("target",), timeout=60))
    reg.register(Tool(
        "exposed_service_check", "Check redis/memcached/elasticsearch for unauthenticated access using read-only probes.",
        Tier.T1, ("enumeration", "vuln_discovery"),
        {"target": Param("string", "Host or IP"), "service": Param("string", "Service type", enum=("redis", "memcached", "elasticsearch")),
         "port": Param("integer", "Port (defaults to the service's usual port)", required=False, minimum=1, maximum=65535)},
        _exposed, target_args=("target",), timeout=60))
    reg.register(Tool(
        "tls_inspect", "Inspect a TLS endpoint: certificate validity/trust, negotiated protocol, deprecated TLS 1.0/1.1 support.",
        Tier.T1, ("enumeration", "vuln_discovery"),
        {"target": Param("string", "Host or IP"), "port": Param("integer", "TLS port", required=False, default=443, minimum=1, maximum=65535)},
        _tls_inspect, target_args=("target",), timeout=90))
    reg.register(Tool(
        "cve_lookup", "Look up built-in version→known-issue hints for a product and version (offline, no target contact).",
        Tier.T0, ("enumeration", "vuln_discovery"),
        {"product": Param("string", "Product name, e.g. 'vsftpd'", max_len=80), "version": Param("string", "Version, e.g. '2.3.4'", max_len=40)},
        _cve_lookup, timeout=10))
