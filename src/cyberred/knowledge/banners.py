"""Turn raw service banners into (name, product, version)."""

from __future__ import annotations

import re

PORT_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http", 110: "pop3", 111: "rpcbind",
    135: "msrpc", 139: "netbios-ssn", 143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "microsoft-ds",
    465: "smtps", 587: "submission", 636: "ldaps", 993: "imaps", 995: "pop3s", 1433: "ms-sql-s", 1521: "oracle",
    2049: "nfs", 2375: "docker", 3000: "http", 3306: "mysql", 3389: "ms-wbt-server", 5000: "http",
    5432: "postgresql", 5601: "http", 5900: "vnc", 5985: "wsman", 5986: "wsmans", 6379: "redis", 8000: "http",
    8008: "http", 8080: "http", 8081: "http", 8443: "https", 8888: "http", 9000: "http", 9200: "elasticsearch",
    11211: "memcached", 27017: "mongodb",
}
TLS_PORTS = {443, 465, 636, 993, 995, 5986, 8443, 9443}
HTTP_NAMES = {"http", "https", "http-alt", "http-proxy", "ssl/http", "https-alt"}

_PRODUCT_ALIASES = {"apache": "Apache httpd", "microsoft-iis": "Microsoft IIS httpd", "nginx": "nginx", "lighttpd": "lighttpd"}


def is_web(name: str | None, port: int) -> bool:
    n = (name or "").lower()
    return n in HTTP_NAMES or "http" in n or port in (80, 443, 3000, 5000, 5601, 8000, 8008, 8080, 8081, 8443, 8888, 9000)


def parse_server_header(value: str) -> tuple[str | None, str | None]:
    m = re.match(r"\s*([A-Za-z][\w.\-]*)(?:/(\S+))?", value or "")
    if not m:
        return None, None
    prod = _PRODUCT_ALIASES.get(m.group(1).lower(), m.group(1))
    return prod, m.group(2)


def parse_banner(port: int, banner: str) -> tuple[str, str | None, str | None]:
    """Best-effort (name, product, version). ``name`` falls back to the well-known port name."""
    name = PORT_NAMES.get(port, "unknown")
    b = (banner or "").strip()
    if not b:
        return name, None, None

    m = re.match(r"SSH-\d\.\d+-(\S+)", b)
    if m:
        token = m.group(1)
        pm = re.match(r"([A-Za-z]+)[_-]?([\d][\w.]*)", token)
        if pm:
            return "ssh", pm.group(1), pm.group(2)
        return "ssh", token, None

    if re.match(r"^220[ -]", b):
        for pat, prod in ((r"vsFTPd ([\d.]+)", "vsftpd"), (r"ProFTPD ([\w.]+)", "ProFTPD"),
                          (r"FileZilla Server(?: version)? ([\w.]+)", "FileZilla ftpd"), (r"Pure-FTPd", "Pure-FTPd")):
            m = re.search(pat, b, re.I)
            if m:
                return "ftp", prod, (m.group(1) if m.groups() else None)
        m = re.search(r"Exim ([\d.]+)", b)
        if m:
            return "smtp", "Exim", m.group(1)
        m = re.search(r"(Postfix|Sendmail|Microsoft ESMTP)", b)
        if m:
            return "smtp", m.group(1), None
        if "ftp" in b.lower():
            return "ftp", None, None
        if "smtp" in b.lower():
            return "smtp", None, None

    if b.upper().startswith("HTTP/"):
        m = re.search(r"^Server:\s*(.+)$", b, re.I | re.M)
        if m:
            prod, ver = parse_server_header(m.group(1))
            return ("https" if port in TLS_PORTS else "http"), prod, ver
        return ("https" if port in TLS_PORTS else "http"), None, None

    if port == 3306 or "mysql" in b.lower():
        m = re.search(r"(\d+\.\d+\.\d+[-\w.]*)", b)
        if m:
            return "mysql", "MySQL", m.group(1)

    if b.startswith("-NOAUTH") or b.startswith("+PONG") or "redis_version" in b:
        return "redis", "Redis", (re.search(r"redis_version:([\d.]+)", b) or [None, None])[1]

    return name, None, None
