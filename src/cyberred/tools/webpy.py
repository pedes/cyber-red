"""Pure-Python web tools: fingerprinting, hygiene checks, exposed-file discovery, crawling, light DAST."""

from __future__ import annotations

import asyncio
import re
import secrets
from collections.abc import Callable
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from ..config import Tier
from ..knowledge.banners import parse_server_header
from ..models import Finding, ToolOutput
from ..policy import Resolved, ScopeViolation
from .base import Param, Registry, Tool, ToolContext
from .httputil import Fetched, fetch, make_client

# --------------------------------------------------------------------------- fingerprinting

_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_GENERATOR = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I)

_BODY_TECH = [
    (r"wp-content|wp-includes", "wordpress"), (r"/sites/default/files|Drupal\.settings", "drupal"),
    (r"/media/jui/|Joomla!", "joomla"), (r"jenkins", "jenkins"), (r"Grafana", "grafana"),
    (r"phpmyadmin", "phpmyadmin"), (r"Apache Tomcat", "tomcat"), (r"Welcome to nginx", "nginx"),
    (r"Index of /", "directory-listing"), (r"X-Jenkins", "jenkins"), (r"gitlab", "gitlab"),
    (r"__NEXT_DATA__", "nextjs"), (r"ng-version", "angular"), (r"data-reactroot|react-root", "react"),
]
_COOKIE_TECH = {"PHPSESSID": "php", "JSESSIONID": "java", "ASP.NET_SessionId": "aspnet", "laravel_session": "laravel",
                "connect.sid": "express", "csrftoken": "django", "_rails": "rails", "wordpress_": "wordpress"}


def detect_tech(headers: Any, body: str, cookies: list[str]) -> list[str]:
    tech: set[str] = set()
    server = headers.get("server", "")
    prod, _ = parse_server_header(server) if server else (None, None)
    if prod:
        tech.add(prod.lower().split()[0])
    xp = headers.get("x-powered-by", "")
    if xp:
        tech.add(xp.split("/")[0].lower())
    if headers.get("x-generator"):
        tech.add(headers["x-generator"].split()[0].lower())
    for pat, name in _BODY_TECH:
        if re.search(pat, body[:60000], re.I):
            tech.add(name)
    g = _GENERATOR.search(body[:20000])
    if g:
        tech.add(g.group(1).split()[0].lower())
    for c in cookies:
        for k, v in _COOKIE_TECH.items():
            if c.startswith(k) or c.lower().startswith(k.lower()):
                tech.add(v)
    return sorted(tech)


_SEC_HEADERS = [
    ("content-security-policy", "Content-Security-Policy"), ("x-content-type-options", "X-Content-Type-Options"),
    ("referrer-policy", "Referrer-Policy"), ("permissions-policy", "Permissions-Policy"),
]


def _missing_headers(headers: Any, https: bool) -> list[str]:
    missing = [label for key, label in _SEC_HEADERS if key not in headers]
    csp = headers.get("content-security-policy", "")
    if "x-frame-options" not in headers and "frame-ancestors" not in csp.lower():
        missing.append("X-Frame-Options (or CSP frame-ancestors)")
    if https and "strict-transport-security" not in headers:
        missing.append("Strict-Transport-Security")
    return missing


def _cookie_issues(cookies: list[str], https: bool) -> list[str]:
    issues = []
    for c in cookies:
        name = c.split("=", 1)[0].strip()
        low = c.lower()
        flags = [x for x, ok in (("HttpOnly", "httponly" in low), ("Secure", "secure" in low or not https), ("SameSite", "samesite" in low)) if not ok]
        if flags:
            issues.append(f"{name}: missing {', '.join(flags)}")
    return issues


# --------------------------------------------------------------------------- http_probe

async def _http_probe(ctx: ToolContext, args: dict[str, Any], res: dict[str, list[Resolved]]) -> ToolOutput:
    r = res["url"][0]
    assert r.url
    findings: list[Finding] = []
    lines: list[str] = []
    async with make_client() as client:
        f = await fetch(ctx, client, r.url)
        if not f.ok:
            why = f.blocked or f.error or "no response"
            return ToolOutput(False, why, f"{r.url}: {why}")
        final = ctx.scope.check(f.url)
        https = final.scheme == "https"
        title = (_TITLE.search(f.text) or [None, ""])[1].strip()[:120] if _TITLE.search(f.text) else ""
        tech = detect_tech(f.headers, f.text, f.set_cookies)
        server = f.headers.get("server", "")
        prod, ver = parse_server_header(server) if server else (None, None)
        lines.append(f"{f.status} {f.url}" + (f" → via {len(f.redirects)} redirect(s)" if f.redirects else ""))
        if title:
            lines.append(f"title: {title}")
        if tech:
            lines.append("tech: " + ", ".join(tech))
        mk = lambda **kw: Finding(host=final.addresses[0], port=final.port, url=f.url, source="http_probe", status="confirmed", **kw)  # noqa: E731

        missing = _missing_headers(f.headers, https)
        if missing and f.status and f.status < 400:
            findings.append(mk(title="Missing HTTP security headers", severity="low" if len(missing) >= 3 else "info", category="hardening",
                               description="The response lacks recommended browser security headers.",
                               evidence="missing: " + ", ".join(missing), remediation="Add the missing headers at the web server or application layer."))
        if server and ver:
            findings.append(mk(title="Web server version disclosed", severity="info", category="info-disclosure",
                               description="The Server header reveals the product and version, which helps attackers choose exploits.",
                               evidence=f"Server: {server}", remediation="Suppress version details (e.g. ServerTokens Prod / server_tokens off)."))
        xp = f.headers.get("x-powered-by")
        if xp:
            findings.append(mk(title="Technology disclosed via X-Powered-By", severity="info", category="info-disclosure",
                               evidence=f"X-Powered-By: {xp}", description="Backend technology and version are advertised.",
                               remediation="Remove the X-Powered-By header."))
        ci = _cookie_issues(f.set_cookies, https)
        if ci:
            findings.append(mk(title="Cookies missing security attributes", severity="low", category="hardening",
                               description="Session cookies without HttpOnly/Secure/SameSite are easier to steal or abuse.",
                               evidence="; ".join(ci[:6]), remediation="Set HttpOnly, Secure and SameSite on session cookies."))
        if re.search(r"<input[^>]+type=[\"']?password", f.text, re.I) and not https:
            findings.append(mk(title="Login form served over cleartext HTTP", severity="medium", category="cleartext",
                               description="Credentials entered on this page are sent unencrypted.",
                               evidence="password input found on an http:// page", remediation="Serve authentication pages only over HTTPS and redirect HTTP to HTTPS."))
        if re.search(r"<title>\s*Index of /", f.text, re.I):
            findings.append(mk(title="Directory listing enabled", severity="medium", category="info-disclosure",
                               description="The server lists directory contents.", evidence=f"{f.url} shows an 'Index of /' page",
                               remediation="Disable auto-indexing (Options -Indexes / autoindex off)."))
        if re.search(r"Apache2 (Ubuntu|Debian) Default Page|Welcome to nginx!|IIS Windows Server|It works!", f.text):
            findings.append(mk(title="Default web server page", severity="info", category="misconfig",
                               description="A default install page is served, which suggests an unconfigured or forgotten service.",
                               evidence=title or "default page", remediation="Remove default content or the unused service."))

        # CORS: does the server reflect an arbitrary Origin?
        evil = "https://cyberred-origin-test.invalid"
        cf = await fetch(ctx, client, f.url, headers={"Origin": evil}, max_redirects=0)
        if cf.ok:
            acao, acac = cf.headers.get("access-control-allow-origin", ""), cf.headers.get("access-control-allow-credentials", "").lower()
            if acao == evil and acac == "true":
                findings.append(mk(title="CORS reflects arbitrary origin with credentials", severity="medium", category="misconfig",
                                   description="Any website can make credentialed cross-origin requests and read the responses.",
                                   evidence=f"Origin: {evil} → ACAO: {acao}, ACAC: true", remediation="Allow-list trusted origins; never combine reflected origins with credentials."))
            elif acao == evil:
                findings.append(mk(title="CORS reflects arbitrary origin", severity="low", category="misconfig",
                                   description="The server echoes any Origin in Access-Control-Allow-Origin.", evidence=f"ACAO: {acao}",
                                   remediation="Use an explicit allow-list of origins."))
        # Advertised methods
        of = await fetch(ctx, client, f.url, method="OPTIONS", max_redirects=0)
        if of.ok:
            allow = (of.headers.get("allow", "") + "," + of.headers.get("access-control-allow-methods", "")).upper()
            risky = sorted({m for m in ("PUT", "DELETE", "TRACE", "CONNECT", "PATCH") if m in allow} - {"PATCH"})
            if risky:
                findings.append(mk(title="Potentially dangerous HTTP methods advertised", severity="low", category="misconfig",
                                   description="Methods that modify server state or aid attacks are advertised.",
                                   evidence=f"Allow: {allow.strip(',')}", remediation="Disable unneeded methods."))
                lines.append("methods: " + ", ".join(risky))
    services = [{"address": final.addresses[0], "port": final.port, "proto": "tcp", "name": "https" if https else "http",
                 "product": prod, "version": ver, "banner": f"Server: {server}"[:200] if server else None,
                 "hostname": final.host if final.kind == "url" and not re.fullmatch(r"[\d.:a-f]+", final.host) else None}]
    endpoints = [{"url": f.url, "status": f.status, "title": title, "tech": tech, "params": [k for k, _ in parse_qsl(urlsplit(f.url).query)], "source": "http_probe"}]
    n = len(findings)
    lines.append(f"{n} finding(s): " + "; ".join(f"[{x.severity}] {x.title}" for x in findings) if n else "no hygiene issues found")
    summary = "\n".join(lines)
    return ToolOutput(True, summary, summary, {"services": services, "endpoints": endpoints, "findings": [x.to_dict() for x in findings]})


# --------------------------------------------------------------------------- web_common_files

def _mask_env(body: str) -> str:
    return "\n".join(re.sub(r"=.*", "=***", ln) for ln in body.splitlines()[:12] if "=" in ln)


def _mask_htpasswd(body: str) -> str:
    return "\n".join(ln.split(":", 1)[0] + ":***" for ln in body.splitlines()[:8])


Validator = Callable[[int, str, Any], "str | None"]


def _v(pred: Callable[[int, str, Any], bool], ev: Callable[[str], str] = lambda b: b.strip()[:160]) -> Validator:
    return lambda s, b, h: ev(b) if pred(s, b, h) else None


_CHECKS: list[tuple[str, Validator, dict[str, Any] | None]] = [
    ("/.git/HEAD", _v(lambda s, b, h: s == 200 and b.startswith("ref:")),
     dict(title="Exposed .git repository", severity="high", category="exposed-secret",
          description="The Git metadata is downloadable, so source code and committed secrets can be reconstructed.",
          remediation="Block access to dotfiles at the web server and remove .git from the web root.")),
    ("/.git/config", _v(lambda s, b, h: s == 200 and "[core]" in b), None),
    ("/.env", _v(lambda s, b, h: s == 200 and "<html" not in b[:300].lower() and bool(re.search(r"^[A-Z][A-Z0-9_]{2,}=", b, re.M)), _mask_env),
     dict(title="Exposed .env file", severity="high", category="exposed-secret",
          description="An environment file (often holding credentials and API keys) is publicly readable. Values are masked in this report.",
          remediation="Remove it from the web root, block dotfiles, and rotate every secret it contained.")),
    ("/.htpasswd", _v(lambda s, b, h: s == 200 and bool(re.match(r"^[\w.\-]+:\S+", b)), _mask_htpasswd),
     dict(title="Exposed .htpasswd file", severity="high", category="exposed-secret",
          description="Password hashes are downloadable and can be cracked offline.", remediation="Move it outside the web root and rotate the credentials.")),
    ("/.svn/wc.db", _v(lambda s, b, h: s == 200 and b.startswith("SQLite format 3"), lambda b: "SQLite database"),
     dict(title="Exposed Subversion metadata", severity="high", category="exposed-secret",
          description="The SVN working-copy database is downloadable.", remediation="Remove .svn from the web root.")),
    ("/.DS_Store", _v(lambda s, b, h: s == 200 and "Bud1" in b[:16], lambda b: "macOS .DS_Store"),
     dict(title="Exposed .DS_Store file", severity="info", category="info-disclosure",
          description="Directory metadata leaks file names.", remediation="Delete .DS_Store files from deployments.")),
    ("/server-status", _v(lambda s, b, h: s == 200 and "Apache Server Status" in b),
     dict(title="Apache server-status exposed", severity="medium", category="info-disclosure",
          description="Live request and client information is visible.", remediation="Restrict /server-status to localhost.")),
    ("/phpinfo.php", _v(lambda s, b, h: s == 200 and ("phpinfo()" in b or "PHP Version" in b), lambda b: "phpinfo() output"),
     dict(title="phpinfo() page exposed", severity="medium", category="info-disclosure",
          description="Detailed PHP and server configuration is exposed.", remediation="Remove the phpinfo file.")),
    ("/info.php", _v(lambda s, b, h: s == 200 and ("phpinfo()" in b or "PHP Version" in b), lambda b: "phpinfo() output"),
     dict(title="phpinfo() page exposed", severity="medium", category="info-disclosure",
          description="Detailed PHP and server configuration is exposed.", remediation="Remove the phpinfo file.")),
    ("/backup.sql", _v(lambda s, b, h: s == 200 and bool(re.search(r"CREATE TABLE|INSERT INTO", b[:5000])), lambda b: "SQL dump"),
     dict(title="Database backup exposed", severity="high", category="exposed-secret",
          description="A SQL dump is downloadable.", remediation="Remove backups from the web root.")),
    ("/backup.zip", _v(lambda s, b, h: s == 200 and b.startswith("PK"), lambda b: "ZIP archive"),
     dict(title="Backup archive exposed", severity="high", category="exposed-secret",
          description="An archive is downloadable and may contain source or data.", remediation="Remove backups from the web root.")),
    ("/config.php.bak", _v(lambda s, b, h: s == 200 and "<?php" in b, lambda b: "PHP source (config backup)"),
     dict(title="Configuration backup exposed", severity="high", category="exposed-secret",
          description="Server-side source is served as plain text.", remediation="Remove backup copies from the web root.")),
    ("/web.config", _v(lambda s, b, h: s == 200 and "<configuration" in b, lambda b: "web.config"),
     dict(title="web.config exposed", severity="medium", category="exposed-secret",
          description="IIS configuration is downloadable.", remediation="Block access to web.config.")),
    ("/WEB-INF/web.xml", _v(lambda s, b, h: s == 200 and "<web-app" in b, lambda b: "web.xml"),
     dict(title="WEB-INF/web.xml exposed", severity="high", category="exposed-secret",
          description="Java app deployment descriptor is readable.", remediation="Fix the servlet container/reverse-proxy path handling.")),
    ("/actuator/env", _v(lambda s, b, h: s == 200 and "propertySources" in b, lambda b: "Spring Boot env actuator"),
     dict(title="Spring Boot actuator /env exposed", severity="high", category="exposed-secret",
          description="Environment properties (often secrets) are readable.", remediation="Disable or secure actuator endpoints.")),
    ("/actuator", _v(lambda s, b, h: s == 200 and "_links" in b, lambda b: "Spring Boot actuator index"),
     dict(title="Spring Boot actuator exposed", severity="low", category="info-disclosure",
          description="Management endpoints are reachable.", remediation="Restrict actuator endpoints.")),
    ("/swagger.json", _v(lambda s, b, h: s == 200 and ('"swagger"' in b or '"openapi"' in b), lambda b: "API specification"),
     dict(title="API specification exposed", severity="info", category="info-disclosure",
          description="The OpenAPI/Swagger document maps the API surface.", remediation="Restrict documentation in production if the API is not public.")),
    ("/openapi.json", _v(lambda s, b, h: s == 200 and '"openapi"' in b, lambda b: "API specification"),
     dict(title="API specification exposed", severity="info", category="info-disclosure",
          description="The OpenAPI/Swagger document maps the API surface.", remediation="Restrict documentation in production if the API is not public.")),
    ("/graphql", _v(lambda s, b, h: s in (200, 400) and "graphql" in b.lower(), lambda b: "GraphQL endpoint"),
     dict(title="GraphQL endpoint found", severity="info", category="info-disclosure",
          description="A GraphQL endpoint is reachable; test introspection and authorization.", remediation="Disable introspection in production; enforce authorization per field.")),
    ("/phpmyadmin/", _v(lambda s, b, h: s == 200 and "phpMyAdmin" in b, lambda b: "phpMyAdmin login"),
     dict(title="phpMyAdmin exposed", severity="medium", category="exposure",
          description="A database administration UI is internet-reachable.", remediation="Restrict by IP / VPN and require strong auth.")),
    ("/manager/html", _v(lambda s, b, h: s in (401, 403) and "tomcat" in (h.get("www-authenticate", "") + b).lower(), lambda b: "Tomcat manager"),
     dict(title="Tomcat Manager exposed", severity="medium", category="exposure",
          description="The Tomcat management application is reachable; default credentials are a classic compromise path.", remediation="Restrict the manager app by IP and remove default credentials.")),
    ("/console", _v(lambda s, b, h: s == 200 and ("Werkzeug" in b or "Interactive Console" in b), lambda b: "Werkzeug console"),
     dict(title="Werkzeug debugger console exposed", severity="high", category="exposure",
          description="The Flask/Werkzeug debug console allows code execution if the PIN is obtained.", remediation="Never run debug mode in production.")),
    ("/crossdomain.xml", _v(lambda s, b, h: s == 200 and "<cross-domain-policy" in b and 'domain="*"' in b, lambda b: 'allow-access-from domain="*"'),
     dict(title="Permissive crossdomain.xml", severity="low", category="misconfig",
          description="Any domain may load this site's content from Flash/legacy clients.", remediation="Restrict the allowed domains.")),
    ("/robots.txt", _v(lambda s, b, h: s == 200 and bool(re.search(r"(?im)^(user-agent|disallow|allow|sitemap)", b)), lambda b: b.strip()[:300]), None),
    ("/sitemap.xml", _v(lambda s, b, h: s == 200 and "<urlset" in b, lambda b: "sitemap"), None),
    ("/admin", _v(lambda s, b, h: s in (200, 401, 403), lambda b: "interesting endpoint"), None),
    ("/login", _v(lambda s, b, h: s in (200, 401), lambda b: "interesting endpoint"), None),
    ("/wp-login.php", _v(lambda s, b, h: s == 200 and "wp-submit" in b, lambda b: "WordPress login"), None),
    ("/administrator/", _v(lambda s, b, h: s in (200, 401, 403), lambda b: "interesting endpoint"), None),
]


async def _common_files(ctx: ToolContext, args: dict[str, Any], res: dict[str, list[Resolved]]) -> ToolOutput:
    r = res["url"][0]
    base = f"{r.scheme}://{r.host}" + ("" if r.port in (80, 443) and r.port == (443 if r.scheme == "https" else 80) else f":{r.port}")
    sem = asyncio.Semaphore(4)
    findings: list[Finding] = []
    endpoints: list[dict[str, Any]] = []
    found: list[str] = []
    async with make_client() as client:
        base_probe = await fetch(ctx, client, f"{base}/cyberred-{secrets.token_hex(5)}.html", max_redirects=0)
        if not base_probe.ok:
            why = base_probe.blocked or base_probe.error
            return ToolOutput(False, str(why), f"{base}: {why}")
        soft404 = base_probe.status == 200  # the server answers 200 for everything
        base_len = len(base_probe.text)

        async def check(path: str, validator: Validator, spec: dict[str, Any] | None):
            async with sem:
                f = await fetch(ctx, client, base + path, max_redirects=0)
            if not f.ok or f.status is None:
                return
            if soft404 and abs(len(f.text) - base_len) < 40 and f.status == 200:
                return
            ev = validator(f.status, f.text, f.headers)
            if not ev:
                return
            found.append(f"{f.status} {path}")
            endpoints.append({"url": base + path, "status": f.status, "tech": [], "params": [], "source": "web_common_files"})
            if spec:
                findings.append(Finding(url=base + path, host=r.addresses[0], port=r.port, evidence=f"HTTP {f.status}: {ev}",
                                        source="web_common_files", status="confirmed", **spec))
            if path == "/robots.txt":
                for m in re.finditer(r"(?im)^\s*disallow:\s*(/\S*)", f.text):
                    p = m.group(1).split("*")[0].rstrip("$")
                    if p and p != "/" and len(endpoints) < 60:
                        endpoints.append({"url": base + p, "status": None, "tech": [], "params": [], "source": "robots.txt"})
        await asyncio.gather(*(check(p, v, s) for p, v, s in _CHECKS))
    lines = [f"checked {len(_CHECKS)} common paths on {base}" + (" (soft-404 server detected)" if soft404 else "")]
    lines += [f"  found {x}" for x in sorted(found)] or ["  nothing notable"]
    if findings:
        lines.append("findings: " + "; ".join(f"[{x.severity}] {x.title}" for x in findings))
    summary = "\n".join(lines)
    return ToolOutput(True, summary, summary, {"findings": [x.to_dict() for x in findings], "endpoints": endpoints})


# --------------------------------------------------------------------------- web_crawl

class _Page(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: set[str] = set()
        self.forms: list[dict[str, Any]] = []
        self.comments: list[str] = []
        self._form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k: (v or "") for k, v in attrs}
        if tag in ("a", "link", "area") and a.get("href"):
            self.links.add(a["href"])
        elif tag in ("script", "img", "iframe", "source") and a.get("src"):
            self.links.add(a["src"])
        elif tag == "form":
            self._form = {"action": a.get("action", ""), "method": (a.get("method") or "get").upper(), "inputs": []}
            self.forms.append(self._form)
        elif tag in ("input", "textarea", "select") and self._form is not None and a.get("name"):
            if a.get("type", "text").lower() not in ("submit", "button", "image", "reset"):
                self._form["inputs"].append(a["name"])

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._form = None

    def handle_comment(self, data: str) -> None:
        if re.search(r"(?i)password|passwd|secret|api[_-]?key|token|todo|fixme|debug|admin", data):
            self.comments.append(data.strip()[:160])


async def _web_crawl(ctx: ToolContext, args: dict[str, Any], res: dict[str, list[Resolved]]) -> ToolOutput:
    start = res["url"][0]
    assert start.url
    max_pages, max_depth = args.get("max_pages", 25), args.get("max_depth", 2)
    origin = (start.scheme, start.host, start.port)
    seen: set[str] = set()
    queue: list[tuple[str, int]] = [(start.url, 0)]
    endpoints: dict[str, dict[str, Any]] = {}
    findings: list[Finding] = []
    n_forms = 0
    async with make_client() as client:
        while queue and len(seen) < max_pages:
            url, depth = queue.pop(0)
            key = urlunsplit(urlsplit(url)._replace(fragment=""))
            if key in seen:
                continue
            seen.add(key)
            f = await fetch(ctx, client, key, max_redirects=3)
            if not f.ok:
                continue
            sp = urlsplit(f.url)
            params = [k for k, _ in parse_qsl(sp.query)]
            endpoints[f.url] = {"url": f.url, "status": f.status, "tech": [], "params": params, "source": "web_crawl", "method": "GET"}
            if "html" not in f.headers.get("content-type", "html").lower():
                continue
            page = _Page()
            try:
                page.feed(f.text[:200_000])
            except Exception:
                continue
            for c in page.comments[:3]:
                findings.append(Finding("Sensitive-looking HTML comment", "info", "A comment mentions credentials, debug or admin details.",
                                        c, "Strip comments from production HTML.", url=f.url, host=start.addresses[0], port=start.port,
                                        category="info-disclosure", source="web_crawl", status="confirmed"))
            for form in page.forms:
                n_forms += 1
                action = urljoin(f.url, form["action"] or f.url)
                try:
                    ctx.scope.check(action)
                except ScopeViolation:
                    continue
                if form["inputs"]:
                    endpoints[f"{form['method']} {action}"] = {"url": action, "status": None, "tech": [], "params": form["inputs"],
                                                               "source": "web_crawl:form", "method": form["method"]}
            if depth < max_depth:
                for href in page.links:
                    nxt = urljoin(f.url, href)
                    p = urlsplit(nxt)
                    if p.scheme not in ("http", "https"):
                        continue
                    if (p.scheme, (p.hostname or "").lower(), p.port or (443 if p.scheme == "https" else 80)) != origin:
                        continue
                    if re.search(r"\.(png|jpe?g|gif|svg|ico|css|woff2?|ttf|eot|mp4|mp3|pdf|zip)(\?|$)", p.path, re.I):
                        continue
                    queue.append((nxt, depth + 1))
    with_params = [e for e in endpoints.values() if e["params"]]
    lines = [f"crawled {len(seen)} page(s), found {len(endpoints)} endpoint(s), {n_forms} form(s), {len(with_params)} with parameters"]
    for e in with_params[:12]:
        lines.append(f"  {e.get('method', 'GET')} {e['url']}  params: {','.join(e['params'])}")
    summary = "\n".join(lines)
    return ToolOutput(True, summary, summary, {"endpoints": list(endpoints.values()), "findings": [x.to_dict() for x in findings]})


# --------------------------------------------------------------------------- web_param_probe (T2)

_SQL_ERRORS = re.compile(
    r"You have an error in your SQL syntax|mysqli?_|MySQLSyntaxErrorException|Warning: mysql|"
    r"PostgreSQL.*ERROR|pg_query\(\)|unterminated quoted string|SQLite3?::|sqlite_error|SQLITE_ERROR|"
    r"Unclosed quotation mark|Microsoft OLE DB Provider for SQL Server|ODBC SQL Server Driver|ORA-\d{5}|"
    r"quoted string not properly terminated|SQLSTATE\[", re.I)


async def _param_probe(ctx: ToolContext, args: dict[str, Any], res: dict[str, list[Resolved]]) -> ToolOutput:
    r = res["url"][0]
    assert r.url
    method = args.get("method", "GET")
    sp = urlsplit(r.url)
    params = dict(parse_qsl(sp.query, keep_blank_values=True))
    if method == "POST" and args.get("data"):
        params.update(dict(parse_qsl(args["data"], keep_blank_values=True)))
    if not params:
        return ToolOutput(False, "no parameters", "no parameters to test: give a URL with a query string, or POST data")
    base_url = urlunsplit(sp._replace(query=""))
    findings: list[Finding] = []
    lines: list[str] = []

    async def send(client, values: dict[str, str]) -> Fetched:
        if method == "POST":
            return await fetch(ctx, client, base_url, method="POST", data=values, max_redirects=0)
        return await fetch(ctx, client, f"{base_url}?{urlencode(values)}", max_redirects=0)

    async with make_client() as client:
        baseline = await send(client, {k: v or "1" for k, v in params.items()})
        if not baseline.ok:
            why = baseline.blocked or baseline.error
            return ToolOutput(False, str(why), f"baseline request failed: {why}")
        base_has_sql_error = bool(_SQL_ERRORS.search(baseline.text))
        for name in list(params)[:10]:
            orig = params[name] or "1"
            marker = "cyrd" + secrets.token_hex(3)
            payload = f'{marker}"\'<>'
            vals = {k: (v or "1") for k, v in params.items()}
            vals[name] = payload
            f = await send(client, vals)
            if f.ok and payload in f.text:
                ct = f.headers.get("content-type", "")
                findings.append(Finding(
                    "Reflected input is not encoded (potential XSS)", "medium", f"Parameter '{name}' is reflected with quotes and angle brackets intact.",
                    f"payload {payload!r} appeared verbatim in the response ({ct or 'no content-type'})",
                    "Contextually encode output and add a restrictive Content-Security-Policy.",
                    url=r.url, host=r.addresses[0], port=r.port, category="injection", source="web_param_probe", status="candidate"))
                lines.append(f"  {name}: reflected unencoded")
            vals[name] = orig + "'"
            f2 = await send(client, vals)
            if f2.ok and not base_has_sql_error and _SQL_ERRORS.search(f2.text):
                m = _SQL_ERRORS.search(f2.text)
                findings.append(Finding(
                    "Possible SQL injection (database error on quote)", "high", f"A single quote in '{name}' triggers a database error message.",
                    f"error signature: {m.group(0)[:80] if m else ''}",
                    "Use parameterised queries; confirm with sqlmap_test or manual testing.",
                    url=r.url, host=r.addresses[0], port=r.port, category="injection", cvss=9.8, source="web_param_probe", status="candidate"))
                lines.append(f"  {name}: SQL error on quote")
    head = f"tested {min(len(params), 10)} parameter(s) on {base_url} via {method}"
    summary = "\n".join([head] + (lines or ["  no reflection or SQL error signals"]))
    return ToolOutput(True, summary, summary, {"findings": [x.to_dict() for x in findings]})


def register(reg: Registry) -> None:
    url = Param("string", "Full URL (http/https) inside scope", max_len=1024)
    reg.register(Tool(
        "http_probe",
        "Fetch a URL and fingerprint it: status, title, technologies, security headers, cookies, CORS, methods. "
        "Also records the web service. Start here for any HTTP(S) service.",
        Tier.T1, ("enumeration", "vuln_discovery"), {"url": url}, _http_probe, target_args=("url",), timeout=120))
    reg.register(Tool(
        "web_common_files",
        "Check ~30 high-signal paths (.git, .env, backups, phpinfo, actuator, admin panels, robots.txt...) with content "
        "validation and soft-404 detection.",
        Tier.T1, ("enumeration", "vuln_discovery"), {"url": Param("string", "Base URL of the site", max_len=1024)},
        _common_files, target_args=("url",), timeout=300))
    reg.register(Tool(
        "web_crawl", "Crawl same-origin links and forms (depth ≤ 3, ≤ 60 pages) to discover endpoints and parameters.",
        Tier.T1, ("enumeration",),
        {"url": url, "max_pages": Param("integer", "Page cap", required=False, default=25, minimum=1, maximum=60),
         "max_depth": Param("integer", "Link depth", required=False, default=2, minimum=0, maximum=3)},
        _web_crawl, target_args=("url",), timeout=600))
    reg.register(Tool(
        "web_param_probe",
        "Light input testing: sends a harmless marker and a single quote to each parameter to spot unencoded reflection and "
        "database error messages. Intrusive (T2): requires approval.",
        Tier.T2, ("vuln_discovery", "validation"),
        {"url": Param("string", "URL including query parameters", max_len=1024),
         "method": Param("string", "HTTP method", required=False, default="GET", enum=("GET", "POST")),
         "data": Param("string", "Form-encoded POST body, e.g. 'user=a&q=b'", required=False, max_len=1024)},
        _param_probe, target_args=("url",), timeout=300))
